#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Options {
    std::size_t min_string = 4;
    std::size_t max_strings = 500;
    std::size_t entropy_window = 4096;
    double entropy_threshold = 7.2;
    std::size_t max_entropy_regions = 20;
    std::string path;
    bool show_help = false;
};

struct ExtractedString {
    std::size_t offset = 0;
    std::string kind;
    std::string value;
};

struct EntropyRegion {
    std::size_t offset = 0;
    std::size_t size = 0;
    double entropy = 0.0;
};

bool parse_size(const char* text, std::size_t& value) {
    try {
        std::size_t parsed_count = 0;
        unsigned long long parsed = std::stoull(text, &parsed_count, 0);
        if (text[parsed_count] != '\0') {
            return false;
        }
        value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_double(const char* text, double& value) {
    try {
        std::size_t parsed_count = 0;
        double parsed = std::stod(text, &parsed_count);
        if (text[parsed_count] != '\0') {
            return false;
        }
        value = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_args(int argc, char** argv, Options& options, std::string& error) {
    for (int index = 1; index < argc; ++index) {
        std::string arg = argv[index];
        if (arg == "-h" || arg == "--help") {
            options.show_help = true;
            return true;
        }
        auto require_value = [&](const char* name) -> char* {
            if (index + 1 >= argc) {
                error = std::string("Missing value for ") + name;
                return nullptr;
            }
            return argv[++index];
        };

        if (arg == "--min-string") {
            char* value = require_value("--min-string");
            if (value == nullptr || !parse_size(value, options.min_string) || options.min_string == 0) {
                error = "Invalid --min-string";
                return false;
            }
        } else if (arg == "--max-strings") {
            char* value = require_value("--max-strings");
            if (value == nullptr || !parse_size(value, options.max_strings)) {
                error = "Invalid --max-strings";
                return false;
            }
        } else if (arg == "--entropy-window") {
            char* value = require_value("--entropy-window");
            if (value == nullptr || !parse_size(value, options.entropy_window) || options.entropy_window < 256) {
                error = "Invalid --entropy-window";
                return false;
            }
        } else if (arg == "--entropy-threshold") {
            char* value = require_value("--entropy-threshold");
            if (value == nullptr || !parse_double(value, options.entropy_threshold)) {
                error = "Invalid --entropy-threshold";
                return false;
            }
        } else if (arg == "--max-entropy-regions") {
            char* value = require_value("--max-entropy-regions");
            if (value == nullptr || !parse_size(value, options.max_entropy_regions)) {
                error = "Invalid --max-entropy-regions";
                return false;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            error = "Unknown option: " + arg;
            return false;
        } else {
            options.path = arg;
        }
    }

    if (options.path.empty()) {
        error = "Target path is required.";
        return false;
    }
    return true;
}

void write_help() {
    std::cout << "Usage: perf_scan [options] <target>\n";
    std::cout << "Options:\n";
    std::cout << "  --min-string <n>\n";
    std::cout << "  --max-strings <n>\n";
    std::cout << "  --entropy-window <n>\n";
    std::cout << "  --entropy-threshold <f>\n";
    std::cout << "  --max-entropy-regions <n>\n";
}

std::string json_escape(const std::string& value) {
    std::ostringstream output;
    for (unsigned char ch : value) {
        switch (ch) {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (ch < 0x20) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                           << std::dec << std::setfill(' ');
                } else {
                    output << static_cast<char>(ch);
                }
        }
    }
    return output.str();
}

std::vector<std::uint8_t> read_file(const std::string& path, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Could not open target file.";
        return {};
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        error = "Could not determine file size.";
        return {};
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            error = "Could not read target file.";
            return {};
        }
    }
    return data;
}

bool is_ascii_string_byte(std::uint8_t value) {
    return value >= 0x20 && value <= 0x7e;
}

std::vector<ExtractedString> extract_ascii_strings(const std::vector<std::uint8_t>& data, const Options& options) {
    std::vector<ExtractedString> results;
    std::string current;
    std::size_t current_offset = 0;

    auto flush = [&]() {
        if (current.size() >= options.min_string && results.size() < options.max_strings) {
            results.push_back({current_offset, "ascii", current});
        }
        current.clear();
    };

    for (std::size_t offset = 0; offset < data.size(); ++offset) {
        if (is_ascii_string_byte(data[offset])) {
            if (current.empty()) {
                current_offset = offset;
            }
            current.push_back(static_cast<char>(data[offset]));
        } else {
            flush();
            if (results.size() >= options.max_strings) {
                break;
            }
        }
    }
    if (results.size() < options.max_strings) {
        flush();
    }
    return results;
}

std::vector<ExtractedString> extract_utf16le_strings(const std::vector<std::uint8_t>& data, const Options& options) {
    std::vector<ExtractedString> results;
    const std::size_t width = 2;

    for (std::size_t alignment = 0; alignment < width && alignment + 1 < data.size(); ++alignment) {
        std::string current;
        std::size_t current_offset = alignment;

        auto flush = [&]() {
            if (current.size() >= options.min_string && results.size() < options.max_strings) {
                results.push_back({current_offset, "utf16le", current});
            }
            current.clear();
        };

        for (std::size_t offset = alignment; offset + 1 < data.size(); offset += width) {
            std::uint8_t low = data[offset];
            std::uint8_t high = data[offset + 1];
            if (high == 0x00 && is_ascii_string_byte(low)) {
                if (current.empty()) {
                    current_offset = offset;
                }
                current.push_back(static_cast<char>(low));
            } else {
                flush();
                if (results.size() >= options.max_strings) {
                    return results;
                }
            }
        }
        if (results.size() < options.max_strings) {
            flush();
        }
        if (results.size() >= options.max_strings) {
            break;
        }
    }

    return results;
}

std::vector<ExtractedString> extract_strings(const std::vector<std::uint8_t>& data, const Options& options) {
    std::vector<ExtractedString> results = extract_ascii_strings(data, options);
    if (results.size() < options.max_strings) {
        std::vector<ExtractedString> unicode_results = extract_utf16le_strings(data, options);
        results.insert(results.end(), unicode_results.begin(), unicode_results.end());
    }
    std::sort(
        results.begin(),
        results.end(),
        [](const ExtractedString& left, const ExtractedString& right) {
            if (left.offset != right.offset) {
                return left.offset < right.offset;
            }
            return left.kind < right.kind;
        }
    );
    if (results.size() > options.max_strings) {
        results.resize(options.max_strings);
    }
    return results;
}

double entropy(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0.0;
    }
    std::array<std::size_t, 256> counts{};
    for (std::size_t index = 0; index < size; ++index) {
        ++counts[data[index]];
    }
    double result = 0.0;
    for (std::size_t count : counts) {
        if (count == 0) {
            continue;
        }
        double probability = static_cast<double>(count) / static_cast<double>(size);
        result -= probability * std::log2(probability);
    }
    return result;
}

std::vector<EntropyRegion> high_entropy_regions(const std::vector<std::uint8_t>& data, const Options& options) {
    std::vector<EntropyRegion> regions;
    if (data.empty()) {
        return regions;
    }
    for (std::size_t offset = 0; offset < data.size(); offset += options.entropy_window) {
        std::size_t size = std::min(options.entropy_window, data.size() - offset);
        double value = entropy(data.data() + offset, size);
        if (value >= options.entropy_threshold) {
            regions.push_back({offset, size, value});
        }
        if (regions.size() >= options.max_entropy_regions) {
            break;
        }
    }
    return regions;
}

void write_json(const Options& options, const std::vector<std::uint8_t>& data) {
    std::vector<ExtractedString> strings = extract_strings(data, options);
    std::vector<EntropyRegion> regions = high_entropy_regions(data, options);

    std::cout << "{";
    std::cout << "\"tool\":\"perf_scan\",";
    std::cout << "\"version\":1,";
    std::cout << "\"target\":\"" << json_escape(options.path) << "\",";
    std::cout << "\"size\":" << data.size() << ",";
    std::cout << "\"strings\":{";
    std::cout << "\"min_length\":" << options.min_string << ",";
    std::cout << "\"limit\":" << options.max_strings << ",";
    std::cout << "\"count\":" << strings.size() << ",";
    std::cout << "\"items\":[";
    for (std::size_t index = 0; index < strings.size(); ++index) {
        if (index != 0) {
            std::cout << ",";
        }
        std::cout << "{\"offset\":" << strings[index].offset << ",\"kind\":\"" << strings[index].kind
                  << "\",\"value\":\"" << json_escape(strings[index].value) << "\"}";
    }
    std::cout << "]},";
    std::cout << "\"entropy\":{";
    std::cout << "\"window\":" << options.entropy_window << ",";
    std::cout << "\"threshold\":" << options.entropy_threshold << ",";
    std::cout << "\"region_count\":" << regions.size() << ",";
    std::cout << "\"regions\":[";
    for (std::size_t index = 0; index < regions.size(); ++index) {
        if (index != 0) {
            std::cout << ",";
        }
        std::cout << "{\"offset\":" << regions[index].offset << ",\"size\":" << regions[index].size
                  << ",\"entropy\":" << std::fixed << std::setprecision(4) << regions[index].entropy << "}";
    }
    std::cout << "]}}";
    std::cout << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    Options options;
    std::string error;
    if (!parse_args(argc, argv, options, error)) {
        std::cerr << error << "\n";
        return 2;
    }
    if (options.show_help) {
        write_help();
        return 0;
    }

    std::vector<std::uint8_t> data = read_file(options.path, error);
    if (!error.empty()) {
        std::cerr << error << "\n";
        return 2;
    }

    write_json(options, data);
    return 0;
}
