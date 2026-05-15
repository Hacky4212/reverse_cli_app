#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PROCESS_MEMORY_VERSION "0.1.0"
#define PROCESS_MEMORY_MAX_READ 4096U

typedef struct {
    DWORD pid;
    uint64_t address;
    size_t requested_size;
    size_t effective_size;
    bool limited;
} ReaderRequest;

static void print_json_string(FILE* out, const char* value) {
    const unsigned char* cursor = (const unsigned char*)(value ? value : "");
    fputc('"', out);
    while (*cursor != '\0') {
        switch (*cursor) {
            case '\\':
                fputs("\\\\", out);
                break;
            case '"':
                fputs("\\\"", out);
                break;
            case '\b':
                fputs("\\b", out);
                break;
            case '\f':
                fputs("\\f", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (*cursor < 0x20) {
                    fprintf(out, "\\u%04x", (unsigned int)*cursor);
                } else {
                    fputc((int)*cursor, out);
                }
                break;
        }
        ++cursor;
    }
    fputc('"', out);
}

static void print_u64_hex(FILE* out, uint64_t value) {
    fprintf(out, "\"0x%llX\"", (unsigned long long)value);
}

static char* trim_line_breaks(char* text) {
    if (!text) {
        return text;
    }
    size_t length = strlen(text);
    while (length > 0 && (text[length - 1] == '\r' || text[length - 1] == '\n')) {
        text[--length] = '\0';
    }
    return text;
}

static char* format_windows_error(DWORD error_code) {
    char* message = NULL;
    const DWORD flags =
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    if (FormatMessageA(flags, NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPSTR)&message, 0, NULL) == 0 || message == NULL) {
        return NULL;
    }
    return trim_line_breaks(message);
}

static void print_usage(FILE* out) {
    fputs("usage: process_memory_reader --pid <pid> --address <address> [--size <bytes>]\n", out);
}

static bool parse_u64(const char* text, uint64_t* out) {
    if (text == NULL || out == NULL) {
        return false;
    }

    errno = 0;
    char* end = NULL;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno != 0 || end == text || end == NULL || *end != '\0') {
        return false;
    }

    *out = (uint64_t)value;
    return true;
}

static void print_protect_name(FILE* out, DWORD protect) {
    const DWORD base = protect & 0xFFU;
    const bool guard = (protect & PAGE_GUARD) != 0;
    const bool nocache = (protect & PAGE_NOCACHE) != 0;
    const bool writecombine = (protect & PAGE_WRITECOMBINE) != 0;

    fputc('"', out);
    switch (base) {
        case PAGE_NOACCESS:
            fputs("PAGE_NOACCESS", out);
            break;
        case PAGE_READONLY:
            fputs("PAGE_READONLY", out);
            break;
        case PAGE_READWRITE:
            fputs("PAGE_READWRITE", out);
            break;
        case PAGE_WRITECOPY:
            fputs("PAGE_WRITECOPY", out);
            break;
        case PAGE_EXECUTE:
            fputs("PAGE_EXECUTE", out);
            break;
        case PAGE_EXECUTE_READ:
            fputs("PAGE_EXECUTE_READ", out);
            break;
        case PAGE_EXECUTE_READWRITE:
            fputs("PAGE_EXECUTE_READWRITE", out);
            break;
        case PAGE_EXECUTE_WRITECOPY:
            fputs("PAGE_EXECUTE_WRITECOPY", out);
            break;
        default:
            fprintf(out, "0x%lX", (unsigned long)protect);
            break;
    }

    if (guard) {
        fputs("|PAGE_GUARD", out);
    }
    if (nocache) {
        fputs("|PAGE_NOCACHE", out);
    }
    if (writecombine) {
        fputs("|PAGE_WRITECOMBINE", out);
    }
    fputc('"', out);
}

static void print_state_name(FILE* out, DWORD state) {
    switch (state) {
        case MEM_COMMIT:
            fputs("\"MEM_COMMIT\"", out);
            return;
        case MEM_RESERVE:
            fputs("\"MEM_RESERVE\"", out);
            return;
        case MEM_FREE:
            fputs("\"MEM_FREE\"", out);
            return;
        default:
            fprintf(out, "\"0x%lX\"", (unsigned long)state);
            return;
    }
}

static void print_type_name(FILE* out, DWORD type) {
    switch (type) {
        case MEM_PRIVATE:
            fputs("\"MEM_PRIVATE\"", out);
            return;
        case MEM_MAPPED:
            fputs("\"MEM_MAPPED\"", out);
            return;
        case MEM_IMAGE:
            fputs("\"MEM_IMAGE\"", out);
            return;
        default:
            fprintf(out, "\"0x%lX\"", (unsigned long)type);
            return;
    }
}

static void print_region(FILE* out, const MEMORY_BASIC_INFORMATION* mbi) {
    if (mbi == NULL) {
        fputs("null", out);
        return;
    }

    fputs("{", out);
    fputs("\"base_address\":", out);
    print_u64_hex(out, (uint64_t)(uintptr_t)mbi->BaseAddress);
    fputs(",\"allocation_base\":", out);
    print_u64_hex(out, (uint64_t)(uintptr_t)mbi->AllocationBase);
    fprintf(out, ",\"region_size\":%zu,", (size_t)mbi->RegionSize);
    fputs("\"state\":", out);
    print_state_name(out, mbi->State);
    fputs(",\"protect\":", out);
    print_protect_name(out, mbi->Protect);
    fputs(",\"type\":", out);
    print_type_name(out, mbi->Type);
    fputc('}', out);
}

static void print_hex_preview(FILE* out, const unsigned char* data, size_t size) {
    fputc('"', out);
    for (size_t index = 0; index < size; ++index) {
        if (index != 0) {
            fputc(' ', out);
        }
        fprintf(out, "%02X", data[index]);
    }
    fputc('"', out);
}

static void print_ascii_preview(FILE* out, const unsigned char* data, size_t size) {
    fputc('"', out);
    for (size_t index = 0; index < size; ++index) {
        const unsigned char ch = data[index];
        if (ch >= 0x20 && ch <= 0x7E) {
            fputc((int)ch, out);
        } else {
            fputc('.', out);
        }
    }
    fputc('"', out);
}

static void print_failure_json(const ReaderRequest* request, const char* error_text, DWORD error_code) {
    fputs("{", stdout);
    fputs("\"tool\":\"process_memory_reader\",", stdout);
    fputs("\"version\":\"" PROCESS_MEMORY_VERSION "\",", stdout);
    fputs("\"target\":\"", stdout);
    fprintf(stdout, "pid-%lu-", (unsigned long)request->pid);
    fprintf(stdout, "0x%llX", (unsigned long long)request->address);
    fputs("\",", stdout);
    fprintf(stdout, "\"pid\":%lu,", (unsigned long)request->pid);
    fputs("\"address\":", stdout);
    print_u64_hex(stdout, request->address);
    fprintf(stdout, ",\"requested_size\":%zu,", request->requested_size);
    fprintf(stdout, "\"read_size\":0,\"limited\":%s,", request->limited ? "true" : "false");
    fputs("\"success\":false,\"partial\":false,\"region\":null,", stdout);
    fputs("\"data_hex\":\"\",\"data_ascii\":\"\",", stdout);
    fputs("\"error\":", stdout);
    if (error_text) {
        print_json_string(stdout, error_text);
    } else {
        char buffer[128];
        if (error_code != 0) {
            snprintf(buffer, sizeof(buffer), "Windows error %lu", (unsigned long)error_code);
        } else {
            snprintf(buffer, sizeof(buffer), "Unknown error");
        }
        print_json_string(stdout, buffer);
    }
    fputs("}", stdout);
    fputc('\n', stdout);
}

static int run_reader(const ReaderRequest* request) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, request->pid);
    if (process == NULL) {
        DWORD error_code = GetLastError();
        char* message = format_windows_error(error_code);
        char error_text[256];
        if (message) {
            snprintf(error_text, sizeof(error_text), "OpenProcess failed: %s", message);
            LocalFree(message);
            print_failure_json(request, error_text, error_code);
        } else {
            print_failure_json(request, NULL, error_code);
        }
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    MEMORY_BASIC_INFORMATION* region = NULL;
    if (VirtualQueryEx(process, (LPCVOID)(uintptr_t)request->address, &mbi, sizeof(mbi)) != 0) {
        region = &mbi;
    }

    unsigned char* buffer = (unsigned char*)malloc(request->effective_size);
    if (buffer == NULL) {
        CloseHandle(process);
        print_failure_json(request, "Out of memory while allocating the read buffer.", 0);
        return 1;
    }

    SIZE_T bytes_read = 0;
    const BOOL ok = ReadProcessMemory(process, (LPCVOID)(uintptr_t)request->address, buffer,
                                      request->effective_size, &bytes_read);

    fputs("{", stdout);
    fputs("\"tool\":\"process_memory_reader\",", stdout);
    fputs("\"version\":\"" PROCESS_MEMORY_VERSION "\",", stdout);
    fputs("\"target\":\"", stdout);
    fprintf(stdout, "pid-%lu-", (unsigned long)request->pid);
    fprintf(stdout, "0x%llX", (unsigned long long)request->address);
    fputs("\",", stdout);
    fprintf(stdout, "\"pid\":%lu,", (unsigned long)request->pid);
    fputs("\"address\":", stdout);
    print_u64_hex(stdout, request->address);
    fprintf(stdout, ",\"requested_size\":%zu,", request->requested_size);
    fprintf(stdout, "\"read_size\":%zu,", (size_t)bytes_read);
    fprintf(stdout, "\"limited\":%s,", request->limited ? "true" : "false");
    fprintf(stdout, "\"success\":%s,", ok ? "true" : "false");
    fprintf(stdout, "\"partial\":%s,", (!ok && bytes_read > 0) ? "true" : "false");
    fputs("\"region\":", stdout);
    print_region(stdout, region);
    fputs(",\"data_hex\":", stdout);
    print_hex_preview(stdout, buffer, (size_t)bytes_read);
    fputs(",\"data_ascii\":", stdout);
    print_ascii_preview(stdout, buffer, (size_t)bytes_read);
    fputs(",\"error\":", stdout);

    if (ok) {
        fputs("null", stdout);
    } else {
        DWORD error_code = GetLastError();
        char* message = format_windows_error(error_code);
        if (message) {
            char error_text[256];
            snprintf(error_text, sizeof(error_text), "ReadProcessMemory failed: %s", message);
            print_json_string(stdout, error_text);
            LocalFree(message);
        } else {
            char error_text[128];
            snprintf(error_text, sizeof(error_text), "ReadProcessMemory failed with Windows error %lu",
                     (unsigned long)error_code);
            print_json_string(stdout, error_text);
        }
    }

    fputs("}", stdout);
    fputc('\n', stdout);

    free(buffer);
    CloseHandle(process);
    return ok ? 0 : 1;
}

static bool parse_args(int argc, char** argv, ReaderRequest* request, bool* help_requested) {
    request->requested_size = 64U;
    request->effective_size = 64U;
    request->limited = false;

    if (help_requested) {
        *help_requested = false;
    }

    bool pid_set = false;
    bool address_set = false;

    for (int index = 1; index < argc; ++index) {
        const char* arg = argv[index];
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(stdout);
            if (help_requested) {
                *help_requested = true;
            }
            return false;
        }
        if (strcmp(arg, "--pid") == 0 && index + 1 < argc) {
            uint64_t value = 0;
            if (!parse_u64(argv[++index], &value) || value > 0xFFFFFFFFULL) {
                fprintf(stderr, "invalid pid: %s\n", argv[index]);
                return false;
            }
            request->pid = (DWORD)value;
            pid_set = true;
            continue;
        }
        if (strcmp(arg, "--address") == 0 && index + 1 < argc) {
            if (!parse_u64(argv[++index], &request->address)) {
                fprintf(stderr, "invalid address: %s\n", argv[index]);
                return false;
            }
            address_set = true;
            continue;
        }
        if (strcmp(arg, "--size") == 0 && index + 1 < argc) {
            uint64_t size_value = 0;
            if (!parse_u64(argv[++index], &size_value)) {
                fprintf(stderr, "invalid size: %s\n", argv[index]);
                return false;
            }
            request->requested_size = (size_t)size_value;
            continue;
        }

        fprintf(stderr, "unknown argument: %s\n", arg);
        return false;
    }

    if (!pid_set || !address_set) {
        print_usage(stderr);
        return false;
    }

    if (request->requested_size == 0U) {
        fprintf(stderr, "size must be greater than zero\n");
        return false;
    }

    if (request->requested_size > PROCESS_MEMORY_MAX_READ) {
        request->effective_size = PROCESS_MEMORY_MAX_READ;
        request->limited = true;
    } else {
        request->effective_size = request->requested_size;
    }

    return true;
}

int main(int argc, char** argv) {
    ReaderRequest request;
    memset(&request, 0, sizeof(request));
    bool help_requested = false;

    if (!parse_args(argc, argv, &request, &help_requested)) {
        return help_requested ? 0 : 2;
    }

    return run_reader(&request);
}

#else

int main(void) {
    fputs("process_memory_reader is only available on Windows.\n", stderr);
    return 2;
}

#endif
