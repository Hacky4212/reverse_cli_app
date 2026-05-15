#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_FILE_DLL 0x2000u
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define IMAGE_SCN_MEM_WRITE 0x80000000u
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0u
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1u
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5u
#define IMAGE_DIRECTORY_ENTRY_TLS 9u
#define MAX_DATA_DIRS 16u
#define MAX_SECTIONS 96u
#define MAX_EXPORT_NAMES 64u
#define MAX_IMPORT_DLLS 64u
#define MAX_IMPORT_FUNCS 64u
#define MAX_STRING_COPY 256u

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_pointer;
    uint32_t characteristics;
} SectionView;

typedef struct {
    const uint8_t *data;
    size_t size;
    uint16_t machine;
    uint16_t section_count;
    uint16_t characteristics;
    uint16_t optional_magic;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t entry_point_rva;
    uint32_t size_of_headers;
    uint64_t image_base;
    uint32_t dir_rva[MAX_DATA_DIRS];
    uint32_t dir_size[MAX_DATA_DIRS];
    SectionView sections[MAX_SECTIONS];
} PeView;

static int has_range(size_t size, size_t offset, size_t length) {
    return offset <= size && length <= size - offset;
}

static int read_u16(const uint8_t *data, size_t size, size_t offset, uint16_t *out) {
    if (!has_range(size, offset, 2u)) {
        return 0;
    }
    *out = (uint16_t)data[offset] | ((uint16_t)data[offset + 1u] << 8u);
    return 1;
}

static int read_u32(const uint8_t *data, size_t size, size_t offset, uint32_t *out) {
    if (!has_range(size, offset, 4u)) {
        return 0;
    }
    *out = (uint32_t)data[offset] |
           ((uint32_t)data[offset + 1u] << 8u) |
           ((uint32_t)data[offset + 2u] << 16u) |
           ((uint32_t)data[offset + 3u] << 24u);
    return 1;
}

static int read_u64(const uint8_t *data, size_t size, size_t offset, uint64_t *out) {
    uint32_t lo = 0;
    uint32_t hi = 0;
    if (!read_u32(data, size, offset, &lo) || !read_u32(data, size, offset + 4u, &hi)) {
        return 0;
    }
    *out = (uint64_t)lo | ((uint64_t)hi << 32u);
    return 1;
}

static uint32_t max_u32(uint32_t left, uint32_t right) {
    return left > right ? left : right;
}

static void print_json_string(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    putchar('"');
    while (*cursor != '\0') {
        unsigned char ch = *cursor++;
        switch (ch) {
            case '\\':
                fputs("\\\\", stdout);
                break;
            case '"':
                fputs("\\\"", stdout);
                break;
            case '\b':
                fputs("\\b", stdout);
                break;
            case '\f':
                fputs("\\f", stdout);
                break;
            case '\n':
                fputs("\\n", stdout);
                break;
            case '\r':
                fputs("\\r", stdout);
                break;
            case '\t':
                fputs("\\t", stdout);
                break;
            default:
                if (ch < 0x20u) {
                    printf("\\u%04x", (unsigned int)ch);
                } else {
                    putchar((int)ch);
                }
                break;
        }
    }
    putchar('"');
}

static void copy_section_name(const uint8_t *raw, char out[9]) {
    size_t index = 0;
    for (; index < 8u; ++index) {
        unsigned char ch = raw[index];
        if (ch == 0u) {
            break;
        }
        out[index] = (ch >= 0x20u && ch <= 0x7eu) ? (char)ch : '.';
    }
    out[index] = '\0';
}

static int read_c_string(const uint8_t *data, size_t size, size_t offset, char *out, size_t out_size) {
    size_t index = 0;
    if (out_size == 0u || offset >= size) {
        return 0;
    }
    while (offset + index < size && index + 1u < out_size) {
        unsigned char ch = data[offset + index];
        if (ch == 0u) {
            out[index] = '\0';
            return 1;
        }
        out[index] = (ch >= 0x20u && ch <= 0x7eu) ? (char)ch : '.';
        ++index;
    }
    out[index] = '\0';
    return index > 0u;
}

static int rva_to_offset(const PeView *pe, uint32_t rva, size_t *out) {
    uint16_t index = 0;
    if (rva < pe->size_of_headers && rva < pe->size) {
        *out = (size_t)rva;
        return 1;
    }
    for (; index < pe->section_count; ++index) {
        const SectionView *section = &pe->sections[index];
        uint32_t span = max_u32(section->virtual_size, section->raw_size);
        if (span == 0u) {
            continue;
        }
        if (rva >= section->virtual_address && rva < section->virtual_address + span) {
            uint32_t delta = rva - section->virtual_address;
            size_t offset = (size_t)section->raw_pointer + (size_t)delta;
            if (offset < pe->size) {
                *out = offset;
                return 1;
            }
        }
    }
    return 0;
}

static const char *machine_name(uint16_t machine) {
    switch (machine) {
        case 0x014cu:
            return "x86";
        case 0x8664u:
            return "x64";
        case 0xaa64u:
            return "arm64";
        case 0x01c4u:
            return "armv7";
        default:
            return "unknown";
    }
}

static const char *subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
        case 1u:
            return "native";
        case 2u:
            return "windows_gui";
        case 3u:
            return "windows_cui";
        case 9u:
            return "windows_ce_gui";
        case 10u:
            return "efi_application";
        case 11u:
            return "efi_boot_service_driver";
        case 12u:
            return "efi_runtime_driver";
        default:
            return "unknown";
    }
}

static int parse_pe(const uint8_t *data, size_t size, PeView *pe, const char **error) {
    uint32_t pe_offset = 0;
    uint16_t optional_size = 0;
    size_t coff_offset = 0;
    size_t optional_offset = 0;
    size_t section_offset = 0;
    uint32_t data_dir_count = 0;
    uint32_t data_dir_offset = 0;
    uint16_t index = 0;

    memset(pe, 0, sizeof(*pe));
    pe->data = data;
    pe->size = size;

    if (size < 0x40u || data[0] != 'M' || data[1] != 'Z') {
        *error = "Missing MZ header.";
        return 0;
    }
    if (!read_u32(data, size, 0x3cu, &pe_offset) || !has_range(size, (size_t)pe_offset, 24u)) {
        *error = "Invalid PE header offset.";
        return 0;
    }
    if (data[pe_offset] != 'P' || data[pe_offset + 1u] != 'E' || data[pe_offset + 2u] != 0u || data[pe_offset + 3u] != 0u) {
        *error = "Missing PE signature.";
        return 0;
    }

    coff_offset = (size_t)pe_offset + 4u;
    if (!read_u16(data, size, coff_offset, &pe->machine) ||
        !read_u16(data, size, coff_offset + 2u, &pe->section_count) ||
        !read_u16(data, size, coff_offset + 16u, &optional_size) ||
        !read_u16(data, size, coff_offset + 18u, &pe->characteristics)) {
        *error = "Invalid COFF header.";
        return 0;
    }

    if (pe->section_count > MAX_SECTIONS) {
        *error = "Too many sections for safe parsing.";
        return 0;
    }

    optional_offset = coff_offset + 20u;
    if (!has_range(size, optional_offset, optional_size) || optional_size < 96u) {
        *error = "Invalid optional header.";
        return 0;
    }
    if (!read_u16(data, size, optional_offset, &pe->optional_magic) ||
        !read_u32(data, size, optional_offset + 16u, &pe->entry_point_rva) ||
        !read_u16(data, size, optional_offset + 68u, &pe->subsystem) ||
        !read_u16(data, size, optional_offset + 70u, &pe->dll_characteristics) ||
        !read_u32(data, size, optional_offset + 60u, &pe->size_of_headers)) {
        *error = "Invalid optional header fields.";
        return 0;
    }

    if (pe->optional_magic == 0x10bu) {
        uint32_t base32 = 0;
        if (!read_u32(data, size, optional_offset + 28u, &base32) ||
            !read_u32(data, size, optional_offset + 92u, &data_dir_count)) {
            *error = "Invalid PE32 optional header.";
            return 0;
        }
        pe->image_base = (uint64_t)base32;
        data_dir_offset = 96u;
    } else if (pe->optional_magic == 0x20bu) {
        if (!read_u64(data, size, optional_offset + 24u, &pe->image_base) ||
            !read_u32(data, size, optional_offset + 108u, &data_dir_count)) {
            *error = "Invalid PE32+ optional header.";
            return 0;
        }
        data_dir_offset = 112u;
    } else {
        *error = "Unsupported PE optional header magic.";
        return 0;
    }

    for (index = 0; index < MAX_DATA_DIRS && index < data_dir_count; ++index) {
        size_t entry_offset = optional_offset + data_dir_offset + ((size_t)index * 8u);
        if (!has_range(optional_size, data_dir_offset + ((size_t)index * 8u), 8u)) {
            break;
        }
        (void)read_u32(data, size, entry_offset, &pe->dir_rva[index]);
        (void)read_u32(data, size, entry_offset + 4u, &pe->dir_size[index]);
    }

    section_offset = optional_offset + optional_size;
    if (!has_range(size, section_offset, (size_t)pe->section_count * 40u)) {
        *error = "Invalid section table.";
        return 0;
    }

    for (index = 0; index < pe->section_count; ++index) {
        size_t current = section_offset + ((size_t)index * 40u);
        copy_section_name(&data[current], pe->sections[index].name);
        (void)read_u32(data, size, current + 8u, &pe->sections[index].virtual_size);
        (void)read_u32(data, size, current + 12u, &pe->sections[index].virtual_address);
        (void)read_u32(data, size, current + 16u, &pe->sections[index].raw_size);
        (void)read_u32(data, size, current + 20u, &pe->sections[index].raw_pointer);
        (void)read_u32(data, size, current + 36u, &pe->sections[index].characteristics);
    }

    return 1;
}

static int read_file(const char *path, uint8_t **out_data, size_t *out_size) {
    FILE *handle = fopen(path, "rb");
    long length = 0;
    uint8_t *buffer = NULL;

    if (handle == NULL) {
        return 0;
    }
    if (fseek(handle, 0, SEEK_END) != 0) {
        fclose(handle);
        return 0;
    }
    length = ftell(handle);
    if (length < 0) {
        fclose(handle);
        return 0;
    }
    if (fseek(handle, 0, SEEK_SET) != 0) {
        fclose(handle);
        return 0;
    }
    buffer = (uint8_t *)malloc((size_t)length + 1u);
    if (buffer == NULL) {
        fclose(handle);
        return 0;
    }
    if ((size_t)length > 0u && fread(buffer, 1u, (size_t)length, handle) != (size_t)length) {
        free(buffer);
        fclose(handle);
        return 0;
    }
    fclose(handle);
    *out_data = buffer;
    *out_size = (size_t)length;
    return 1;
}

static void print_sections(const PeView *pe) {
    uint16_t index = 0;
    fputs("\"sections\":[", stdout);
    for (; index < pe->section_count; ++index) {
        const SectionView *section = &pe->sections[index];
        if (index > 0u) {
            putchar(',');
        }
        putchar('{');
        fputs("\"name\":", stdout);
        print_json_string(section->name);
        printf(",\"virtual_address\":\"0x%08x\"", section->virtual_address);
        printf(",\"virtual_size\":%u", section->virtual_size);
        printf(",\"raw_pointer\":\"0x%08x\"", section->raw_pointer);
        printf(",\"raw_size\":%u", section->raw_size);
        printf(",\"characteristics\":\"0x%08x\"", section->characteristics);
        printf(",\"executable\":%s", (section->characteristics & IMAGE_SCN_MEM_EXECUTE) ? "true" : "false");
        printf(",\"writable\":%s", (section->characteristics & IMAGE_SCN_MEM_WRITE) ? "true" : "false");
        putchar('}');
    }
    putchar(']');
}

static void print_exports(const PeView *pe) {
    uint32_t export_rva = pe->dir_rva[IMAGE_DIRECTORY_ENTRY_EXPORT];
    size_t export_offset = 0;
    uint32_t function_count = 0;
    uint32_t name_count = 0;
    uint32_t names_rva = 0;
    uint32_t index = 0;
    unsigned int printed = 0;

    fputs("\"exports\":", stdout);
    if (export_rva == 0u || pe->dir_size[IMAGE_DIRECTORY_ENTRY_EXPORT] == 0u ||
        !rva_to_offset(pe, export_rva, &export_offset) ||
        !has_range(pe->size, export_offset, 40u)) {
        fputs("{\"present\":false,\"function_count\":0,\"name_count\":0,\"names\":[]}", stdout);
        return;
    }

    (void)read_u32(pe->data, pe->size, export_offset + 20u, &function_count);
    (void)read_u32(pe->data, pe->size, export_offset + 24u, &name_count);
    (void)read_u32(pe->data, pe->size, export_offset + 32u, &names_rva);

    printf("{\"present\":true,\"function_count\":%u,\"name_count\":%u,\"names\":[", function_count, name_count);
    for (index = 0; index < name_count && printed < MAX_EXPORT_NAMES; ++index) {
        size_t names_offset = 0;
        uint32_t name_rva = 0;
        size_t name_offset = 0;
        char name[MAX_STRING_COPY];
        if (!rva_to_offset(pe, names_rva + (index * 4u), &names_offset) ||
            !read_u32(pe->data, pe->size, names_offset, &name_rva) ||
            !rva_to_offset(pe, name_rva, &name_offset) ||
            !read_c_string(pe->data, pe->size, name_offset, name, sizeof(name))) {
            continue;
        }
        if (printed > 0u) {
            putchar(',');
        }
        print_json_string(name);
        ++printed;
    }
    fputs("]}", stdout);
}

static void print_import_functions(const PeView *pe, uint32_t thunk_rva) {
    size_t thunk_offset = 0;
    unsigned int index = 0;
    unsigned int printed = 0;
    int is_pe32_plus = pe->optional_magic == 0x20bu;
    uint64_t ordinal_mask = is_pe32_plus ? 0x8000000000000000ull : 0x80000000ull;
    size_t thunk_size = is_pe32_plus ? 8u : 4u;

    putchar('[');
    if (thunk_rva == 0u || !rva_to_offset(pe, thunk_rva, &thunk_offset)) {
        putchar(']');
        return;
    }

    for (; index < MAX_IMPORT_FUNCS; ++index) {
        uint64_t thunk_value = 0;
        if (is_pe32_plus) {
            if (!read_u64(pe->data, pe->size, thunk_offset + ((size_t)index * thunk_size), &thunk_value)) {
                break;
            }
        } else {
            uint32_t thunk32 = 0;
            if (!read_u32(pe->data, pe->size, thunk_offset + ((size_t)index * thunk_size), &thunk32)) {
                break;
            }
            thunk_value = (uint64_t)thunk32;
        }
        if (thunk_value == 0u) {
            break;
        }
        if (printed > 0u) {
            putchar(',');
        }
        if ((thunk_value & ordinal_mask) != 0u) {
            char ordinal[32];
            unsigned long long ordinal_value = (unsigned long long)(thunk_value & 0xffffu);
            (void)snprintf(ordinal, sizeof(ordinal), "#%llu", ordinal_value);
            print_json_string(ordinal);
        } else {
            size_t name_offset = 0;
            char name[MAX_STRING_COPY];
            if (rva_to_offset(pe, (uint32_t)thunk_value, &name_offset) &&
                has_range(pe->size, name_offset, 2u) &&
                read_c_string(pe->data, pe->size, name_offset + 2u, name, sizeof(name))) {
                print_json_string(name);
            } else {
                print_json_string("<unresolved>");
            }
        }
        ++printed;
    }
    putchar(']');
}

static void print_imports(const PeView *pe) {
    uint32_t import_rva = pe->dir_rva[IMAGE_DIRECTORY_ENTRY_IMPORT];
    size_t descriptor_offset = 0;
    unsigned int index = 0;
    unsigned int printed = 0;

    fputs("\"imports\":", stdout);
    if (import_rva == 0u || pe->dir_size[IMAGE_DIRECTORY_ENTRY_IMPORT] == 0u ||
        !rva_to_offset(pe, import_rva, &descriptor_offset)) {
        fputs("{\"present\":false,\"dll_count\":0,\"dlls\":[]}", stdout);
        return;
    }

    fputs("{\"present\":true,\"dlls\":[", stdout);
    for (; index < MAX_IMPORT_DLLS; ++index) {
        size_t current = descriptor_offset + ((size_t)index * 20u);
        uint32_t original_thunk = 0;
        uint32_t name_rva = 0;
        uint32_t first_thunk = 0;
        size_t name_offset = 0;
        char dll_name[MAX_STRING_COPY];

        if (!has_range(pe->size, current, 20u)) {
            break;
        }
        (void)read_u32(pe->data, pe->size, current, &original_thunk);
        (void)read_u32(pe->data, pe->size, current + 12u, &name_rva);
        (void)read_u32(pe->data, pe->size, current + 16u, &first_thunk);
        if (original_thunk == 0u && name_rva == 0u && first_thunk == 0u) {
            break;
        }
        if (!rva_to_offset(pe, name_rva, &name_offset) ||
            !read_c_string(pe->data, pe->size, name_offset, dll_name, sizeof(dll_name))) {
            strcpy(dll_name, "<unresolved>");
        }
        if (printed > 0u) {
            putchar(',');
        }
        putchar('{');
        fputs("\"name\":", stdout);
        print_json_string(dll_name);
        fputs(",\"functions\":", stdout);
        print_import_functions(pe, original_thunk != 0u ? original_thunk : first_thunk);
        putchar('}');
        ++printed;
    }
    printf("],\"dll_count\":%u}", printed);
}

static void print_risk(const PeView *pe) {
    uint16_t index = 0;
    unsigned int printed = 0;
    fputs("\"risk\":{\"writable_executable_sections\":[", stdout);
    for (; index < pe->section_count; ++index) {
        const SectionView *section = &pe->sections[index];
        if ((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u &&
            (section->characteristics & IMAGE_SCN_MEM_WRITE) != 0u) {
            if (printed > 0u) {
                putchar(',');
            }
            print_json_string(section->name);
            ++printed;
        }
    }
    printf("],\"has_tls\":%s", pe->dir_size[IMAGE_DIRECTORY_ENTRY_TLS] > 0u ? "true" : "false");
    printf(",\"has_relocations\":%s", pe->dir_size[IMAGE_DIRECTORY_ENTRY_BASERELOC] > 0u ? "true" : "false");
    putchar('}');
}

int main(int argc, char **argv) {
    const char *target = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    PeView pe;
    const char *error = NULL;

    if (argc != 2) {
        fputs("Usage: dll_audit <dll-or-pe-file>\n", stderr);
        return 2;
    }

    target = argv[1];
    if (!read_file(target, &data, &size)) {
        printf("{\"tool\":\"dll_audit\",\"target\":");
        print_json_string(target);
        printf(",\"valid\":false,\"format\":\"unknown\",\"error\":");
        print_json_string(strerror(errno));
        puts("}");
        return 1;
    }

    printf("{\"tool\":\"dll_audit\",\"target\":");
    print_json_string(target);
    printf(",\"file_size\":%llu", (unsigned long long)size);

    if (!parse_pe(data, size, &pe, &error)) {
        printf(",\"valid\":false,\"format\":\"unknown\",\"error\":");
        print_json_string(error != NULL ? error : "Invalid PE file.");
        puts("}");
        free(data);
        return 0;
    }

    printf(",\"valid\":true,\"format\":\"PE\"");
    printf(",\"is_dll\":%s", (pe.characteristics & IMAGE_FILE_DLL) ? "true" : "false");
    printf(",\"machine\":");
    print_json_string(machine_name(pe.machine));
    printf(",\"machine_value\":\"0x%04x\"", pe.machine);
    printf(",\"subsystem\":");
    print_json_string(subsystem_name(pe.subsystem));
    printf(",\"subsystem_value\":%u", pe.subsystem);
    printf(",\"optional_magic\":\"0x%04x\"", pe.optional_magic);
    printf(",\"image_base\":\"0x%llx\"", (unsigned long long)pe.image_base);
    printf(",\"entry_point_rva\":\"0x%08x\"", pe.entry_point_rva);
    printf(",\"dll_characteristics\":\"0x%04x\"", pe.dll_characteristics);
    printf(",\"section_count\":%u,", pe.section_count);
    print_sections(&pe);
    putchar(',');
    print_exports(&pe);
    putchar(',');
    print_imports(&pe);
    putchar(',');
    print_risk(&pe);
    puts("}");

    free(data);
    return 0;
}
