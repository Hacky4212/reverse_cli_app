#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t size;
} ByteBuffer;

static bool has_range(const ByteBuffer* buffer, size_t offset, size_t size) {
    return offset <= buffer->size && size <= buffer->size - offset;
}

static uint16_t read_u16_le(const ByteBuffer* buffer, size_t offset) {
    return (uint16_t)buffer->data[offset] | ((uint16_t)buffer->data[offset + 1] << 8U);
}

static uint16_t read_u16_be(const ByteBuffer* buffer, size_t offset) {
    return (uint16_t)buffer->data[offset + 1] | ((uint16_t)buffer->data[offset] << 8U);
}

static uint32_t read_u32_le(const ByteBuffer* buffer, size_t offset) {
    return (uint32_t)buffer->data[offset] |
           ((uint32_t)buffer->data[offset + 1] << 8U) |
           ((uint32_t)buffer->data[offset + 2] << 16U) |
           ((uint32_t)buffer->data[offset + 3] << 24U);
}

static uint32_t read_u32_be(const ByteBuffer* buffer, size_t offset) {
    return (uint32_t)buffer->data[offset + 3] |
           ((uint32_t)buffer->data[offset + 2] << 8U) |
           ((uint32_t)buffer->data[offset + 1] << 16U) |
           ((uint32_t)buffer->data[offset] << 24U);
}

static uint64_t read_u64_le(const ByteBuffer* buffer, size_t offset) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= (uint64_t)buffer->data[offset + index] << (index * 8U);
    }
    return value;
}

static uint64_t read_u64_be(const ByteBuffer* buffer, size_t offset) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value = (value << 8U) | (uint64_t)buffer->data[offset + index];
    }
    return value;
}

static uint16_t read_u16(const ByteBuffer* buffer, size_t offset, bool little) {
    return little ? read_u16_le(buffer, offset) : read_u16_be(buffer, offset);
}

static uint32_t read_u32(const ByteBuffer* buffer, size_t offset, bool little) {
    return little ? read_u32_le(buffer, offset) : read_u32_be(buffer, offset);
}

static uint64_t read_u64(const ByteBuffer* buffer, size_t offset, bool little) {
    return little ? read_u64_le(buffer, offset) : read_u64_be(buffer, offset);
}

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

static void print_hex_bytes(FILE* out, const ByteBuffer* buffer, size_t limit) {
    const size_t count = buffer->size < limit ? buffer->size : limit;
    fputc('"', out);
    for (size_t index = 0; index < count; ++index) {
        if (index != 0) {
            fputc(' ', out);
        }
        fprintf(out, "%02x", buffer->data[index]);
    }
    fputc('"', out);
}

static void print_machine_name(FILE* out, uint16_t machine) {
    switch (machine) {
        case 0x014C:
            fputs("\"x86\"", out);
            return;
        case 0x8664:
            fputs("\"x64\"", out);
            return;
        case 0x01C0:
            fputs("\"ARM\"", out);
            return;
        case 0xAA64:
            fputs("\"ARM64\"", out);
            return;
        default:
            fprintf(out, "\"0x%X\"", machine);
            return;
    }
}

static void print_optional_name(FILE* out, uint16_t magic) {
    switch (magic) {
        case 0x10B:
            fputs("\"PE32\"", out);
            return;
        case 0x20B:
            fputs("\"PE32+\"", out);
            return;
        default:
            fprintf(out, "\"0x%X\"", magic);
            return;
    }
}

static void print_subsystem_name(FILE* out, uint16_t subsystem) {
    switch (subsystem) {
        case 1:
            fputs("\"NATIVE\"", out);
            return;
        case 2:
            fputs("\"WINDOWS_GUI\"", out);
            return;
        case 3:
            fputs("\"WINDOWS_CUI\"", out);
            return;
        case 10:
            fputs("\"EFI_APPLICATION\"", out);
            return;
        case 11:
            fputs("\"EFI_BOOT_SERVICE_DRIVER\"", out);
            return;
        case 12:
            fputs("\"EFI_RUNTIME_DRIVER\"", out);
            return;
        default:
            fprintf(out, "\"%u\"", subsystem);
            return;
    }
}

static void print_elf_type_name(FILE* out, uint16_t value) {
    switch (value) {
        case 0:
            fputs("\"NONE\"", out);
            return;
        case 1:
            fputs("\"REL\"", out);
            return;
        case 2:
            fputs("\"EXEC\"", out);
            return;
        case 3:
            fputs("\"DYN\"", out);
            return;
        case 4:
            fputs("\"CORE\"", out);
            return;
        default:
            fprintf(out, "\"%u\"", value);
            return;
    }
}

static void print_elf_machine_name(FILE* out, uint16_t value) {
    switch (value) {
        case 3:
            fputs("\"x86\"", out);
            return;
        case 40:
            fputs("\"ARM\"", out);
            return;
        case 62:
            fputs("\"x64\"", out);
            return;
        case 183:
            fputs("\"ARM64\"", out);
            return;
        default:
            fprintf(out, "\"%u\"", value);
            return;
    }
}

static void section_name(const ByteBuffer* buffer, size_t offset, char out_name[9]) {
    size_t output_index = 0;
    for (size_t index = 0; index < 8 && offset + index < buffer->size; ++index) {
        const unsigned char ch = buffer->data[offset + index];
        if (ch == 0) {
            break;
        }
        if (ch >= 0x20 && ch <= 0x7E) {
            out_name[output_index++] = (char)ch;
        }
    }
    out_name[output_index] = '\0';
}

static void print_common_prefix(FILE* out, const char* target, const ByteBuffer* buffer) {
    fputs("{\"tool\":\"native_probe\",\"version\":\"0.1.0\",\"target\":", out);
    print_json_string(out, target);
    fprintf(out, ",\"file_size\":%zu,\"magic\":", buffer->size);
    print_hex_bytes(out, buffer, 16);
    fputc(',', out);
}

static void probe_pe(FILE* out, const char* target, const ByteBuffer* buffer) {
    print_common_prefix(out, target, buffer);
    fputs("\"format\":\"PE\",", out);

    const uint32_t pe_offset = read_u32_le(buffer, 0x3C);
    if (!has_range(buffer, pe_offset, 24) || buffer->data[pe_offset] != 'P' ||
        buffer->data[pe_offset + 1] != 'E' || buffer->data[pe_offset + 2] != 0 ||
        buffer->data[pe_offset + 3] != 0) {
        fputs("\"valid\":false,\"error\":\"MZ header found, but PE signature is invalid.\"}", out);
        return;
    }

    const uint16_t machine = read_u16_le(buffer, pe_offset + 4);
    const uint16_t sections = read_u16_le(buffer, pe_offset + 6);
    const uint32_t timestamp = read_u32_le(buffer, pe_offset + 8);
    const uint16_t optional_size = read_u16_le(buffer, pe_offset + 20);
    const uint16_t characteristics = read_u16_le(buffer, pe_offset + 22);
    const size_t optional_offset = (size_t)pe_offset + 24U;
    const uint16_t optional_magic =
        has_range(buffer, optional_offset, 2) ? read_u16_le(buffer, optional_offset) : 0;
    const uint16_t subsystem =
        has_range(buffer, optional_offset + 68U, 2) ? read_u16_le(buffer, optional_offset + 68U) : 0;
    const uint16_t dll_characteristics =
        has_range(buffer, optional_offset + 70U, 2) ? read_u16_le(buffer, optional_offset + 70U) : 0;
    const size_t data_directory_offset =
        optional_magic == 0x10B ? optional_offset + 96U : optional_magic == 0x20B ? optional_offset + 112U : 0U;
    const uint32_t certificate_table_size =
        data_directory_offset != 0U && has_range(buffer, data_directory_offset + 32U, 8)
            ? read_u32_le(buffer, data_directory_offset + 36U)
            : 0U;
    const size_t section_offset = optional_offset + optional_size;
    const uint16_t section_limit = sections < 64U ? sections : 64U;

    fputs("\"valid\":true,\"headers\":{", out);
    fprintf(out, "\"pe_offset\":%" PRIu32 ",", pe_offset);
    fputs("\"machine\":", out);
    print_machine_name(out, machine);
    fprintf(out, ",\"sections\":%u,\"timestamp\":%" PRIu32 ",\"optional_header_size\":%u,", sections,
            timestamp, optional_size);
    fputs("\"optional_header_magic\":", out);
    print_optional_name(out, optional_magic);
    fputs(",\"subsystem\":", out);
    print_subsystem_name(out, subsystem);
    fprintf(out, ",\"subsystem_value\":%u,", subsystem);
    fprintf(out, "\"characteristics\":\"0x%X\",\"dll_characteristics\":\"0x%X\",", characteristics,
            dll_characteristics);
    fprintf(out, "\"certificate_table_size\":%" PRIu32 ",", certificate_table_size);
    fprintf(out, "\"certificate_table_present\":%s", certificate_table_size > 0 ? "true" : "false");
    fputs("},\"sections\":[", out);

    bool first_section = true;
    for (uint16_t index = 0; index < section_limit; ++index) {
        const size_t offset = section_offset + ((size_t)index * 40U);
        if (!has_range(buffer, offset, 40U)) {
            break;
        }
        if (!first_section) {
            fputc(',', out);
        }
        first_section = false;
        char name[9];
        section_name(buffer, offset, name);
        fputc('{', out);
        fputs("\"name\":", out);
        print_json_string(out, name);
        fprintf(out, ",\"virtual_size\":%" PRIu32 ",\"virtual_address\":%" PRIu32 ",\"raw_size\":%" PRIu32 ",",
                read_u32_le(buffer, offset + 8U), read_u32_le(buffer, offset + 12U), read_u32_le(buffer, offset + 16U));
        fprintf(out, "\"raw_pointer\":%" PRIu32 ",\"characteristics\":\"0x%X\"}",
                read_u32_le(buffer, offset + 20U), read_u32_le(buffer, offset + 36U));
    }

    fprintf(out, "],\"section_list_truncated\":%s}", sections > section_limit ? "true" : "false");
}

static void probe_elf(FILE* out, const char* target, const ByteBuffer* buffer) {
    print_common_prefix(out, target, buffer);
    fputs("\"format\":\"ELF\",", out);

    const uint8_t elf_class = buffer->data[4];
    const uint8_t endian_flag = buffer->data[5];
    const bool little = endian_flag == 1;
    const bool valid_ident = (elf_class == 1 || elf_class == 2) && (endian_flag == 1 || endian_flag == 2);
    const size_t header_size = elf_class == 1 ? 52U : 64U;

    if (!valid_ident || !has_range(buffer, 0, header_size)) {
        fputs("\"valid\":false,\"error\":\"Invalid or truncated ELF header.\"}", out);
        return;
    }

    const uint16_t type = read_u16(buffer, 16U, little);
    const uint16_t machine = read_u16(buffer, 18U, little);
    const uint32_t version = read_u32(buffer, 20U, little);
    const uint64_t entry = elf_class == 1 ? read_u32(buffer, 24U, little) : read_u64(buffer, 24U, little);
    const uint64_t program_header_offset =
        elf_class == 1 ? read_u32(buffer, 28U, little) : read_u64(buffer, 32U, little);
    const uint64_t section_header_offset =
        elf_class == 1 ? read_u32(buffer, 32U, little) : read_u64(buffer, 40U, little);
    const uint16_t program_header_size = read_u16(buffer, elf_class == 1 ? 42U : 54U, little);
    const uint16_t program_header_count = read_u16(buffer, elf_class == 1 ? 44U : 56U, little);
    const uint16_t section_header_size = read_u16(buffer, elf_class == 1 ? 46U : 58U, little);
    const uint16_t section_header_count = read_u16(buffer, elf_class == 1 ? 48U : 60U, little);

    fputs("\"valid\":true,\"headers\":{", out);
    fprintf(out, "\"class\":\"%s\",", elf_class == 1 ? "ELF32" : "ELF64");
    fprintf(out, "\"endian\":\"%s\",", little ? "little" : "big");
    fputs("\"type\":", out);
    print_elf_type_name(out, type);
    fputs(",\"machine\":", out);
    print_elf_machine_name(out, machine);
    fprintf(out, ",\"version\":%" PRIu32 ",", version);
    fprintf(out, "\"entry\":%" PRIu64 ",\"program_header_offset\":%" PRIu64 ",\"program_header_size\":%u,",
            entry, program_header_offset, program_header_size);
    fprintf(out, "\"program_header_count\":%u,\"section_header_offset\":%" PRIu64 ",\"section_header_size\":%u,",
            program_header_count, section_header_offset, section_header_size);
    fprintf(out, "\"section_header_count\":%u}", section_header_count);
    fputc('}', out);
}

static void probe_unknown(FILE* out, const char* target, const ByteBuffer* buffer) {
    print_common_prefix(out, target, buffer);
    fputs("\"format\":\"unknown\",\"valid\":false}", out);
}

static ByteBuffer read_file(const char* path) {
    ByteBuffer buffer = {NULL, 0};
    FILE* input = fopen(path, "rb");
    if (!input) {
        return buffer;
    }

    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return buffer;
    }

    long size = ftell(input);
    if (size < 0) {
        fclose(input);
        return buffer;
    }

    if (fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return buffer;
    }

    buffer.size = (size_t)size;
    if (buffer.size > 0) {
        buffer.data = (uint8_t*)malloc(buffer.size);
        if (!buffer.data) {
            fclose(input);
            buffer.size = 0;
            return buffer;
        }

        if (fread(buffer.data, 1, buffer.size, input) != buffer.size) {
            free(buffer.data);
            buffer.data = NULL;
            buffer.size = 0;
            fclose(input);
            return buffer;
        }
    }

    fclose(input);
    return buffer;
}

static void free_buffer(ByteBuffer* buffer) {
    if (buffer->data) {
        free(buffer->data);
        buffer->data = NULL;
    }
    buffer->size = 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: native_probe <target>\n");
        return 2;
    }

    const char* target = argv[1];
    ByteBuffer buffer = read_file(target);
    if (buffer.data == NULL && buffer.size == 0) {
        print_common_prefix(stdout, target, &buffer);
        fputs("\"format\":\"unknown\",\"valid\":false,\"error\":\"File is empty or cannot be read.\"}", stdout);
        fputc('\n', stdout);
        return 1;
    }

    if (has_range(&buffer, 0, 0x40U) && buffer.data[0] == 'M' && buffer.data[1] == 'Z') {
        probe_pe(stdout, target, &buffer);
        fputc('\n', stdout);
        free_buffer(&buffer);
        return 0;
    }

    if (has_range(&buffer, 0, 20U) && buffer.data[0] == 0x7F && buffer.data[1] == 'E' &&
        buffer.data[2] == 'L' && buffer.data[3] == 'F') {
        probe_elf(stdout, target, &buffer);
        fputc('\n', stdout);
        free_buffer(&buffer);
        return 0;
    }

    probe_unknown(stdout, target, &buffer);
    fputc('\n', stdout);
    free_buffer(&buffer);
    return 0;
}
