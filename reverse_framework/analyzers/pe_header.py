from __future__ import annotations

import struct

from reverse_framework.core.context import AnalysisContext


MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

FILE_CHARACTERISTICS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
    0x8000: "BYTES_REVERSED_HI",
}

DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}


class PeHeaderAnalyzer:
    name = "pe_header"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        if len(data) < 0x40 or data[:2] != b"MZ":
            return

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            context.add_error(self.name, "MZ header found, but PE signature is invalid.")
            return

        machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, pe_offset + 4
        )
        optional_offset = pe_offset + 24
        optional = _parse_optional_header(data, optional_offset, optional_size, characteristics)

        context.add_finding(
            self.name,
            {
                "pe_offset": pe_offset,
                "machine": MACHINE_TYPES.get(machine, hex(machine)),
                "sections": sections,
                "timestamp": timestamp,
                "optional_header_size": optional_size,
                "optional_header_magic": _optional_header_name(optional.get("optional_header_magic")),
                "characteristics": hex(characteristics),
                "file_characteristics": optional.get("file_characteristics", []),
                "dll_characteristics": optional.get("dll_characteristics", []),
                "subsystem": optional.get("subsystem"),
                "entry_point_rva": optional.get("entry_point_rva"),
                "preferred_image_base": optional.get("preferred_image_base"),
                "addressing": {
                    "display_mode": optional.get("display_mode", "absolute"),
                    "aslr_enabled": optional.get("aslr_enabled", False),
                    "relocations_stripped": optional.get("relocations_stripped", False),
                    "nx_compatible": optional.get("nx_compatible", False),
                    "cfg_enabled": optional.get("cfg_enabled", False),
                },
            },
        )


def _optional_header_name(value: int | None) -> str | None:
    if value == 0x10B:
        return "PE32"
    if value == 0x20B:
        return "PE32+"
    if value is None:
        return None
    return hex(value)


def _parse_optional_header(
    data: bytes,
    optional_offset: int,
    optional_size: int,
    file_characteristics: int,
) -> dict[str, object]:
    if optional_offset + 2 > len(data):
        return {}

    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic not in {0x10B, 0x20B}:
        return {
            "optional_header_magic": optional_magic,
            "file_characteristics": _flag_names(file_characteristics, FILE_CHARACTERISTICS),
            "dll_characteristics": [],
            "subsystem": None,
            "entry_point_rva": None,
            "preferred_image_base": None,
            "relocations_stripped": bool(file_characteristics & 0x0001),
            "aslr_enabled": False,
            "nx_compatible": False,
            "cfg_enabled": False,
            "display_mode": "absolute",
        }

    is_pe32_plus = optional_magic == 0x20B
    entry_offset = optional_offset + 16
    image_base_offset = optional_offset + (24 if is_pe32_plus else 28)
    subsystem_offset = optional_offset + 68
    dll_characteristics_offset = optional_offset + 70

    entry_point_rva = _read_u32(data, entry_offset) if entry_offset + 4 <= len(data) else None
    if is_pe32_plus:
        preferred_image_base = _read_u64(data, image_base_offset) if image_base_offset + 8 <= len(data) else None
    else:
        preferred_image_base = _read_u32(data, image_base_offset) if image_base_offset + 4 <= len(data) else None

    subsystem_value = _read_u16(data, subsystem_offset) if subsystem_offset + 2 <= len(data) else None
    dll_characteristics = _read_u16(data, dll_characteristics_offset) if dll_characteristics_offset + 2 <= len(data) else 0

    relocations_stripped = bool(file_characteristics & 0x0001)
    aslr_enabled = bool(dll_characteristics & 0x0040) and not relocations_stripped
    nx_compatible = bool(dll_characteristics & 0x0100)
    cfg_enabled = bool(dll_characteristics & 0x4000)

    return {
        "optional_header_magic": optional_magic,
        "file_characteristics": _flag_names(file_characteristics, FILE_CHARACTERISTICS),
        "dll_characteristics": _flag_names(dll_characteristics, DLL_CHARACTERISTICS),
        "subsystem": _subsystem_name(subsystem_value),
        "entry_point_rva": _format_int(entry_point_rva),
        "preferred_image_base": _format_int(preferred_image_base),
        "relocations_stripped": relocations_stripped,
        "aslr_enabled": aslr_enabled,
        "nx_compatible": nx_compatible,
        "cfg_enabled": cfg_enabled,
        "display_mode": "rva" if aslr_enabled else "absolute",
        "optional_header_truncated": optional_size > 0 and optional_offset + optional_size > len(data),
    }


def _flag_names(value: int, mapping: dict[int, str]) -> list[str]:
    return [name for bit, name in mapping.items() if value & bit]


def _subsystem_name(value: int | None) -> str | None:
    if value is None:
        return None
    names = {
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
    }
    return names.get(value, str(value))


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _format_int(value: int | None) -> str | None:
    if value is None:
        return None
    return hex(value)
