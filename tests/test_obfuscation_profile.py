from pathlib import Path
import struct

from reverse_framework.analyzers.obfuscation_profile import ObfuscationProfileAnalyzer
from reverse_framework.analyzers.pe_header import PeHeaderAnalyzer
from reverse_framework.core.context import AnalysisContext


def test_obfuscation_profile_detects_runtime_resolution(tmp_path: Path) -> None:
    sample = tmp_path / "obfuscated.bin"
    sample.write_bytes(
        bytes(range(256)) * 16
        + b"LoadLibraryA\x00"
        + b"GetProcAddress\x00"
        + b"VirtualProtect\x00"
        + b"IsDebuggerPresent\x00"
        + b"RtlDecompressBuffer\x00"
    )
    context = AnalysisContext(target=sample)
    context.add_finding("file_profile", {"entropy": 7.9})
    context.add_finding("strings", {"count": 4})
    context.add_finding("entropy_regions", {"region_count": 3})

    ObfuscationProfileAnalyzer().run(context)

    finding = context.findings["obfuscation_profile"]
    assert finding["obfuscation_score"] >= 55
    assert finding["addressing"]["display_mode"] == "module+rva"
    assert "api_resolution" in finding["signals"]
    assert any(issue.id == "obfuscation_or_randomized_addressing" for issue in context.issues)


def test_pe_header_reports_aslr_ready_addressing(tmp_path: Path) -> None:
    sample = tmp_path / "aslr-ready.exe"
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1234)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<H", data, optional + 70, 0x0140)
    sample.write_bytes(bytes(data))

    context = AnalysisContext(target=sample)
    PeHeaderAnalyzer().run(context)

    finding = context.findings["pe_header"]
    assert finding["addressing"]["aslr_enabled"] is True
    assert finding["addressing"]["display_mode"] == "rva"
    assert finding["preferred_image_base"] == "0x140000000"
    assert finding["entry_point_rva"] == "0x1234"
    assert "DYNAMIC_BASE" in finding["dll_characteristics"]
