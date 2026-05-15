from __future__ import annotations

from reverse_framework.analyzers.elf_header import ElfHeaderAnalyzer
from reverse_framework.analyzers.entropy import EntropyAnalyzer
from reverse_framework.analyzers.external_tools import ExternalToolAnalyzer
from reverse_framework.analyzers.code_structure import CodeStructureAnalyzer
from reverse_framework.analyzers.dll_audit import DllAuditAnalyzer
from reverse_framework.analyzers.execution_trace import ExecutionTraceAnalyzer
from reverse_framework.analyzers.file_profile import FileProfileAnalyzer
from reverse_framework.analyzers.indicators import IndicatorAnalyzer
from reverse_framework.analyzers.kernel_security import KernelSecurityAnalyzer
from reverse_framework.analyzers.obfuscation_profile import ObfuscationProfileAnalyzer
from reverse_framework.analyzers.native_probe import NativeProbeAnalyzer
from reverse_framework.analyzers.perf_scan import PerfScanAnalyzer
from reverse_framework.analyzers.process_memory import ProcessMemoryAnalyzer
from reverse_framework.analyzers.pe_header import PeHeaderAnalyzer
from reverse_framework.analyzers.strings import StringsAnalyzer
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.pipeline import Analyzer


DEFAULT_ANALYZERS = [
    "file_profile",
    "strings",
    "indicators",
    "kernel_security",
    "entropy_regions",
    "perf_scan",
    "native_probe",
    "pe_header",
    "obfuscation_profile",
    "code_structure",
    "elf_header",
    "external_tools",
]


def build_analyzers(config: TriageConfig, names: list[str] | None = None) -> list[Analyzer]:
    selected = names or config.enabled_analyzers or DEFAULT_ANALYZERS
    registry = {
        "file_profile": lambda: FileProfileAnalyzer(),
        "strings": lambda: StringsAnalyzer(min_length=config.min_string, limit=config.max_strings),
        "indicators": lambda: IndicatorAnalyzer(),
        "kernel_security": lambda: KernelSecurityAnalyzer(),
        "entropy_regions": lambda: EntropyAnalyzer(),
        "native_probe": lambda: NativeProbeAnalyzer(
            path=config.native_probe_path,
            timeout=config.native_probe_timeout,
        ),
        "dll_audit": lambda: DllAuditAnalyzer(
            path=config.dll_audit_path,
            timeout=config.dll_audit_timeout,
        ),
        "perf_scan": lambda: PerfScanAnalyzer(
            path=config.perf_scan_path,
            timeout=config.perf_scan_timeout,
        ),
        "process_memory": lambda: ProcessMemoryAnalyzer(
            path=config.process_memory_path,
            timeout=config.process_memory_timeout,
            extra_args=config.process_memory_extra_args,
        ),
        "pe_header": lambda: PeHeaderAnalyzer(),
        "obfuscation_profile": lambda: ObfuscationProfileAnalyzer(),
        "code_structure": lambda: CodeStructureAnalyzer(),
        "execution_trace": lambda: ExecutionTraceAnalyzer(),
        "elf_header": lambda: ElfHeaderAnalyzer(),
        "external_tools": lambda: ExternalToolAnalyzer(),
    }

    analyzers: list[Analyzer] = []
    for name in selected:
        if name not in registry:
            raise ValueError(f"Unknown analyzer: {name}")
        if name == "native_probe" and not config.native_probe_enabled:
            continue
        if name == "dll_audit" and not config.dll_audit_enabled:
            continue
        if name == "perf_scan" and not config.perf_scan_enabled:
            continue
        if name == "process_memory" and not config.process_memory_enabled:
            continue
        analyzers.append(registry[name]())
    return analyzers
