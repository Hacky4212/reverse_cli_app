"""Reverse engineering triage framework."""

from reverse_framework.api import (
    analyze_and_write_reports,
    analyze_code_text,
    analyze_code_text_and_write_reports,
    analyze_execution_evidence,
    analyze_execution_evidence_and_write_reports,
    analyze_process_memory,
    analyze_process_memory_and_write_reports,
    analyze_target,
    available_analyzers,
    open_live_kernel_monitor,
    stream_live_kernel_events,
)
from reverse_framework.core.addressing import format_address, module_address_model, normalize_offset
from reverse_framework.live import KernelLiveEvent, KernelLiveMonitor

__all__ = [
    "__version__",
    "analyze_and_write_reports",
    "analyze_code_text",
    "analyze_code_text_and_write_reports",
    "analyze_execution_evidence",
    "analyze_execution_evidence_and_write_reports",
    "analyze_process_memory",
    "analyze_process_memory_and_write_reports",
    "analyze_target",
    "available_analyzers",
    "KernelLiveEvent",
    "KernelLiveMonitor",
    "format_address",
    "open_live_kernel_monitor",
    "module_address_model",
    "normalize_offset",
    "stream_live_kernel_events",
]

__version__ = "0.1.0"
