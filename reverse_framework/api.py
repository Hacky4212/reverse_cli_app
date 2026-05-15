from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterable, Iterator

from reverse_framework.analyzers.registry import DEFAULT_ANALYZERS, build_analyzers
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.pipeline import AnalysisPipeline, AnalysisResult
from reverse_framework.live import KernelLiveEvent, KernelLiveMonitor, stream_kernel_events
from reverse_framework.reporting import ReportFormat, write_reports


def available_analyzers() -> list[str]:
    return _dedupe_names([*DEFAULT_ANALYZERS, "dll_audit", "execution_trace", "process_memory", "perf_scan"])


def build_pipeline(
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> AnalysisPipeline:
    resolved_config = config or TriageConfig()
    selected = list(analyzers) if analyzers is not None else None
    return AnalysisPipeline(analyzers=build_analyzers(resolved_config, selected))


def analyze_target(
    target: Path | str,
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> AnalysisResult:
    resolved_config = config or TriageConfig()
    pipeline = build_pipeline(resolved_config, analyzers)
    context = AnalysisContext(target=Path(target), config=resolved_config)
    return pipeline.run(context)


def analyze_code_text(
    code: str,
    target_name: str = "analysis-input.txt",
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> AnalysisResult:
    resolved_config = config or TriageConfig()
    selected = list(analyzers) if analyzers is not None else (resolved_config.enabled_analyzers or ["code_structure"])
    pipeline = build_pipeline(resolved_config, selected)
    context = AnalysisContext(target=Path(target_name), config=resolved_config, data=code.encode("utf-8"))
    return pipeline.run(context)


def analyze_and_write_reports(
    target: Path | str,
    out_dir: Path | str,
    report_format: ReportFormat,
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> tuple[AnalysisResult, list[Path]]:
    result = analyze_target(target=target, config=config, analyzers=analyzers)
    written = write_reports(result, Path(out_dir), report_format)
    return result, written


def analyze_code_text_and_write_reports(
    code: str,
    out_dir: Path | str,
    report_format: ReportFormat,
    target_name: str = "analysis-input.txt",
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> tuple[AnalysisResult, list[Path]]:
    result = analyze_code_text(code=code, target_name=target_name, config=config, analyzers=analyzers)
    written = write_reports(result, Path(out_dir), report_format)
    return result, written


def analyze_execution_evidence(
    evidence: str | dict[str, Any] | list[Any],
    static_code: str | None = None,
    static_report: dict[str, Any] | None = None,
    target_name: str = "execution-evidence",
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> AnalysisResult:
    resolved_config = config or TriageConfig()
    payload: str | dict[str, Any] | list[Any]
    if isinstance(evidence, (dict, list)):
        payload = evidence
    else:
        payload = evidence

    if static_code is not None or static_report is not None:
        if isinstance(payload, dict):
            bundle: dict[str, Any] = dict(payload)
        elif isinstance(payload, list):
            bundle = {"events": payload}
        else:
            parsed_payload = _try_parse_json_payload(payload)
            if isinstance(parsed_payload, dict):
                bundle = dict(parsed_payload)
            elif isinstance(parsed_payload, list):
                bundle = {"events": parsed_payload}
            else:
                bundle = {"raw_text": payload}
        if static_code is not None:
            bundle["static_code"] = static_code
        if static_report is not None:
            bundle["static_report"] = static_report
        payload = bundle

    if isinstance(payload, (dict, list)):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    else:
        data = payload.encode("utf-8")

    if analyzers is None:
        selected = ["execution_trace", *resolved_config.enabled_analyzers]
    else:
        selected = list(analyzers)
        if "execution_trace" not in selected:
            selected.insert(0, "execution_trace")

    pipeline = build_pipeline(resolved_config, _dedupe_names(selected))
    context = AnalysisContext(target=Path(target_name), config=resolved_config, data=data)
    return pipeline.run(context)


def analyze_execution_evidence_and_write_reports(
    evidence: str | dict[str, Any] | list[Any],
    out_dir: Path | str,
    report_format: ReportFormat,
    static_code: str | None = None,
    static_report: dict[str, Any] | None = None,
    target_name: str = "execution-evidence",
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> tuple[AnalysisResult, list[Path]]:
    result = analyze_execution_evidence(
        evidence=evidence,
        static_code=static_code,
        static_report=static_report,
        target_name=target_name,
        config=config,
        analyzers=analyzers,
    )
    written = write_reports(result, Path(out_dir), report_format)
    return result, written


def analyze_process_memory(
    pid: int | str,
    address: int | str,
    size: int = 64,
    target_name: str | None = None,
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> AnalysisResult:
    resolved_config = _clone_config(config or TriageConfig())
    pid_value = int(pid)
    address_text = _memory_address_text(address)
    resolved_config.process_memory_pid = pid_value
    resolved_config.process_memory_address = address_text
    resolved_config.process_memory_size = int(size)

    selected = list(analyzers) if analyzers is not None else ["process_memory"]
    if "process_memory" not in selected:
        selected.insert(0, "process_memory")

    pipeline = build_pipeline(resolved_config, _dedupe_names(selected))
    context = AnalysisContext(
        target=Path(target_name or _memory_target_name(pid_value, address_text)),
        config=resolved_config,
    )
    return pipeline.run(context)


def analyze_process_memory_and_write_reports(
    pid: int | str,
    address: int | str,
    size: int = 64,
    out_dir: Path | str = Path("reports"),
    report_format: ReportFormat = "all",
    target_name: str | None = None,
    config: TriageConfig | None = None,
    analyzers: Iterable[str] | None = None,
) -> tuple[AnalysisResult, list[Path]]:
    result = analyze_process_memory(
        pid=pid,
        address=address,
        size=size,
        target_name=target_name,
        config=config,
        analyzers=analyzers,
    )
    written = write_reports(result, Path(out_dir), report_format)
    return result, written


def open_live_kernel_monitor(
    process_id: int | None = None,
    duration_seconds: int | None = None,
    include_processes: bool = True,
    include_threads: bool = True,
    include_images: bool = True,
    powershell_path: str | None = None,
    stop_event: threading.Event | None = None,
) -> list[KernelLiveEvent]:
    monitor = KernelLiveMonitor(
        process_id=process_id,
        include_processes=include_processes,
        include_threads=include_threads,
        include_images=include_images,
        powershell_path=powershell_path,
    )
    return list(monitor.iter_events(duration_seconds=duration_seconds, stop_event=stop_event))


def stream_live_kernel_events(
    process_id: int | None = None,
    duration_seconds: int | None = None,
    include_processes: bool = True,
    include_threads: bool = True,
    include_images: bool = True,
    powershell_path: str | None = None,
    stop_event: threading.Event | None = None,
) -> Iterator[KernelLiveEvent]:
    yield from stream_kernel_events(
        process_id=process_id,
        duration_seconds=duration_seconds,
        include_processes=include_processes,
        include_threads=include_threads,
        include_images=include_images,
        powershell_path=powershell_path,
        stop_event=stop_event,
    )


def _dedupe_names(values: list[str]) -> list[str]:
    seen = set()
    deduped: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _try_parse_json_payload(value: str) -> Any:
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _clone_config(config: TriageConfig) -> TriageConfig:
    return TriageConfig.from_mapping(config.to_dict())


def _memory_address_text(address: int | str) -> str:
    if isinstance(address, int):
        return f"0x{address:X}"
    text = str(address).strip()
    return text.replace(" ", "_")


def _memory_target_name(pid: int, address_text: str) -> str:
    clean_address = address_text.replace(":", "_")
    return f"process-memory-p{pid}-{clean_address}"
