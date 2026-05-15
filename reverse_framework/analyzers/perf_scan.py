from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, ToolStatus


class PerfScanAnalyzer:
    name = "perf_scan"

    def __init__(self, path: str | None = None, timeout: int = 30) -> None:
        self.path = path
        self.timeout = timeout

    def run(self, context: AnalysisContext) -> None:
        executable = _resolve_perf_scan(self.path)
        command = [
            str(executable or self.path or "perf_scan"),
            "--min-string",
            str(context.config.min_string),
            "--max-strings",
            str(context.config.max_strings),
            "--entropy-window",
            str(max(context.config.entropy_window, 256)),
            "--entropy-threshold",
            str(context.config.entropy_threshold),
            "--max-entropy-regions",
            str(context.config.max_entropy_regions),
            str(context.target),
        ]

        if executable is None:
            context.add_tool_status(
                ToolStatus(
                    name=self.name,
                    command=command,
                    available=False,
                    enabled=True,
                    error=(
                        "C++ perf scanner executable not found. "
                        "Build native/perf_scan or set perf_scan_path."
                    ),
                )
            )
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": "C++ perf scanner executable not found.",
                },
            )
            return

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=max(self.timeout, 1),
            )
        except Exception as exc:
            context.add_tool_status(
                ToolStatus(
                    name=self.name,
                    command=command,
                    available=True,
                    enabled=True,
                    error=str(exc),
                )
            )
            context.add_error(self.name, str(exc))
            return

        output = completed.stdout.strip()
        error = completed.stderr.strip()
        context.add_tool_status(
            ToolStatus(
                name=self.name,
                command=command,
                available=True,
                enabled=True,
                output=(output or error)[:8000],
                error=None if completed.returncode == 0 else f"Exit code {completed.returncode}",
            )
        )

        if not output:
            context.add_error(self.name, error or "C++ perf scanner produced no JSON output.")
            return

        try:
            payload: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError as exc:
            context.add_error(self.name, f"Invalid C++ perf scanner JSON: {exc}")
            return

        normalized = _normalize_perf_scan_payload(payload)
        context.add_finding(self.name, normalized)
        _add_perf_scan_issues(context, normalized)


def _resolve_perf_scan(configured_path: str | None) -> Path | None:
    if configured_path:
        configured = Path(configured_path)
        candidates = [configured]
        if not configured.is_absolute():
            candidates.append(_project_root() / configured)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        found = shutil.which(configured_path)
        return Path(found) if found else None

    for candidate in _default_perf_scan_paths():
        if candidate.exists() and candidate.is_file():
            return candidate

    found = shutil.which("perf_scan")
    return Path(found) if found else None


def _default_perf_scan_paths() -> list[Path]:
    root = _project_root()
    build = root / "native" / "perf_scan" / "build"
    return [
        build / "Release" / "perf_scan.exe",
        build / "Debug" / "perf_scan.exe",
        build / "RelWithDebInfo" / "perf_scan.exe",
        build / "perf_scan.exe",
        build / "perf_scan",
    ]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_perf_scan_issues(context: AnalysisContext, payload: dict[str, Any]) -> None:
    entropy = payload.get("entropy")
    if not isinstance(entropy, dict):
        return

    regions = entropy.get("regions")
    if not isinstance(regions, list) or not regions:
        return

    context.add_issue(
        Finding(
            id="perf_scan_high_entropy_regions",
            title="C++ perf scanner found high entropy regions",
            severity="medium",
            category="packing",
            summary="The native performance scanner found regions that may be packed, encrypted, or compressed.",
            confidence=0.7,
            evidence={"regions": regions[:5]},
            tags=["native", "performance", "packing"],
            recommendation="Review the reported offsets during static or dynamic unpacking triage.",
        )
    )


def _normalize_perf_scan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    strings = payload.get("strings")
    entropy = payload.get("entropy")
    items = strings.get("items") if isinstance(strings, dict) else []
    regions = entropy.get("regions") if isinstance(entropy, dict) else []

    ascii_count = 0
    utf16le_count = 0
    preview_items: list[str] = []

    if isinstance(items, list):
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "ascii")
            value = str(item.get("value") or "")
            offset = item.get("offset")
            if kind == "utf16le":
                utf16le_count += 1
            else:
                ascii_count += 1
            preview_items.append(
                f"0x{int(offset or 0):08X} {kind} {value[:120]}"
            )

        for item in items[10:]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "ascii")
            if kind == "utf16le":
                utf16le_count += 1
            else:
                ascii_count += 1
    total_strings = int(strings.get("count") if isinstance(strings, dict) and strings.get("count") is not None else len(items) if isinstance(items, list) else 0)
    entropy_region_count = int(entropy.get("region_count") if isinstance(entropy, dict) and entropy.get("region_count") is not None else len(regions) if isinstance(regions, list) else 0)
    size = int(payload.get("size") or 0)
    window = int(entropy.get("window") or 0) if isinstance(entropy, dict) else 0
    threshold = float(entropy.get("threshold") or 0.0) if isinstance(entropy, dict) else 0.0

    summary_lines = [
        f"Target size: {size} bytes",
        f"Strings: {total_strings} total ({ascii_count} ascii, {utf16le_count} utf16le)",
        f"Entropy regions: {entropy_region_count} at window {window} threshold {threshold:.2f}",
    ]

    normalized = dict(payload)
    normalized["summary_text"] = " | ".join(summary_lines[:3])
    normalized["preview_lines"] = preview_items[:5]
    normalized["metrics"] = {
        "size": size,
        "string_count": total_strings,
        "ascii_string_count": ascii_count,
        "utf16le_string_count": utf16le_count,
        "entropy_region_count": entropy_region_count,
    }
    return normalized
