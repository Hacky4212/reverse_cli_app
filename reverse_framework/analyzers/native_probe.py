from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, ToolStatus


class NativeProbeAnalyzer:
    name = "native_probe"

    def __init__(
        self,
        path: str | None = None,
        timeout: int = 30,
        extra_args: list[str] | None = None,
    ) -> None:
        self.path = path
        self.timeout = timeout
        self.extra_args = extra_args or []

    def run(self, context: AnalysisContext) -> None:
        executable = _resolve_probe(self.path)
        command = [
            str(executable or self.path or "native_probe"),
            *self.extra_args,
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
                        "Native probe executable not found. "
                        "Build native/native_probe or set native_probe_path."
                    ),
                )
            )
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": "Native probe executable not found.",
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
            context.add_error(self.name, error or "Native probe produced no JSON output.")
            return

        try:
            payload: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError as exc:
            context.add_error(self.name, f"Invalid native probe JSON: {exc}")
            return

        context.add_finding(self.name, payload)
        _add_native_issues(context, payload)


def _resolve_probe(configured_path: str | None) -> Path | None:
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

    for candidate in _default_probe_paths():
        if candidate.exists() and candidate.is_file():
            return candidate

    found = shutil.which("native_probe")
    return Path(found) if found else None


def _default_probe_paths() -> list[Path]:
    root = _project_root()
    build = root / "native" / "native_probe" / "build"
    return [
        build / "Release" / "native_probe.exe",
        build / "Debug" / "native_probe.exe",
        build / "RelWithDebInfo" / "native_probe.exe",
        build / "native_probe.exe",
        build / "native_probe",
    ]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_native_issues(context: AnalysisContext, payload: dict[str, Any]) -> None:
    if payload.get("format") == "unknown":
        return

    if payload.get("valid") is False:
        context.add_issue(
            Finding(
                id="native_probe_invalid_header",
                title="Native probe found an invalid executable header",
                severity="medium",
                category="format",
                summary="The native parser found a known file signature with an invalid header.",
                confidence=0.75,
                evidence={"format": payload.get("format"), "error": payload.get("error")},
                tags=["native", "format"],
                recommendation="Open the sample in a disassembler and verify the header manually.",
            )
        )
