from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, ToolStatus


class ProcessMemoryAnalyzer:
    name = "process_memory"

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
        pid = getattr(context.config, "process_memory_pid", None)
        address = getattr(context.config, "process_memory_address", None)
        size = getattr(context.config, "process_memory_size", 64)

        if pid is None or address in {None, ""}:
            message = "Process memory PID and address are required."
            context.add_error(self.name, message)
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": message,
                },
            )
            return

        try:
            pid_value = int(pid)
            size_value = int(size)
        except (TypeError, ValueError) as exc:
            context.add_error(self.name, f"Invalid process memory parameters: {exc}")
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": "Invalid process memory parameters.",
                },
            )
            return

        if pid_value <= 0 or size_value <= 0:
            message = "Process memory PID and size must be greater than zero."
            context.add_error(self.name, message)
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": message,
                },
            )
            return

        executable = _resolve_reader(self.path)
        command = [
            str(executable or self.path or "process_memory_reader"),
            *self.extra_args,
            "--pid",
            str(pid_value),
            "--address",
            str(address),
            "--size",
            str(size_value),
        ]

        if executable is None:
            context.add_tool_status(
                ToolStatus(
                    name=self.name,
                    command=command,
                    available=False,
                    enabled=True,
                    error=(
                        "Process memory reader executable not found. "
                        "Build native/process_memory_reader or set process_memory_path."
                    ),
                )
            )
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": "Process memory reader executable not found.",
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
            context.add_error(self.name, error or "Process memory reader produced no JSON output.")
            return

        try:
            payload: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError as exc:
            context.add_error(self.name, f"Invalid process memory JSON: {exc}")
            return

        context.add_finding(self.name, payload)
        _add_process_memory_issues(context, payload)


def _resolve_reader(configured_path: str | None) -> Path | None:
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

    for candidate in _default_reader_paths():
        if candidate.exists() and candidate.is_file():
            return candidate

    found = shutil.which("process_memory_reader")
    return Path(found) if found else None


def _default_reader_paths() -> list[Path]:
    root = _project_root()
    build = root / "native" / "process_memory_reader" / "build"
    return [
        build / "Release" / "process_memory_reader.exe",
        build / "Debug" / "process_memory_reader.exe",
        build / "RelWithDebInfo" / "process_memory_reader.exe",
        build / "process_memory_reader.exe",
        build / "process_memory_reader",
    ]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_process_memory_issues(context: AnalysisContext, payload: dict[str, Any]) -> None:
    if payload.get("success") is False:
        error_text = str(payload.get("error") or "Process memory read failed.")
        context.add_issue(
            Finding(
                id="process_memory_read_failed",
                title="Live process memory read failed",
                severity="medium",
                category="memory",
                summary=error_text,
                confidence=0.8,
                evidence={
                    "pid": payload.get("pid"),
                    "address": payload.get("address"),
                    "requested_size": payload.get("requested_size"),
                    "read_size": payload.get("read_size"),
                    "error": payload.get("error"),
                },
                tags=["memory", "live", "windows"],
                recommendation="Verify the PID, address, and current access rights for the target process.",
            )
        )
        return

    if payload.get("partial") is True:
        context.add_issue(
            Finding(
                id="process_memory_partial_read",
                title="Live process memory read was partial",
                severity="low",
                category="memory",
                summary="Only part of the requested memory range was read.",
                confidence=0.7,
                evidence={
                    "pid": payload.get("pid"),
                    "address": payload.get("address"),
                    "requested_size": payload.get("requested_size"),
                    "read_size": payload.get("read_size"),
                },
                tags=["memory", "live", "partial"],
                recommendation="Re-read the adjacent range or reduce the request size.",
            )
        )
