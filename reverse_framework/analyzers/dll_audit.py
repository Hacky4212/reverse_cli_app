from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, ToolStatus


class DllAuditAnalyzer:
    name = "dll_audit"

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
        executable = _resolve_auditor(self.path)
        command = [
            str(executable or self.path or "dll_audit"),
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
                        "DLL audit executable not found. "
                        "Build native/dll_audit or set dll_audit_path."
                    ),
                )
            )
            context.add_finding(
                self.name,
                {
                    "enabled": True,
                    "available": False,
                    "message": "DLL audit executable not found.",
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
            context.add_error(self.name, error or "DLL audit produced no JSON output.")
            return

        try:
            payload: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError as exc:
            context.add_error(self.name, f"Invalid DLL audit JSON: {exc}")
            return

        context.add_finding(self.name, payload)
        _add_dll_audit_issues(context, payload)


def _resolve_auditor(configured_path: str | None) -> Path | None:
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

    for candidate in _default_auditor_paths():
        if candidate.exists() and candidate.is_file():
            return candidate

    found = shutil.which("dll_audit")
    return Path(found) if found else None


def _default_auditor_paths() -> list[Path]:
    root = _project_root()
    build = root / "native" / "dll_audit" / "build"
    return [
        build / "Release" / "dll_audit.exe",
        build / "Debug" / "dll_audit.exe",
        build / "RelWithDebInfo" / "dll_audit.exe",
        build / "dll_audit.exe",
        build / "dll_audit",
    ]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_dll_audit_issues(context: AnalysisContext, payload: dict[str, Any]) -> None:
    if payload.get("valid") is False and context.target.suffix.lower() == ".dll":
        context.add_issue(
            Finding(
                id="dll_audit_invalid_dll",
                title="DLL audit found an invalid DLL candidate",
                severity="medium",
                category="format",
                summary=str(payload.get("error") or "The file does not parse as a valid PE DLL."),
                confidence=0.75,
                evidence={"error": payload.get("error"), "format": payload.get("format")},
                tags=["dll", "pe", "format"],
                recommendation="Verify the sample source and inspect the PE header manually.",
            )
        )
        return

    if payload.get("valid") is not True:
        return

    if payload.get("is_dll") is False and context.target.suffix.lower() == ".dll":
        context.add_issue(
            Finding(
                id="dll_audit_not_marked_as_dll",
                title="DLL extension file is not marked as a DLL",
                severity="medium",
                category="format",
                summary="The PE header does not set the DLL characteristic flag.",
                confidence=0.8,
                evidence={"machine": payload.get("machine"), "section_count": payload.get("section_count")},
                tags=["dll", "pe", "format"],
                recommendation="Confirm whether the file was mislabeled or intentionally malformed.",
            )
        )

    wx_sections = payload.get("risk", {}).get("writable_executable_sections", [])
    if wx_sections:
        context.add_issue(
            Finding(
                id="dll_audit_writable_executable_sections",
                title="DLL contains writable executable sections",
                severity="high",
                category="memory",
                summary="One or more sections are both writable and executable.",
                confidence=0.85,
                evidence={"sections": wx_sections},
                tags=["dll", "pe", "memory"],
                recommendation="Review these sections in a disassembler and confirm whether the permissions are intentional.",
            )
        )

    suspicious_imports = _suspicious_imports(payload)
    if suspicious_imports:
        context.add_issue(
            Finding(
                id="dll_audit_sensitive_runtime_imports",
                title="DLL imports sensitive runtime APIs",
                severity="medium",
                category="capability",
                summary="The import table contains APIs commonly used by loaders or process-manipulation code.",
                confidence=0.7,
                evidence={"imports": suspicious_imports},
                tags=["dll", "imports", "capability"],
                recommendation="Correlate these imports with code paths before assigning malicious intent.",
            )
        )


def _suspicious_imports(payload: dict[str, Any]) -> list[dict[str, str]]:
    names = {
        "createremotethread",
        "getprocaddress",
        "loadlibrarya",
        "loadlibraryexw",
        "loadlibraryw",
        "ntcreatethreadex",
        "queueuserapc",
        "setwindowshookexa",
        "setwindowshookexw",
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "writeprocessmemory",
    }
    matches: list[dict[str, str]] = []
    imports = payload.get("imports", {})
    for dll in imports.get("dlls", []) if isinstance(imports, dict) else []:
        dll_name = str(dll.get("name") or "")
        for function in dll.get("functions", []):
            function_name = str(function)
            if function_name.lower() in names:
                matches.append({"dll": dll_name, "function": function_name})
    return matches
