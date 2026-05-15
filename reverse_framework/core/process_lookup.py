from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ProcessCandidate:
    pid: int
    process_name: str = ""
    window_title: str = ""

    def label(self) -> str:
        parts = [f"PID {self.pid}"]
        if self.process_name:
            parts.append(self.process_name)
        if self.window_title:
            parts.append(self.window_title)
        return " | ".join(parts)


def resolve_process_candidate(
    pid: int | str | None = None,
    process_name: str | None = None,
    window_title: str | None = None,
    powershell_path: str | None = None,
) -> ProcessCandidate | None:
    selected_pid = _normalize_optional_pid(pid)
    selected_process_name = _normalize_text(process_name)
    selected_window_title = _normalize_text(window_title)

    if selected_pid is None and selected_process_name is None and selected_window_title is None:
        return None

    candidates = list_process_candidates(
        pid=selected_pid,
        process_name=selected_process_name,
        window_title=selected_window_title,
        powershell_path=powershell_path,
    )
    selector = _describe_selector(
        pid=selected_pid,
        process_name=selected_process_name,
        window_title=selected_window_title,
    )
    if not candidates:
        raise LookupError(f"No running process matched {selector}.")
    if len(candidates) > 1:
        sample = ", ".join(candidate.label() for candidate in candidates[:5])
        raise LookupError(f"Multiple running processes matched {selector}: {sample}")
    return candidates[0]


def list_process_candidates(
    pid: int | None = None,
    process_name: str | None = None,
    window_title: str | None = None,
    powershell_path: str | None = None,
) -> list[ProcessCandidate]:
    selected_pid = _normalize_optional_pid(pid)
    selected_process_name = _normalize_text(process_name)
    selected_window_title = _normalize_text(window_title)

    if selected_pid is None and selected_process_name is None and selected_window_title is None:
        return []

    executable = _resolve_powershell(powershell_path)
    if executable is None:
        raise FileNotFoundError("PowerShell was not found. Install Windows PowerShell or PowerShell 7.")

    script = _build_lookup_script(
        pid=selected_pid,
        process_name=selected_process_name,
        window_title=selected_window_title,
    )
    candidates: list[ProcessCandidate] = []
    payload = _run_powershell_json(executable, script)
    for item in _candidate_payload_items(payload):
        if not isinstance(item, dict):
            continue
        candidate = _candidate_from_mapping(item)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _candidate_payload_items(payload: Any) -> list[Any]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise RuntimeError(f"Process lookup returned unexpected {type(payload).__name__} payload.")


def _candidate_from_mapping(mapping: dict[str, Any]) -> ProcessCandidate | None:
    try:
        pid = int(mapping["pid"])
    except (KeyError, TypeError, ValueError):
        return None
    process_name = str(mapping.get("process_name") or "")
    window_title = str(mapping.get("window_title") or "")
    return ProcessCandidate(pid=pid, process_name=process_name, window_title=window_title)


def _run_powershell_json(executable: str, script: str) -> Any:
    completed = subprocess.run(
        [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"Process lookup exited with code {completed.returncode}."
        raise RuntimeError(message)

    output = completed.stdout.strip()
    if not output:
        return []

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid process lookup JSON: {exc}") from exc


def _build_lookup_script(
    *,
    pid: int | None,
    process_name: str | None,
    window_title: str | None,
) -> str:
    pid_literal = str(pid) if pid is not None else "$null"
    process_name_literal = _ps_single_quote(process_name) if process_name is not None else "$null"
    window_title_literal = _ps_single_quote(window_title) if window_title is not None else "$null"

    script = f"""
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    $requestedPid = {pid_literal}
    $requestedProcessName = {process_name_literal}
    $requestedWindowTitle = {window_title_literal}

    $candidateProcesses = @()
    if ($null -ne $requestedPid) {{
        $candidate = Get-Process -Id $requestedPid -ErrorAction SilentlyContinue
        if ($null -ne $candidate) {{
            $candidateProcesses = @($candidate)
        }}
    }}
    else {{
        $candidateProcesses = Get-Process -ErrorAction SilentlyContinue
    }}

    $resolvedCandidates = foreach ($process in $candidateProcesses) {{
        $matchesProcessName = $true
        if ($null -ne $requestedProcessName) {{
            $baseName = [IO.Path]::GetFileNameWithoutExtension($requestedProcessName)
            $matchesProcessName = $process.ProcessName -ieq $requestedProcessName -or $process.ProcessName -ieq $baseName
        }}

        $matchesWindowTitle = $true
        if ($null -ne $requestedWindowTitle) {{
            $windowPattern = [regex]::Escape($requestedWindowTitle)
            $matchesWindowTitle = -not [string]::IsNullOrWhiteSpace($process.MainWindowTitle) -and $process.MainWindowTitle -match $windowPattern
        }}

        if ($matchesProcessName -and $matchesWindowTitle) {{
            [ordered]@{{
                pid = [int]$process.Id
                process_name = [string]$process.ProcessName
                window_title = [string]$process.MainWindowTitle
            }}
        }}
    }}

    ConvertTo-Json -InputObject @($resolvedCandidates) -Compress -Depth 4
    """
    return textwrap.dedent(script).strip()


def _resolve_powershell(configured_path: str | None) -> str | None:
    if configured_path:
        configured = Path(configured_path)
        if configured.exists() and configured.is_file():
            return str(configured)
        found = shutil.which(configured_path)
        if found:
            return found
        return None

    for candidate in ("pwsh", "powershell"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _normalize_optional_pid(value: int | str | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("PID must be greater than zero.")
        return value
    text = str(value).strip()
    if not text:
        return None
    parsed = int(text, 0)
    if parsed <= 0:
        raise ValueError("PID must be greater than zero.")
    return parsed


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _describe_selector(
    *,
    pid: int | None,
    process_name: str | None,
    window_title: str | None,
) -> str:
    parts: list[str] = []
    if pid is not None:
        parts.append(f"PID {pid}")
    if process_name is not None:
        parts.append(f'process name "{process_name}"')
    if window_title is not None:
        parts.append(f'window title "{window_title}"')
    return " and ".join(parts) if parts else "the requested target"


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
