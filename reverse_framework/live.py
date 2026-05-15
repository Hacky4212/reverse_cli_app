from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from reverse_framework.core.addressing import module_address_model, parse_int_value


@dataclass(slots=True)
class KernelLiveEvent:
    kind: str
    timestamp: str
    source: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class KernelLiveMonitor:
    process_id: int | None = None
    include_processes: bool = True
    include_threads: bool = True
    include_images: bool = True
    powershell_path: str | None = None

    def supported(self) -> bool:
        return sys.platform == "win32"

    def iter_events(
        self,
        duration_seconds: int | None = None,
        stop_event: threading.Event | None = None,
    ) -> Iterator[KernelLiveEvent]:
        executable = _resolve_powershell(self.powershell_path)
        if executable is None:
            raise FileNotFoundError("PowerShell was not found. Install Windows PowerShell or PowerShell 7.")

        if not self.supported():
            raise RuntimeError("Live kernel monitoring is only supported on Windows.")

        script = _build_powershell_script(
            process_id=self.process_id,
            include_processes=self.include_processes,
            include_threads=self.include_threads,
            include_images=self.include_images,
            duration_seconds=duration_seconds,
        )
        command = [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]

        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )

        try:
            assert process.stdout is not None
            for line in process.stdout:
                if stop_event is not None and stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield _event_from_payload(payload)
        finally:
            stopped_intentionally = stop_event is not None and stop_event.is_set()
            if process.poll() is None:
                stopped_intentionally = True
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            stderr = ""
            if process.stderr is not None:
                stderr = process.stderr.read().strip()

            if not stopped_intentionally and process.returncode not in {0, None}:
                message = stderr or f"Live monitor exited with code {process.returncode}."
                if "access denied" in message.lower():
                    message += " Run PowerShell as Administrator."
                raise RuntimeError(message)


def stream_kernel_events(
    process_id: int | None = None,
    duration_seconds: int | None = None,
    include_processes: bool = True,
    include_threads: bool = True,
    include_images: bool = True,
    powershell_path: str | None = None,
    stop_event: threading.Event | None = None,
) -> Iterator[KernelLiveEvent]:
    monitor = KernelLiveMonitor(
        process_id=process_id,
        include_processes=include_processes,
        include_threads=include_threads,
        include_images=include_images,
        powershell_path=powershell_path,
    )
    yield from monitor.iter_events(duration_seconds=duration_seconds, stop_event=stop_event)


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


def _build_powershell_script(
    *,
    process_id: int | None,
    include_processes: bool,
    include_threads: bool,
    include_images: bool,
    duration_seconds: int | None,
) -> str:
    query_process_filter = f" WHERE ProcessID = {int(process_id)}" if process_id is not None else ""
    process_queries = []
    if include_processes:
        process_queries.extend(
            [
                ("reverse-tools.process.start", "Win32_ProcessStartTrace"),
                ("reverse-tools.process.stop", "Win32_ProcessStopTrace"),
            ]
        )
    thread_queries = []
    if include_threads:
        thread_queries.extend(
            [
                ("reverse-tools.thread.start", "Win32_ThreadStartTrace"),
                ("reverse-tools.thread.stop", "Win32_ThreadStopTrace"),
            ]
        )
    image_queries = []
    if include_images:
        image_queries.append(("reverse-tools.module.load", "Win32_ModuleLoadTrace"))

    register_blocks = []
    for source_identifier, class_name in [*process_queries, *thread_queries, *image_queries]:
        where = query_process_filter if "Process" in class_name or "Thread" in class_name or "Module" in class_name else ""
        query = f"SELECT * FROM {class_name}{where}"
        register_blocks.append(
            textwrap.dedent(
                f"""
                $null = $subscriptions.Add(
                    (Register-WmiEvent -Namespace "root\\CIMV2" -Query "{query}" -SourceIdentifier "{source_identifier}")
                )
                """
            ).strip()
        )

    if not register_blocks:
        register_blocks.append('throw "No live kernel event classes enabled."')

    process_filter_literal = "$null"
    if process_id is not None:
        process_filter_literal = str(int(process_id))

    include_processes_literal = "$true" if include_processes else "$false"
    include_threads_literal = "$true" if include_threads else "$false"
    include_images_literal = "$true" if include_images else "$false"
    duration_literal = 0 if duration_seconds in {None, 0} else int(duration_seconds)

    script = f"""
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    function Convert-ToIsoTime {{
        param([object]$Value)
        try {{
            return [DateTimeOffset]::FromFileTimeUtc([int64]$Value).ToString("o")
        }}
        catch {{
            return [DateTimeOffset]::UtcNow.ToString("o")
        }}
    }}

    function Convert-ToSid {{
        param([object]$Value)
        if ($null -eq $Value) {{
            return $null
        }}
        try {{
            return [Convert]::ToBase64String([byte[]]$Value)
        }}
        catch {{
            return $null
        }}
    }}

    function Write-LiveEvent {{
        param(
            [string]$Kind,
            [string]$Summary,
            [object]$Record,
            [string]$ClassName
        )

        $payload = [ordered]@{{
            kind = $Kind
            class_name = $ClassName
            timestamp = if ($Record.PSObject.Properties.Name -contains "TIME_CREATED") {{ Convert-ToIsoTime $Record.TIME_CREATED }} else {{ [DateTimeOffset]::UtcNow.ToString("o") }}
            source = "krnlprov"
            summary = $Summary
            data = [ordered]@{{}}
            raw = [ordered]@{{}}
        }}

        switch ($Kind) {{
            "process_start" {{
                $payload.data = [ordered]@{{
                    process_id = [int]$Record.ProcessID
                    parent_process_id = [int]$Record.ParentProcessID
                    process_name = $Record.ProcessName
                    session_id = [int]$Record.SessionID
                    sid = Convert-ToSid $Record.Sid
                }}
            }}
            "process_stop" {{
                $payload.data = [ordered]@{{
                    process_id = [int]$Record.ProcessID
                    parent_process_id = [int]$Record.ParentProcessID
                    process_name = $Record.ProcessName
                    session_id = [int]$Record.SessionID
                    exit_status = [int64]$Record.ExitStatus
                    sid = Convert-ToSid $Record.Sid
                }}
            }}
            "thread_start" {{
                $payload.data = [ordered]@{{
                    process_id = [int]$Record.ProcessID
                    thread_id = [int]$Record.ThreadID
                    start_addr = ("0x{{0:X}}" -f [uint64]$Record.StartAddr)
                    win32_start_addr = ("0x{{0:X}}" -f [uint64]$Record.Win32StartAddr)
                    stack_base = ("0x{{0:X}}" -f [uint64]$Record.StackBase)
                    stack_limit = ("0x{{0:X}}" -f [uint64]$Record.StackLimit)
                    user_stack_base = ("0x{{0:X}}" -f [uint64]$Record.UserStackBase)
                    user_stack_limit = ("0x{{0:X}}" -f [uint64]$Record.UserStackLimit)
                    wait_mode = [int]$Record.WaitMode
                }}
            }}
            "thread_stop" {{
                $payload.data = [ordered]@{{
                    process_id = [int]$Record.ProcessID
                    thread_id = [int]$Record.ThreadID
                }}
            }}
            "module_load" {{
                $fileName = [string]$Record.FileName
                $payload.data = [ordered]@{{
                    process_id = [int]$Record.ProcessID
                    file_name = $fileName
                    module_kind = if ($fileName -match "\\.sys$") {{ "driver" }} else {{ "image" }}
                    default_base = ("0x{{0:X}}" -f [uint64]$Record.DefaultBase)
                    image_base = ("0x{{0:X}}" -f [uint64]$Record.ImageBase)
                    image_checksum = [uint32]$Record.ImageChecksum
                    image_size = [uint64]$Record.ImageSize
                    timestamp = [uint32]$Record.TimeDateStamp
                }}
            }}
        }}

        $payload.raw = [ordered]@{{
            process_id = if ($Record.PSObject.Properties.Name -contains "ProcessID") {{ [int]$Record.ProcessID }} else {{ $null }}
            thread_id = if ($Record.PSObject.Properties.Name -contains "ThreadID") {{ [int]$Record.ThreadID }} else {{ $null }}
            file_name = if ($Record.PSObject.Properties.Name -contains "FileName") {{ [string]$Record.FileName }} else {{ $null }}
        }}

        [Console]::Out.WriteLine(($payload | ConvertTo-Json -Compress -Depth 8))
    }}

    $subscriptions = New-Object System.Collections.Generic.List[object]
    try {{
        {os.linesep.join(register_blocks)}
        [Console]::Out.WriteLine((@{{
            kind = "monitor_status"
            class_name = "kernel_live"
            timestamp = [DateTimeOffset]::UtcNow.ToString("o")
            source = "krnlprov"
            summary = "Live kernel monitor ready"
            data = [ordered]@{{
                process_id = {process_filter_literal}
                include_processes = {include_processes_literal}
                include_threads = {include_threads_literal}
                include_images = {include_images_literal}
            }}
            raw = [ordered]@{{}}
        }} | ConvertTo-Json -Compress -Depth 6))

        $stopAt = if ({duration_literal} -gt 0) {{ (Get-Date).AddSeconds({duration_literal}) }} else {{ $null }}
        while ($true) {{
            if ($null -ne $stopAt -and (Get-Date) -ge $stopAt) {{
                break
            }}

            $event = Wait-Event -Timeout 1
            if ($null -eq $event) {{
                continue
            }}

            try {{
                $record = $event.SourceEventArgs.NewEvent
                switch ($event.SourceIdentifier) {{
                    "reverse-tools.process.start" {{
                        $summary = if ($record.ProcessName) {{ "Process started: $($record.ProcessName) ($($record.ProcessID))" }} else {{ "Process started: $($record.ProcessID)" }}
                        Write-LiveEvent -Kind "process_start" -Summary $summary -Record $record -ClassName "Win32_ProcessStartTrace"
                    }}
                    "reverse-tools.process.stop" {{
                        $summary = if ($record.ProcessName) {{ "Process stopped: $($record.ProcessName) ($($record.ProcessID))" }} else {{ "Process stopped: $($record.ProcessID)" }}
                        Write-LiveEvent -Kind "process_stop" -Summary $summary -Record $record -ClassName "Win32_ProcessStopTrace"
                    }}
                    "reverse-tools.thread.start" {{
                        $summary = "Thread started: $($record.ThreadID) in $($record.ProcessID)"
                        Write-LiveEvent -Kind "thread_start" -Summary $summary -Record $record -ClassName "Win32_ThreadStartTrace"
                    }}
                    "reverse-tools.thread.stop" {{
                        $summary = "Thread stopped: $($record.ThreadID) in $($record.ProcessID)"
                        Write-LiveEvent -Kind "thread_stop" -Summary $summary -Record $record -ClassName "Win32_ThreadStopTrace"
                    }}
                    "reverse-tools.module.load" {{
                        $summary = if ($record.FileName) {{ "Module loaded: $($record.FileName) in $($record.ProcessID)" }} else {{ "Module loaded in $($record.ProcessID)" }}
                        Write-LiveEvent -Kind "module_load" -Summary $summary -Record $record -ClassName "Win32_ModuleLoadTrace"
                    }}
                }}
            }}
            finally {{
                Remove-Event -EventIdentifier $event.EventIdentifier -ErrorAction SilentlyContinue | Out-Null
            }}
        }}
    }}
    finally {{
        foreach ($subscription in $subscriptions) {{
            try {{
                Unregister-Event -SubscriptionId $subscription.Id -Force -ErrorAction SilentlyContinue | Out-Null
            }}
            catch {{
            }}
        }}
    }}
    """

    return textwrap.dedent(script).strip()


def _event_from_payload(payload: dict[str, Any]) -> KernelLiveEvent:
    kind = str(payload.get("kind", "unknown"))
    timestamp = str(payload.get("timestamp", ""))
    source = str(payload.get("source", "krnlprov"))
    summary = str(payload.get("summary", ""))
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}

    if kind == "module_load":
        preferred_base = parse_int_value(data.get("default_base"))
        loaded_base = parse_int_value(data.get("image_base"))
        image_size = parse_int_value(data.get("image_size"))
        module_name = data.get("file_name") if isinstance(data.get("file_name"), str) else None
        data["addressing"] = module_address_model(
            preferred_base=preferred_base,
            loaded_base=loaded_base,
            image_size=image_size,
            module_name=module_name,
        )

    return KernelLiveEvent(
        kind=kind,
        timestamp=timestamp,
        source=source,
        summary=summary,
        data=data,
        raw=raw,
    )
