from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TriageConfig:
    min_string: int = 4
    max_strings: int = 500
    entropy_window: int = 4096
    entropy_threshold: float = 7.2
    max_entropy_regions: int = 20
    native_probe_enabled: bool = True
    native_probe_path: str | None = None
    native_probe_timeout: int = 30
    dll_audit_enabled: bool = True
    dll_audit_path: str | None = None
    dll_audit_timeout: int = 30
    perf_scan_enabled: bool = True
    perf_scan_path: str | None = None
    perf_scan_timeout: int = 30
    process_memory_enabled: bool = True
    process_memory_path: str | None = None
    process_memory_timeout: int = 30
    process_memory_pid: int | None = None
    process_memory_address: str | None = None
    process_memory_size: int = 64
    process_memory_extra_args: list[str] = field(default_factory=list)
    enabled_analyzers: list[str] = field(default_factory=list)
    external_tools: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "TriageConfig":
        config = cls()
        for key, value in values.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_string": self.min_string,
            "max_strings": self.max_strings,
            "entropy_window": self.entropy_window,
            "entropy_threshold": self.entropy_threshold,
            "max_entropy_regions": self.max_entropy_regions,
            "native_probe_enabled": self.native_probe_enabled,
            "native_probe_path": self.native_probe_path,
            "native_probe_timeout": self.native_probe_timeout,
            "dll_audit_enabled": self.dll_audit_enabled,
            "dll_audit_path": self.dll_audit_path,
            "dll_audit_timeout": self.dll_audit_timeout,
            "perf_scan_enabled": self.perf_scan_enabled,
            "perf_scan_path": self.perf_scan_path,
            "perf_scan_timeout": self.perf_scan_timeout,
            "process_memory_enabled": self.process_memory_enabled,
            "process_memory_path": self.process_memory_path,
            "process_memory_timeout": self.process_memory_timeout,
            "process_memory_pid": self.process_memory_pid,
            "process_memory_address": self.process_memory_address,
            "process_memory_size": self.process_memory_size,
            "process_memory_extra_args": self.process_memory_extra_args,
            "enabled_analyzers": self.enabled_analyzers,
            "external_tools": self.external_tools,
        }


def load_config(path: Path | None) -> TriageConfig:
    if path is None or not path.exists():
        return TriageConfig()

    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except UnicodeDecodeError as exc:
        raise ValueError(f"Config must be a UTF-8 JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Config must contain valid JSON: {path}") from exc

    if not isinstance(raw, dict):
        raise ValueError("Config root must be a JSON object.")

    return TriageConfig.from_mapping(raw)
