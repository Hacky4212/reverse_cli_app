from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverse_framework.core.config import TriageConfig
from reverse_framework.core.models import Finding, Indicator, ToolStatus


@dataclass(slots=True)
class AnalysisContext:
    target: Path
    config: TriageConfig = field(default_factory=TriageConfig)
    data: bytes | None = None
    findings: dict[str, Any] = field(default_factory=dict)
    issues: list[Finding] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    tools: list[ToolStatus] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def read_bytes(self) -> bytes:
        if self.data is None:
            self.data = self.target.read_bytes()
        return self.data

    def add_finding(self, name: str, value: Any) -> None:
        self.findings[name] = value

    def add_issue(self, finding: Finding) -> None:
        self.issues.append(finding)

    def add_indicator(self, indicator: Indicator) -> None:
        self.indicators.append(indicator)

    def add_tool_status(self, status: ToolStatus) -> None:
        self.tools.append(status)

    def add_error(self, analyzer: str, message: str) -> None:
        self.errors.append({"analyzer": analyzer, "message": message})
