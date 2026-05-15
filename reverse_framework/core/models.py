from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    summary: str
    confidence: float = 0.5
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Indicator:
    kind: str
    value: str
    source: str
    offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolStatus:
    name: str
    command: list[str]
    available: bool
    enabled: bool
    output: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

