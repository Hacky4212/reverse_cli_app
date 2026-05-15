from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Protocol

from reverse_framework.core.context import AnalysisContext


class Analyzer(Protocol):
    name: str

    def run(self, context: AnalysisContext) -> None:
        ...


@dataclass(slots=True)
class AnalysisResult:
    target: str
    generated_at: str
    config: dict[str, Any]
    findings: dict[str, Any]
    issues: list[dict[str, Any]]
    indicators: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    errors: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "config": self.config,
            "findings": self.findings,
            "issues": self.issues,
            "indicators": self.indicators,
            "tools": self.tools,
            "errors": self.errors,
        }


@dataclass(slots=True)
class AnalysisPipeline:
    analyzers: Iterable[Analyzer]

    def run(self, context: AnalysisContext) -> AnalysisResult:
        for analyzer in self.analyzers:
            try:
                analyzer.run(context)
            except Exception as exc:  # Keep one plugin from killing the run.
                context.add_error(analyzer.name, str(exc))

        return AnalysisResult(
            target=str(context.target),
            generated_at=datetime.now(timezone.utc).isoformat(),
            config=context.config.to_dict(),
            findings=context.findings,
            issues=[issue.to_dict() for issue in context.issues],
            indicators=[indicator.to_dict() for indicator in context.indicators],
            tools=[tool.to_dict() for tool in context.tools],
            errors=context.errors,
        )
