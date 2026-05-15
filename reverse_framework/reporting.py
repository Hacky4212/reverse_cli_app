from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from reverse_framework.core.pipeline import AnalysisResult


ReportFormat = Literal["all", "json", "markdown"]


def summarize_finding(finding: Any, max_preview_items: int = 5) -> tuple[str | None, list[str]]:
    if not isinstance(finding, dict):
        return None, []

    summary_text = _clean_text(finding.get("summary_text"))
    preview_lines: list[str] = []

    raw_preview = finding.get("preview_lines")
    if isinstance(raw_preview, list):
        for item in raw_preview:
            text = _clean_text(item)
            if text:
                preview_lines.append(text)

    if not preview_lines:
        preview_lines = _build_preview_lines(finding, max_preview_items=max_preview_items)

    if summary_text is None and preview_lines:
        summary_preview = preview_lines[:3]
        summary_text = " | ".join(summary_preview)
        preview_lines = preview_lines[len(summary_preview):]

    return summary_text, preview_lines


def write_reports(result: AnalysisResult, out_dir: Path, report_format: ReportFormat) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(result.target).name.replace(" ", "_")
    written: list[Path] = []

    if report_format in {"all", "json"}:
        path = out_dir / f"{safe_name}.json"
        path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(path)

    if report_format in {"all", "markdown"}:
        path = out_dir / f"{safe_name}.md"
        path.write_text(to_markdown(result), encoding="utf-8")
        written.append(path)

    return written


def to_markdown(result: AnalysisResult) -> str:
    lines = [
        "# Reverse Analysis Report",
        "",
        f"- Target: `{result.target}`",
        f"- Generated: `{result.generated_at}`",
        f"- Issues: `{len(result.issues)}`",
        f"- Indicators: `{len(result.indicators)}`",
        "",
        "## Issues",
        "",
    ]

    if result.issues:
        for issue in result.issues:
            lines.append(f"### {issue['severity'].upper()} - {issue['title']}")
            lines.append("")
            lines.append(issue["summary"])
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(issue, indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
    else:
        lines.append("No issues detected by enabled analyzers.")
        lines.append("")

    if result.indicators:
        lines.extend(["## Indicators", ""])
        for indicator in result.indicators[:200]:
            offset = indicator.get("offset")
            suffix = f" @ {offset}" if offset is not None else ""
            lines.append(f"- `{indicator['kind']}`: `{indicator['value']}`{suffix}")
        lines.append("")

    if result.tools:
        lines.extend(["## External Tools", ""])
        for tool in result.tools:
            status = "available" if tool["available"] else "missing"
            error = f" - {tool['error']}" if tool.get("error") else ""
            lines.append(f"- `{tool['name']}`: {status}{error}")
        lines.append("")

    lines.extend(
        [
        "## Findings",
        "",
        ]
    )

    for name, finding in result.findings.items():
        lines.append(f"### {name}")
        lines.append("")
        summary_text, preview_lines = summarize_finding(finding, max_preview_items=12)
        if summary_text:
            lines.append(summary_text)
            lines.append("")

        if preview_lines:
            lines.append("Formatted view")
            for item in preview_lines[:12]:
                lines.append(f"- {item}")
            lines.append("")

        lines.append("```json")
        lines.append(json.dumps(finding, indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")

    if result.errors:
        lines.extend(["## Errors", ""])
        for error in result.errors:
            lines.append(f"- `{error['analyzer']}`: {error['message']}")
        lines.append("")

    return "\n".join(lines)


def _build_preview_lines(finding: dict[str, Any], *, max_preview_items: int) -> list[str]:
    preview_lines: list[str] = []
    for key, value in finding.items():
        if key in {"summary_text", "preview_lines", "metrics"}:
            continue
        description = _describe_value(value, depth=1)
        if description is None:
            continue
        preview_lines.append(f"{key}: {description}")
        if len(preview_lines) >= max_preview_items:
            break
    return preview_lines


def _describe_value(value: Any, *, depth: int) -> str | None:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, str):
        return _truncate_text(value)
    if isinstance(value, dict):
        return _describe_mapping(value, depth=depth)
    if isinstance(value, (list, tuple)):
        return _describe_sequence(list(value), depth=depth)
    return _truncate_text(str(value))


def _describe_mapping(mapping: dict[str, Any], *, depth: int) -> str:
    if not mapping:
        return "0 keys"
    if depth <= 0:
        return f"{len(mapping)} keys"

    parts: list[str] = []
    for key, value in mapping.items():
        if key in {"summary_text", "preview_lines", "metrics"}:
            continue
        description = _describe_value(value, depth=depth - 1)
        if description is None:
            continue
        parts.append(f"{key}={description}")
        if len(parts) >= 3:
            break

    if parts:
        return ", ".join(parts)
    return f"{len(mapping)} keys"


def _describe_sequence(values: list[Any], *, depth: int) -> str:
    if not values:
        return "0 items"

    scalar_preview: list[str] = []
    for item in values[:3]:
        if not _is_scalar(item):
            scalar_preview = []
            break
        description = _describe_value(item, depth=0)
        if description is None:
            continue
        scalar_preview.append(description)

    if scalar_preview:
        suffix = "..." if len(values) > len(scalar_preview) else ""
        return f"{len(values)} items [{', '.join(scalar_preview)}{suffix}]"

    first_item = values[0]
    if isinstance(first_item, dict):
        first_description = _describe_mapping(first_item, depth=depth)
        if first_description:
            suffix = "" if len(values) == 1 else f"; {len(values) - 1} more"
            return f"{len(values)} items; first: {first_description}{suffix}"

    return f"{len(values)} items"


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text or None


def _truncate_text(value: str, limit: int = 96) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."
