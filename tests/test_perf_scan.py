from __future__ import annotations

import json

from reverse_framework.analyzers.perf_scan import PerfScanAnalyzer
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.context import AnalysisContext
from reverse_framework.reporting import summarize_finding, to_markdown


def test_perf_scan_accepts_json_and_records_findings(monkeypatch, tmp_path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"A" * 256 + bytes(range(256)))

    def fake_resolve(configured_path: str | None):
        return target.parent / "perf_scan.exe"

    def fake_run(command, capture_output, check, text, timeout):
        payload = {
            "tool": "perf_scan",
            "target": str(target),
            "strings": {"count": 1, "items": [{"offset": 0, "kind": "ascii", "value": "AAAA"}]},
            "entropy": {"region_count": 1, "regions": [{"offset": 0, "size": 256, "entropy": 7.8}]},
        }
        return type(
            "Completed",
            (),
            {"stdout": json.dumps(payload), "stderr": "", "returncode": 0},
        )()

    monkeypatch.setattr("reverse_framework.analyzers.perf_scan._resolve_perf_scan", fake_resolve)
    monkeypatch.setattr("reverse_framework.analyzers.perf_scan.subprocess.run", fake_run)

    context = AnalysisContext(target=target, config=TriageConfig())
    PerfScanAnalyzer().run(context)

    finding = context.findings["perf_scan"]
    assert finding["tool"] == "perf_scan"
    assert finding["strings"]["items"][0]["kind"] == "ascii"
    assert finding["summary_text"]
    assert finding["preview_lines"] == [
        "0x00000000 ascii AAAA",
    ]
    assert context.issues

    summary_text, preview_lines = summarize_finding(finding)
    assert summary_text
    assert preview_lines == finding["preview_lines"]

    markdown = to_markdown(
        type(
            "Result",
            (),
            {
                "target": str(target),
                "generated_at": "2026-05-14T00:00:00Z",
                "issues": [],
                "indicators": [],
                "tools": [],
                "errors": [],
                "findings": {"perf_scan": finding},
            },
        )()
    )
    assert "Formatted view" in markdown
