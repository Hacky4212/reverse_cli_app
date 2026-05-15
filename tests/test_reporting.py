from reverse_framework.reporting import summarize_finding, to_markdown


def test_summarize_finding_builds_compact_preview_for_nested_payload() -> None:
    finding = {
        "tool": "native_probe",
        "format": "PE",
        "valid": False,
        "headers": {"pe_offset": 128, "machine": "x64", "sections": 0},
        "sections": [],
    }

    summary_text, preview_lines = summarize_finding(finding)

    assert summary_text is not None
    assert "tool: native_probe" in summary_text
    assert preview_lines[0].startswith("headers:")
    assert any(line.startswith("headers:") for line in preview_lines)

    markdown = to_markdown(
        type(
            "Result",
            (),
            {
                "target": "demo.bin",
                "generated_at": "2026-05-14T00:00:00Z",
                "issues": [],
                "indicators": [],
                "tools": [],
                "errors": [],
                "findings": {"native_probe": finding},
            },
        )()
    )
    assert "Formatted view" in markdown
    assert "headers:" in markdown
