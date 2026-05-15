import sys
from pathlib import Path

from reverse_framework.analyzers.dll_audit import DllAuditAnalyzer
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.context import AnalysisContext


def test_dll_audit_records_missing_tool(tmp_path: Path) -> None:
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"MZ")
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(dll_audit_path=str(tmp_path / "missing-dll-audit")),
    )

    DllAuditAnalyzer(path=context.config.dll_audit_path).run(context)

    assert context.tools[0].available is False
    assert context.findings["dll_audit"]["available"] is False


def test_dll_audit_records_json_output_and_issues(tmp_path: Path) -> None:
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"MZ")
    fake_auditor = tmp_path / "fake_dll_audit.py"
    fake_auditor.write_text(
        "import json\n"
        "print(json.dumps({"
        "'tool': 'dll_audit', "
        "'format': 'PE', "
        "'valid': True, "
        "'is_dll': True, "
        "'risk': {'writable_executable_sections': ['.x']}, "
        "'imports': {'dlls': [{'name': 'kernel32.dll', 'functions': ['LoadLibraryA']}]}"
        "}))\n",
        encoding="utf-8",
    )
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(dll_audit_path=sys.executable),
    )

    DllAuditAnalyzer(path=sys.executable, extra_args=[str(fake_auditor)]).run(context)

    assert context.findings["dll_audit"]["format"] == "PE"
    assert context.tools[0].available is True
    assert {issue.id for issue in context.issues} == {
        "dll_audit_sensitive_runtime_imports",
        "dll_audit_writable_executable_sections",
    }
