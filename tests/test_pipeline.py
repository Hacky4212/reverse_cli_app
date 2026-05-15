import subprocess
import sys
from pathlib import Path

from reverse_framework.cli import main


def test_cli_generates_reports(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ test string\x00more data")
    out_dir = tmp_path / "reports"

    assert main([str(sample), "--out", str(out_dir)]) == 0
    assert (out_dir / "sample.bin.json").exists()
    assert (out_dir / "sample.bin.md").exists()


def test_cli_code_text_outputs_reports(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "code_reports"
    assert (
        main(
            [
                "--code-text",
                "call recv\nret\n",
                "--analyzers",
                "code_structure",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "Analysis complete." in captured.out
    assert (out_dir / "analysis-input.txt.json").exists()


def test_cli_evidence_text_outputs_reports(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "trace_reports"
    assert (
        main(
            [
                "--evidence-text",
                '{"events":[{"kind":"call","function":"recv"},{"kind":"call","function":"decrypt_buffer"}]}',
                "--static-code",
                "call recv\ncall LoadLibraryA\nret\n",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "Analysis complete." in captured.out
    assert (out_dir / "execution-evidence.json").exists()


def test_cli_module_entrypoint_lists_analyzers() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "reverse_framework.cli", "--list-analyzers"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "execution_trace" in result.stdout
    assert "process_memory" in result.stdout


def test_cli_handles_empty_text_inputs(tmp_path: Path) -> None:
    code_out = tmp_path / "empty_code"
    evidence_out = tmp_path / "empty_evidence"

    assert (
        main(
            [
                "--code-text",
                "",
                "--analyzers",
                "code_structure",
                "--out",
                str(code_out),
            ]
        )
        == 0
    )
    assert (code_out / "analysis-input.txt.json").exists()

    assert (
        main(
            [
                "--evidence-text",
                "",
                "--analyzers",
                "execution_trace",
                "--out",
                str(evidence_out),
            ]
        )
        == 0
    )
    assert (evidence_out / "execution-evidence.json").exists()


def test_cli_process_memory_outputs_reports(tmp_path: Path, monkeypatch, capsys) -> None:
    out_dir = tmp_path / "memory_reports"
    expected = out_dir / "process-memory-p4321-0x1000.json"

    monkeypatch.setattr(
        "reverse_framework.cli.analyze_process_memory_and_write_reports",
        lambda *args, **kwargs: (None, [expected]),
    )

    assert (
        main(
            [
                "--memory-pid",
                "4321",
                "--memory-address",
                "0x1000",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "Analysis complete." in captured.out
    assert str(expected) in captured.out
