from reverse_framework.cli import main
from reverse_framework.live import _build_powershell_script, _event_from_payload


def test_build_powershell_script_includes_trace_queries() -> None:
    script = _build_powershell_script(
        process_id=4321,
        include_processes=True,
        include_threads=True,
        include_images=True,
        duration_seconds=15,
    )

    assert "Win32_ProcessStartTrace" in script
    assert "Win32_ThreadStartTrace" in script
    assert "Win32_ModuleLoadTrace" in script
    assert "ProcessID = 4321" in script
    assert "AddSeconds(15)" in script


def test_event_payload_normalization() -> None:
    event = _event_from_payload(
        {
            "kind": "module_load",
            "timestamp": "2026-05-12T00:00:00Z",
            "source": "krnlprov",
            "summary": "Module loaded: demo.sys",
            "data": {
                "process_id": 1234,
                "module_kind": "driver",
                "default_base": "0x140000000",
                "image_base": "0x141000000",
                "image_size": "0x2000",
                "file_name": "demo.sys",
            },
            "raw": {"file_name": "demo.sys"},
        }
    )

    assert event.kind == "module_load"
    assert event.data["module_kind"] == "driver"
    assert event.data["addressing"]["display_mode"] == "rva"
    assert event.data["addressing"]["slide"] == 0x1000000
    assert event.raw["file_name"] == "demo.sys"


def test_cli_live_mode_streams_json(monkeypatch, capsys) -> None:
    class FakeEvent:
        def to_dict(self) -> dict[str, object]:
            return {
                "kind": "process_start",
                "timestamp": "2026-05-12T00:00:00Z",
                "source": "krnlprov",
                "summary": "Process started: demo.exe (1000)",
                "data": {"process_id": 1000},
                "raw": {"process_id": 1000},
            }

    monkeypatch.setattr(
        "reverse_framework.cli.stream_live_kernel_events",
        lambda **kwargs: iter([FakeEvent()]),
    )

    assert main(["--live"]) == 0
    captured = capsys.readouterr()
    assert '"kind": "process_start"' in captured.out


def test_cli_live_mode_resolves_process_name(monkeypatch, capsys) -> None:
    class FakeCandidate:
        pid = 4321

        def label(self) -> str:
            return "PID 4321 | demo.exe"

    class FakeEvent:
        def to_dict(self) -> dict[str, object]:
            return {
                "kind": "process_start",
                "timestamp": "2026-05-12T00:00:00Z",
                "source": "krnlprov",
                "summary": "Process started: demo.exe (4321)",
                "data": {"process_id": 4321},
                "raw": {"process_id": 4321},
            }

    monkeypatch.setattr("reverse_framework.cli.resolve_process_candidate", lambda **kwargs: FakeCandidate())
    monkeypatch.setattr("reverse_framework.cli.stream_live_kernel_events", lambda **kwargs: iter([FakeEvent()]))

    assert main(["--live", "--process-name", "demo.exe"]) == 0
    captured = capsys.readouterr()
    assert '"kind": "process_start"' in captured.out


def test_cli_memory_mode_resolves_window_title(tmp_path, monkeypatch, capsys) -> None:
    out_dir = tmp_path / "memory_reports"
    expected = out_dir / "process-memory-p4321-0x1000.json"
    captured = {}

    class FakeCandidate:
        pid = 4321

        def label(self) -> str:
            return "PID 4321 | demo.exe | Demo Window"

    def fake_analyze(*args, **kwargs):
        captured["pid"] = args[0]
        return None, [expected]

    monkeypatch.setattr("reverse_framework.cli.resolve_process_candidate", lambda **kwargs: FakeCandidate())
    monkeypatch.setattr("reverse_framework.cli.analyze_process_memory_and_write_reports", fake_analyze)

    assert (
        main(
            [
                "--memory-address",
                "0x1000",
                "--window-title",
                "Demo Window",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    captured_output = capsys.readouterr()
    assert captured["pid"] == 4321
    assert "Analysis complete." in captured_output.out
    assert str(expected) in captured_output.out
