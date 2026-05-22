from reverse_framework.auth import AuthSession
from reverse_framework.launcher import ZrivShell, main, main_gui


def test_main_enters_shell_on_shell_command(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="admin", role="admin"),
    )

    def fake_run_shell(session: AuthSession) -> int:
        captured["session"] = session
        return 0

    monkeypatch.setattr("reverse_framework.launcher.run_shell", fake_run_shell)

    assert main(["shell"]) == 0
    assert captured["session"].username == "admin"


def test_main_supports_top_level_analyze_shortcut(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    def fake_run_analyze_shortcut(args: list[str]) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr("reverse_framework.launcher.run_analyze_shortcut", fake_run_analyze_shortcut)

    assert main(["-analyze", "file", "sample.bin"]) == 0
    assert captured["args"] == ["file", "sample.bin"]


def test_main_supports_top_level_gui_shortcut(monkeypatch) -> None:
    called = []

    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    def fake_launch_gui(session: AuthSession | None = None) -> int:
        called.append(session is not None)
        return 0

    monkeypatch.setattr("reverse_framework.launcher.launch_gui", fake_launch_gui)

    assert main(["-gui"]) == 0
    assert called == [True]


def test_main_gui_entrypoint_uses_authenticated_session(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    def fake_launch_gui(session: AuthSession | None = None) -> int:
        captured["session"] = session
        return 0

    monkeypatch.setattr("reverse_framework.launcher.launch_gui", fake_launch_gui)

    assert main_gui() == 0
    assert captured["session"].username == "alice"


def test_main_supports_top_level_live_shortcut(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="admin", role="admin"),
    )

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

    monkeypatch.setattr("reverse_framework.launcher.stream_live_kernel_events", lambda **kwargs: iter([FakeEvent()]))

    assert main(["-live", "start", "--pid", "1000"]) == 0
    captured = capsys.readouterr()
    assert '"kind": "process_start"' in captured.out


def test_main_supports_top_level_memory_shortcut(monkeypatch, capsys) -> None:
    expected = "reports/process-memory-p4321-0x1000.json"
    captured = {}

    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="admin", role="admin"),
    )

    def fake_analyze_process_memory_and_write_reports(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return None, [expected]

    monkeypatch.setattr(
        "reverse_framework.launcher.analyze_process_memory_and_write_reports",
        fake_analyze_process_memory_and_write_reports,
    )

    assert main(["-memory", "read", "--pid", "4321", "--address", "0x1000"]) == 0
    output = capsys.readouterr().out
    assert "Analysis complete." in output
    assert expected in output
    assert captured["args"] == (4321, "0x1000")


def test_main_blocks_memory_shortcut_for_restricted_user(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    assert main(["-memory", "read", "--pid", "4321", "--address", "0x1000"]) == 2

    assert "requires admin" in capsys.readouterr().err.lower()


def test_main_blocks_legacy_memory_mode_for_restricted_user(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    assert main(["--memory-pid", "4321", "--memory-address", "0x1000"]) == 2

    assert "requires admin" in capsys.readouterr().err.lower()


def test_shell_dispatches_flat_analyze_command(monkeypatch) -> None:
    shell = ZrivShell(AuthSession(username="alice", role="restricted"))
    captured = {}

    def fake_handle_analyze(args: list[str]) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(shell, "handle_analyze", fake_handle_analyze)

    assert shell.onecmd("analyze file sample.bin") is False
    assert captured["args"] == ["file", "sample.bin"]


def test_shell_blocks_memory_for_restricted_user(capsys) -> None:
    shell = ZrivShell(AuthSession(username="alice", role="restricted"))

    assert shell.onecmd("memory read --pid 1234 --address 0x1000") is False

    assert "requires admin" in capsys.readouterr().out.lower()


def test_shell_dispatches_gui_command(monkeypatch) -> None:
    shell = ZrivShell(AuthSession(username="alice", role="restricted"))
    called = []

    def fake_launch_gui() -> int:
        called.append(True)
        return 0

    monkeypatch.setattr(shell, "launch_gui", fake_launch_gui)

    assert shell.onecmd("gui") is False
    assert called == [True]
