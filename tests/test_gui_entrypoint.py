from reverse_framework.auth import AuthSession
from reverse_framework.cli import main
from reverse_framework.gui import GUI_ENABLED_MODES, check_gui_mode_access


def test_cli_gui_mode_dispatches(monkeypatch) -> None:
    called = []

    def fake_launch_gui() -> int:
        called.append(True)
        return 0

    monkeypatch.setattr("reverse_framework.cli.launch_gui", fake_launch_gui)

    assert main(["--gui"]) == 0
    assert called == [True]


def test_gui_never_exposes_live_or_memory_modes() -> None:
    assert "live" not in GUI_ENABLED_MODES
    assert "memory" not in GUI_ENABLED_MODES


def test_gui_blocks_live_even_for_admin() -> None:
    allowed, message = check_gui_mode_access("live", AuthSession(username="admin", role="admin"))

    assert allowed is False
    assert message is not None
    assert "gui" in message.lower()
    assert "cli" in message.lower()


def test_gui_allows_static_analysis_modes() -> None:
    allowed, message = check_gui_mode_access("file", AuthSession(username="alice", role="restricted"))

    assert allowed is True
    assert message is None
