from reverse_framework.cli import main


def test_cli_gui_mode_dispatches(monkeypatch) -> None:
    called = []

    def fake_launch_gui() -> int:
        called.append(True)
        return 0

    monkeypatch.setattr("reverse_framework.cli.launch_gui", fake_launch_gui)

    assert main(["--gui"]) == 0
    assert called == [True]
