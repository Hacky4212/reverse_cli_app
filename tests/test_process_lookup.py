from reverse_framework.core.process_lookup import ProcessCandidate, list_process_candidates, resolve_process_candidate


def test_resolve_process_candidate_returns_none_for_blank_selection() -> None:
    assert resolve_process_candidate() is None


def test_resolve_process_candidate_uses_process_name(monkeypatch) -> None:
    captured = {}

    def fake_resolve_powershell(configured_path: str | None) -> str | None:
        captured["configured_path"] = configured_path
        return "pwsh"

    def fake_run_powershell_json(executable: str, script: str):
        captured["executable"] = executable
        captured["script"] = script
        return [
            {
                "pid": 1234,
                "process_name": "notepad",
                "window_title": "Untitled - Notepad",
            }
        ]

    monkeypatch.setattr("reverse_framework.core.process_lookup._resolve_powershell", fake_resolve_powershell)
    monkeypatch.setattr("reverse_framework.core.process_lookup._run_powershell_json", fake_run_powershell_json)

    candidate = resolve_process_candidate(process_name="notepad.exe")

    assert candidate == ProcessCandidate(pid=1234, process_name="notepad", window_title="Untitled - Notepad")
    assert captured["configured_path"] is None
    assert "ProcessName" in captured["script"] or "process_name" in captured["script"]


def test_list_process_candidates_accepts_single_object_payload(monkeypatch) -> None:
    monkeypatch.setattr("reverse_framework.core.process_lookup._resolve_powershell", lambda configured_path: "pwsh")
    monkeypatch.setattr(
        "reverse_framework.core.process_lookup._run_powershell_json",
        lambda executable, script: {"pid": 2572, "process_name": "demo", "window_title": "Demo Window"},
    )

    assert list_process_candidates(pid=2572) == [
        ProcessCandidate(pid=2572, process_name="demo", window_title="Demo Window")
    ]


def test_resolve_process_candidate_rejects_multiple_matches(monkeypatch) -> None:
    monkeypatch.setattr("reverse_framework.core.process_lookup._resolve_powershell", lambda configured_path: "pwsh")
    monkeypatch.setattr(
        "reverse_framework.core.process_lookup._run_powershell_json",
        lambda executable, script: [
            {"pid": 1000, "process_name": "demo", "window_title": "One"},
            {"pid": 2000, "process_name": "demo", "window_title": "Two"},
        ],
    )

    try:
        resolve_process_candidate(process_name="demo.exe")
    except LookupError as exc:
        assert "Multiple running processes matched" in str(exc)
    else:
        raise AssertionError("Expected LookupError")
