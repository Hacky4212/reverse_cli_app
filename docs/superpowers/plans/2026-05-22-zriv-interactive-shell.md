# zriv Interactive Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `zriv` launcher with an interactive shell, flat command parsing, shortcut commands, and a GUI entry.

**Architecture:** Keep the existing analyzers and API layer. Add a launcher layer that routes raw argv into either shell mode or shortcut commands, then reuse the current backend functions for analyze/live/memory/gui actions. Keep the shell thin and stateful, with parsing isolated so tests can cover dispatch without starting a full terminal session.

**Tech Stack:** Python standard library (`argparse`, `cmd`, `shlex`, `sys`), pytest, existing `reverse_framework` modules.

---

### Task 1: Add failing launcher and shell tests

**Files:**
- Create: `tests/test_launcher.py`

- [ ] **Step 1: Write the failing test**

```python
from reverse_framework.launcher import main, ZrivShell


def test_main_enters_shell_on_shell_command(monkeypatch):
    called = []

    def fake_run_shell():
        called.append(True)

    monkeypatch.setattr("reverse_framework.launcher.run_shell", fake_run_shell)
    assert main(["shell"]) == 0
    assert called == [True]


def test_main_supports_top_level_analyze_shortcut(monkeypatch):
    captured = {}

    def fake_run_analyze_shortcut(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr("reverse_framework.launcher.run_analyze_shortcut", fake_run_analyze_shortcut)
    assert main(["-analyze", "file", "sample.bin"]) == 0
    assert captured["args"] == ["file", "sample.bin"]


def test_shell_dispatches_flat_analyze_command(monkeypatch):
    shell = ZrivShell()
    captured = {}

    def fake_run_file(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(shell, "handle_analyze", fake_run_file)
    assert shell.onecmd("analyze file sample.bin") is False
    assert captured["args"] == ["file", "sample.bin"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_launcher.py -v`
Expected: fail because `reverse_framework.launcher` does not exist yet.

- [ ] **Step 3: Commit**

```bash
git add tests/test_launcher.py
git commit -m "test: define zriv launcher behavior"
```

### Task 2: Implement launcher and shell routing

**Files:**
- Create: `reverse_framework/launcher.py`
- Modify: `reverse_framework/__main__.py`

- [ ] **Step 1: Write the minimal implementation**

```python
def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] == "shell":
        run_shell()
        return 0
    if args[0] in {"-analyze", "analyze"}:
        return run_analyze_shortcut(args[1:])
    if args[0] in {"-live", "live"}:
        return run_live_shortcut(args[1:])
    if args[0] in {"-memory", "memory"}:
        return run_memory_shortcut(args[1:])
    if args[0] in {"-gui", "gui"}:
        return launch_gui()
    return _legacy_main(args)
```

- [ ] **Step 2: Run the focused tests**

Run: `pytest tests/test_launcher.py -v`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add reverse_framework/launcher.py reverse_framework/__main__.py
git commit -m "feat: add zriv shell launcher"
```

### Task 3: Wire packaging and verify existing tests

**Files:**
- Modify: `pyproject.toml`
- Modify: `README.md`

- [ ] **Step 1: Update script entrypoints**

```toml
[project.scripts]
zriv = "reverse_framework.launcher:main"
reverse-tools = "reverse_framework.launcher:main"
reverse-tools-gui = "reverse_framework.gui:main"
```

- [ ] **Step 2: Run the relevant test suite**

Run: `pytest tests/test_launcher.py tests/test_live.py tests/test_gui_entrypoint.py -k "not cli_memory_mode_resolves_window_title" -v`
Expected: pass, with the known `tmp_path` permission case excluded.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml README.md tests/test_launcher.py reverse_framework
git commit -m "chore: expose zriv launcher"
```
