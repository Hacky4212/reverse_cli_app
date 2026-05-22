# zriv Auth Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local account authentication and role-based command authorization for the `zriv` shell, top-level shortcuts, and GUI launcher.

**Architecture:** Keep auth concerns in a focused `reverse_framework/auth.py` module. The launcher becomes the single gate for login, role checks, and audit events, while the existing analysis and GUI backends stay unchanged except for receiving the authenticated role when needed. Demo scope supports built-in `admin/admin`, optional local user file overrides, and defers leader second approval.

**Tech Stack:** Python standard library (`getpass`, `json`, `hashlib`, `pathlib`), pytest, existing `reverse_framework` modules.

---

### Task 1: Add failing auth tests

**Files:**
- Create: `tests/test_auth.py`
- Modify: `tests/test_launcher.py`

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path

from reverse_framework.auth import AuthError, AuthSession, AuthStore, authorize_command, load_auth_store


def test_load_auth_store_defaults_to_admin_account(tmp_path: Path) -> None:
    store = load_auth_store(tmp_path / "missing-users.json")
    session = store.authenticate("admin", "admin")
    assert session.username == "admin"
    assert session.role == "admin"


def test_load_auth_store_reads_restricted_user_file(tmp_path: Path) -> None:
    users_file = tmp_path / "users.json"
    users_file.write_text(
        '{"users":[{"username":"alice","password":"pw","role":"restricted"}]}',
        encoding="utf-8",
    )

    store = load_auth_store(users_file)
    session = store.authenticate("alice", "pw")
    assert session.role == "restricted"


def test_authorize_command_blocks_restricted_memory_access() -> None:
    allowed, message = authorize_command(AuthSession(username="alice", role="restricted"), "memory")
    assert allowed is False
    assert "memory" in message.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_auth.py tests/test_launcher.py -q`
Expected: FAIL because `reverse_framework.auth` and launcher auth routing do not exist yet.

- [ ] **Step 3: Commit**

```bash
git add tests/test_auth.py tests/test_launcher.py
git commit -m "test: define zriv auth demo behavior"
```

### Task 2: Implement auth store and authorization rules

**Files:**
- Create: `reverse_framework/auth.py`
- Modify: `reverse_framework/core/config.py`
- Modify: `reverse-tools.example.json`

- [ ] **Step 1: Write the minimal implementation**

```python
@dataclass(slots=True)
class AuthSession:
    username: str
    role: str


def authorize_command(session: AuthSession, command: str) -> tuple[bool, str | None]:
    if session.role == "admin":
        return True, None
    if command in {"memory", "live"}:
        return False, f"{command} requires admin privileges."
    return True, None
```

- [ ] **Step 2: Run focused tests**

Run: `pytest tests/test_auth.py -q`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add reverse_framework/auth.py reverse_framework/core/config.py reverse-tools.example.json tests/test_auth.py
git commit -m "feat: add local auth store for zriv demo"
```

### Task 3: Gate launcher, shell, and GUI entrypoints

**Files:**
- Modify: `reverse_framework/launcher.py`
- Modify: `reverse_framework/gui.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_launcher.py`
- Modify: `tests/test_gui_entrypoint.py`

- [ ] **Step 1: Write the failing launcher tests**

```python
def test_main_blocks_memory_shortcut_for_restricted_user(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="alice", role="restricted"),
    )

    assert main(["-memory", "read", "--pid", "4321", "--address", "0x1000"]) == 2
    assert "requires admin" in capsys.readouterr().err.lower()


def test_shell_requires_login_before_cmdloop(monkeypatch) -> None:
    monkeypatch.setattr(
        "reverse_framework.launcher.authenticate_for_command",
        lambda command_name, interactive=True: AuthSession(username="admin", role="admin"),
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_launcher.py tests/test_gui_entrypoint.py -q`
Expected: FAIL because launcher does not authenticate or authorize commands yet.

- [ ] **Step 3: Implement minimal launcher gating**

```python
def authenticate_for_command(command_name: str, interactive: bool = True) -> AuthSession | None:
    store = load_auth_store(DEFAULT_USERS_PATH)
    return prompt_for_session(store) if interactive else None


def _require_authorized_session(command_name: str) -> AuthSession | None:
    session = authenticate_for_command(command_name)
    if session is None:
        return None
    allowed, message = authorize_command(session, command_name)
    if not allowed:
        print(message, file=sys.stderr)
        return None
    return session
```

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_launcher.py tests/test_gui_entrypoint.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add reverse_framework/launcher.py reverse_framework/gui.py pyproject.toml tests/test_launcher.py tests/test_gui_entrypoint.py
git commit -m "feat: gate zriv commands behind local auth"
```

### Task 4: Update docs and run regression checks

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the demo auth model**

```markdown
## Demo auth

- `admin` / `admin` has full access.
- Other local users come from `reverse-tools.users.json`.
- `restricted` users can use `analyze` and `gui`.
- `memory` and `live` require `admin`.
- Leader second approval is planned later and is not part of the demo build.
```

- [ ] **Step 2: Run regression tests**

Run: `pytest tests/test_auth.py tests/test_launcher.py tests/test_process_memory.py tests/test_live.py tests/test_gui_entrypoint.py -q`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: describe zriv auth demo"
```
