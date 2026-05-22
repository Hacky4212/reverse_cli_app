from pathlib import Path

from reverse_framework.auth import AuthSession, load_auth_store, authorize_command


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

    assert session.username == "alice"
    assert session.role == "restricted"


def test_authorize_command_blocks_restricted_memory_access() -> None:
    allowed, message = authorize_command(AuthSession(username="alice", role="restricted"), "memory")

    assert allowed is False
    assert message is not None
    assert "memory" in message.lower()
