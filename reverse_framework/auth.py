from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_USERS_PATH = Path("reverse-tools.users.json")
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"


class AuthError(ValueError):
    pass


@dataclass(slots=True)
class AuthSession:
    username: str
    role: str


@dataclass(slots=True)
class AuthRecord:
    username: str
    role: str
    password: str | None = None
    password_sha256: str | None = None

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "AuthRecord":
        username = str(payload.get("username") or "").strip()
        role = str(payload.get("role") or "restricted").strip() or "restricted"
        password = payload.get("password")
        password_sha256 = payload.get("password_sha256")
        if not username:
            raise AuthError("User record requires a username.")
        if password is None and password_sha256 is None:
            raise AuthError(f"User '{username}' requires password or password_sha256.")
        return cls(
            username=username,
            role=role,
            password=None if password is None else str(password),
            password_sha256=None if password_sha256 is None else str(password_sha256).lower(),
        )

    def matches_password(self, password: str) -> bool:
        if self.password is not None:
            return self.password == password
        if self.password_sha256 is None:
            return False
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest().lower()
        return digest == self.password_sha256


class AuthStore:
    def __init__(self, records: list[AuthRecord]) -> None:
        self._records = {record.username: record for record in records}

    def authenticate(self, username: str, password: str) -> AuthSession:
        record = self._records.get(username)
        if record is None or not record.matches_password(password):
            raise AuthError("Invalid username or password.")
        return AuthSession(username=record.username, role=record.role)


def load_auth_store(path: Path | str | None = None) -> AuthStore:
    resolved = DEFAULT_USERS_PATH if path is None else Path(path)
    if not resolved.exists():
        return AuthStore(_default_records())

    try:
        with resolved.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except UnicodeDecodeError as exc:
        raise AuthError(f"User store must be a UTF-8 JSON file: {resolved}") from exc
    except json.JSONDecodeError as exc:
        raise AuthError(f"User store must contain valid JSON: {resolved}") from exc

    if not isinstance(raw, dict):
        raise AuthError("User store root must be a JSON object.")

    users = raw.get("users")
    if not isinstance(users, list):
        raise AuthError("User store requires a 'users' array.")

    records = [AuthRecord.from_mapping(item) for item in users if isinstance(item, dict)]
    if not records:
        raise AuthError("User store does not contain any valid users.")
    return AuthStore(records)


def authorize_command(session: AuthSession, command: str) -> tuple[bool, str | None]:
    normalized = command.strip().lower().lstrip("-")
    if session.role == "admin":
        return True, None
    if normalized in {"memory", "live", "kernel"}:
        return False, f"{normalized} requires admin privileges."
    return True, None


def _default_records() -> list[AuthRecord]:
    return [
        AuthRecord(
            username=DEFAULT_ADMIN_USERNAME,
            role="admin",
            password=DEFAULT_ADMIN_PASSWORD,
        )
    ]
