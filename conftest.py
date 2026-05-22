from __future__ import annotations

import os
from pathlib import Path

from _pytest.pathlib import LOCK_TIMEOUT, make_numbered_dir_with_cleanup
from _pytest.tmpdir import TempPathFactory, get_user


def _safe_getbasetemp(self: TempPathFactory) -> Path:
    """Keep inherited ACLs on Windows sandboxed runs.

    In this environment, Python directory creation with mode=0o700 produces
    temp directories that become unreadable immediately. pytest uses 0o700 for
    its temp roots by default, so tmp_path-based tests fail before they run.
    """

    if self._basetemp is not None:
        return self._basetemp

    if self._given_basetemp is not None:
        basetemp = self._given_basetemp
        if basetemp.exists():
            from _pytest.pathlib import rm_rf

            rm_rf(basetemp)
        basetemp.mkdir()
        basetemp = basetemp.resolve()
    else:
        from_env = os.environ.get("PYTEST_DEBUG_TEMPROOT")
        default_root = Path(__file__).resolve().parent / "_pytest_temp_root_safe"
        temproot = Path(from_env).resolve() if from_env else default_root.resolve()
        temproot.mkdir(exist_ok=True)
        user = get_user() or "unknown"
        rootdir = temproot.joinpath(f"pytest-of-{user}")
        try:
            rootdir.mkdir(exist_ok=True)
        except OSError:
            rootdir = temproot.joinpath("pytest-of-unknown")
            rootdir.mkdir(exist_ok=True)
        keep = self._retention_count
        if self._retention_policy == "none":
            keep = 0
        basetemp = make_numbered_dir_with_cleanup(
            prefix="pytest-",
            root=rootdir,
            keep=keep,
            lock_timeout=LOCK_TIMEOUT,
            mode=0o755,
        )

    self._basetemp = basetemp
    self._trace("new basetemp", basetemp)
    return basetemp


def _safe_mktemp(self: TempPathFactory, basename: str, numbered: bool = True) -> Path:
    basename = self._ensure_relative_to_basetemp(basename)
    if not numbered:
        path = self.getbasetemp().joinpath(basename)
        path.mkdir()
        return path
    path = make_numbered_dir_with_cleanup(
        root=self.getbasetemp(),
        prefix=basename,
        keep=0,
        lock_timeout=LOCK_TIMEOUT,
        mode=0o755,
    )
    self._trace("mktemp", path)
    return path


if os.name == "nt":
    TempPathFactory.getbasetemp = _safe_getbasetemp
    TempPathFactory.mktemp = _safe_mktemp
