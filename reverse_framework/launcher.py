from __future__ import annotations

import argparse
import cmd
import getpass
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Iterable

from reverse_framework.api import (
    analyze_and_write_reports,
    analyze_code_text_and_write_reports,
    analyze_execution_evidence_and_write_reports,
    analyze_process_memory_and_write_reports,
    stream_live_kernel_events,
)
from reverse_framework.auth import AuthError, AuthSession, authorize_command, load_auth_store
from reverse_framework.core.config import TriageConfig, load_config
from reverse_framework.core.process_lookup import resolve_process_candidate


PROGRAM_NAME = "zriv"
DEFAULT_CONFIG_PATH = Path("reverse-tools.json")
DEFAULT_OUT_DIR = Path("reports")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] == "shell":
        session = _require_authorized_session("shell")
        return 2 if session is None else run_shell(session)

    command = args[0]
    rest = args[1:]
    if command in {"-analyze", "analyze"}:
        if _require_authorized_session("analyze") is None:
            return 2
        return run_analyze_shortcut(rest)
    if command in {"-live", "live"}:
        if _require_authorized_session("live") is None:
            return 2
        return run_live_shortcut(rest)
    if command in {"-memory", "memory"}:
        if _require_authorized_session("memory") is None:
            return 2
        return run_memory_shortcut(rest)
    if command in {"-gui", "gui"}:
        session = _require_authorized_session("gui")
        return 2 if session is None else launch_gui(session)

    if _require_authorized_session(_infer_legacy_command(args)) is None:
        return 2
    return _legacy_main(args)


def main_gui(argv: list[str] | None = None) -> int:
    session = _require_authorized_session("gui")
    return 2 if session is None else launch_gui(session)


def run_shell(session: AuthSession) -> int:
    shell = ZrivShell(session)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        return 0
    return 0


def launch_gui(session: AuthSession | None = None) -> int:
    from reverse_framework.gui import main as gui_main

    return gui_main(session=session)


def run_analyze_shortcut(argv: list[str]) -> int:
    if not argv:
        _print_analyze_usage()
        return 2

    mode = argv[0]
    args = argv[1:]
    if mode == "file":
        parser = _build_common_parser(f"{PROGRAM_NAME} analyze file")
        parser.add_argument("target", type=Path)
        parsed = _parse_args(parser, args)
        if parsed is None:
            return 2
        config = _load_config(parsed.config, parsed.min_string, parsed.max_strings)
        if config is None:
            return 2
        selected = _parse_analyzers(parsed.analyzers)
        _, written = analyze_and_write_reports(
            target=parsed.target,
            out_dir=parsed.out,
            report_format=parsed.format,
            config=config,
            analyzers=selected,
        )
        _print_report_paths(written)
        return 0

    if mode == "code":
        parser = _build_common_parser(f"{PROGRAM_NAME} analyze code")
        parser.add_argument("--text", required=True)
        parser.add_argument("--name", default="analysis-input.txt")
        parsed = _parse_args(parser, args)
        if parsed is None:
            return 2
        config = _load_config(parsed.config, parsed.min_string, parsed.max_strings)
        if config is None:
            return 2
        selected = _parse_analyzers(parsed.analyzers)
        _, written = analyze_code_text_and_write_reports(
            parsed.text,
            out_dir=parsed.out,
            report_format=parsed.format,
            target_name=parsed.name,
            config=config,
            analyzers=selected,
        )
        _print_report_paths(written)
        return 0

    if mode == "evidence":
        parser = _build_common_parser(f"{PROGRAM_NAME} analyze evidence")
        parser.add_argument("--text", required=True)
        parser.add_argument("--name", default="execution-evidence")
        parser.add_argument("--static-code")
        parsed = _parse_args(parser, args)
        if parsed is None:
            return 2
        config = _load_config(parsed.config, parsed.min_string, parsed.max_strings)
        if config is None:
            return 2
        selected = _parse_analyzers(parsed.analyzers)
        _, written = analyze_execution_evidence_and_write_reports(
            parsed.text,
            out_dir=parsed.out,
            report_format=parsed.format,
            static_code=parsed.static_code,
            target_name=parsed.name,
            config=config,
            analyzers=selected,
        )
        _print_report_paths(written)
        return 0

    _print_analyze_usage()
    return 2


def run_live_shortcut(argv: list[str]) -> int:
    if not argv or argv[0] != "start":
        _print_live_usage()
        return 2

    parser = argparse.ArgumentParser(prog=f"{PROGRAM_NAME} live start", add_help=False, allow_abbrev=False)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--process-name")
    parser.add_argument("--window-title")
    parser.add_argument("--duration", type=int, default=0)
    parsed = _parse_args(parser, argv[1:])
    if parsed is None:
        return 2

    live_pid = _resolve_dynamic_pid(parsed.pid, parsed.process_name, parsed.window_title)
    try:
        for event in stream_live_kernel_events(process_id=live_pid, duration_seconds=parsed.duration or None):
            print(json.dumps(event.to_dict(), ensure_ascii=False))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Live monitor error: {exc}", file=sys.stderr)
        return 2
    return 0


def run_memory_shortcut(argv: list[str]) -> int:
    if not argv or argv[0] != "read":
        _print_memory_usage()
        return 2

    parser = _build_common_parser(f"{PROGRAM_NAME} memory read")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--process-name")
    parser.add_argument("--window-title")
    parser.add_argument("--address", required=True)
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--process-memory-path")
    parsed = _parse_args(parser, argv[1:])
    if parsed is None:
        return 2

    config = _load_config(parsed.config, parsed.min_string, parsed.max_strings)
    if config is None:
        return 2
    if parsed.process_memory_path is not None:
        config.process_memory_path = parsed.process_memory_path

    memory_pid = _resolve_dynamic_pid(parsed.pid, parsed.process_name, parsed.window_title)
    if memory_pid is None:
        print("Choose --pid, --process-name, or --window-title.", file=sys.stderr)
        return 2

    _, written = analyze_process_memory_and_write_reports(
        memory_pid,
        parsed.address,
        size=parsed.size,
        out_dir=parsed.out,
        report_format=parsed.format,
        config=config,
        analyzers=_parse_analyzers(parsed.analyzers),
    )
    _print_report_paths(written)
    return 0


class ZrivShell(cmd.Cmd):
    prompt = f"{PROGRAM_NAME}> "

    def __init__(self, session: AuthSession) -> None:
        super().__init__(stdin=sys.stdin, stdout=sys.stdout)
        self.session = session
        self.intro = (
            f"{PROGRAM_NAME} shell. Logged in as {self.session.username} ({self.session.role}). "
            "Type help for commands."
        )

    def emptyline(self) -> None:
        return

    def do_analyze(self, arg: str) -> bool:
        if not self._ensure_allowed("analyze"):
            return False
        args = _split_command_line(arg)
        if not args:
            self.stdout.write("Usage: analyze file <path> | analyze code --text <text> | analyze evidence --text <text>\n")
            return False
        self.handle_analyze(args)
        return False

    def do_live(self, arg: str) -> bool:
        if not self._ensure_allowed("live"):
            return False
        args = _split_command_line(arg)
        if not args:
            self.stdout.write("Usage: live start [--pid ...] [--process-name ...] [--window-title ...] [--duration ...]\n")
            return False
        self.handle_live(args)
        return False

    def do_memory(self, arg: str) -> bool:
        if not self._ensure_allowed("memory"):
            return False
        args = _split_command_line(arg)
        if not args:
            self.stdout.write("Usage: memory read --pid ... --address ... [--size ...]\n")
            return False
        self.handle_memory(args)
        return False

    def do_gui(self, arg: str) -> bool:
        if not self._ensure_allowed("gui"):
            return False
        self.launch_gui()
        return False

    def do_help(self, arg: str) -> bool:
        topic = arg.strip()
        if not topic:
            self.stdout.write(
                "Commands: analyze, live, memory, gui, help, clear, exit\n"
                "Examples:\n"
                "  analyze file sample.bin\n"
                "  live start --pid 1234\n"
                "  memory read --pid 1234 --address 0x1000 --size 64\n"
            )
            return False
        if topic == "analyze":
            self.stdout.write("analyze file <path> | analyze code --text <text> | analyze evidence --text <text>\n")
            return False
        if topic == "live":
            self.stdout.write("live start [--pid ...] [--process-name ...] [--window-title ...] [--duration ...]\n")
            return False
        if topic == "memory":
            self.stdout.write("memory read --pid ... --address ... [--size ...]\n")
            return False
        if topic == "gui":
            self.stdout.write("gui\n")
            return False
        self.stdout.write(f"No help for {topic}\n")
        return False

    def do_clear(self, arg: str) -> bool:
        _clear_screen()
        return False

    def do_exit(self, arg: str) -> bool:
        return True

    def do_EOF(self, arg: str) -> bool:  # pragma: no cover - interactive shortcut
        self.stdout.write("\n")
        return True

    def default(self, line: str) -> bool:
        self.stdout.write(f"Unknown command: {line}\nType 'help' for a list of commands.\n")
        return False

    def handle_analyze(self, args: list[str]) -> int:
        return run_analyze_shortcut(args)

    def handle_live(self, args: list[str]) -> int:
        return run_live_shortcut(args)

    def handle_memory(self, args: list[str]) -> int:
        return run_memory_shortcut(args)

    def launch_gui(self) -> int:
        return launch_gui(self.session)

    def _ensure_allowed(self, command_name: str) -> bool:
        allowed, message = authorize_command(self.session, command_name)
        if allowed:
            return True
        self.stdout.write(f"{message}\n")
        return False


def _legacy_main(argv: list[str]) -> int:
    from reverse_framework.cli import main as legacy_main

    return legacy_main(argv)


def _build_common_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, add_help=False, allow_abbrev=False)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--format", choices=["all", "json", "markdown"], default="all")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--analyzers")
    parser.add_argument("--min-string", type=int, default=None)
    parser.add_argument("--max-strings", type=int, default=None)
    return parser


def _parse_args(parser: argparse.ArgumentParser, args: list[str]) -> argparse.Namespace | None:
    try:
        return parser.parse_args(args)
    except SystemExit:
        return None


def _load_config(path: Path, min_string: int | None, max_strings: int | None) -> TriageConfig | None:
    try:
        config = load_config(path)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return None

    if min_string is not None:
        config.min_string = min_string
    if max_strings is not None:
        config.max_strings = max_strings
    return config


def _parse_analyzers(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def authenticate_for_command(
    command_name: str,
    interactive: bool = True,
    *,
    input_fn=input,
    password_fn=None,
) -> AuthSession | None:
    try:
        store = load_auth_store()
    except AuthError as exc:
        print(f"Authentication setup error: {exc}", file=sys.stderr)
        return None

    if not interactive:
        return None

    try:
        username = input_fn("Username: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("Authentication cancelled.", file=sys.stderr)
        return None
    if not username:
        print("Authentication failed: username is required.", file=sys.stderr)
        return None

    read_password = getpass.getpass if password_fn is None else password_fn
    try:
        password = read_password("Password: ")
    except (EOFError, KeyboardInterrupt):
        print("Authentication cancelled.", file=sys.stderr)
        return None

    try:
        return store.authenticate(username, password)
    except AuthError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return None


def _require_authorized_session(command_name: str) -> AuthSession | None:
    session = authenticate_for_command(command_name, interactive=True)
    if session is None:
        return None
    allowed, message = authorize_command(session, command_name)
    if allowed:
        return session
    if message:
        print(message, file=sys.stderr)
    return None


def _resolve_dynamic_pid(pid: int | None, process_name: str | None, window_title: str | None) -> int | None:
    if pid is not None:
        return pid
    candidate = resolve_process_candidate(pid=pid, process_name=process_name, window_title=window_title)
    return None if candidate is None else candidate.pid


def _split_command_line(arg: str) -> list[str]:
    if not arg.strip():
        return []
    return shlex.split(arg)


def _print_report_paths(paths: Iterable[Path]) -> None:
    print("Analysis complete.")
    for path in paths:
        print(path)


def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _print_analyze_usage() -> None:
    print("Usage: analyze file <path> | analyze code --text <text> | analyze evidence --text <text>", file=sys.stderr)


def _print_live_usage() -> None:
    print("Usage: live start [--pid ...] [--process-name ...] [--window-title ...] [--duration ...]", file=sys.stderr)


def _print_memory_usage() -> None:
    print("Usage: memory read --pid ... --address ... [--size ...]", file=sys.stderr)


def _infer_legacy_command(argv: list[str]) -> str:
    if "--memory-pid" in argv or "--memory-address" in argv:
        return "memory"
    if "--live" in argv:
        return "live"
    if "--gui" in argv:
        return "gui"
    return "analyze"
