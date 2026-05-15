from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reverse_framework.api import (
    analyze_and_write_reports,
    analyze_code_text_and_write_reports,
    analyze_execution_evidence_and_write_reports,
    analyze_process_memory_and_write_reports,
    available_analyzers,
    build_pipeline,
    stream_live_kernel_events,
)
from reverse_framework.core.config import TriageConfig, load_config
from reverse_framework.core.process_lookup import resolve_process_candidate
from reverse_framework.core.pipeline import AnalysisPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse-tools",
        description="Run a first-pass reverse engineering triage workflow on an executable or file, or launch the GUI.",
    )
    parser.add_argument("target", type=Path, nargs="?", help="Executable or file to analyze.")
    parser.add_argument(
        "--code-text",
        help="Analyze pasted decompiler, assembly, or IR text instead of a file.",
    )
    parser.add_argument(
        "--code-name",
        default="analysis-input.txt",
        help="Logical name used for code-text analysis.",
    )
    parser.add_argument(
        "--evidence-text",
        help="Analyze execution trace, syscall, memory, or IO evidence text.",
    )
    parser.add_argument(
        "--evidence-name",
        default="execution-evidence",
        help="Logical name used for execution evidence analysis.",
    )
    parser.add_argument(
        "--static-code",
        help="Optional static code to compare against the execution evidence.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports"),
        help="Report output directory.",
    )
    parser.add_argument(
        "--format",
        choices=["all", "json", "markdown"],
        default="all",
        help="Report format.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("reverse-tools.json"),
        help="Optional JSON config file.",
    )
    parser.add_argument(
        "--analyzers",
        help="Comma-separated analyzer list.",
    )
    parser.add_argument(
        "--list-analyzers",
        action="store_true",
        help="List built-in analyzers and exit.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Tk interface.",
    )
    parser.add_argument(
        "--min-string",
        type=int,
        default=None,
        help="Override minimum printable string length.",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=None,
        help="Override maximum strings to keep in the report.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Stream live Windows kernel events instead of analyzing a file.",
    )
    parser.add_argument(
        "--live-duration",
        type=int,
        default=0,
        help="Live capture duration in seconds; 0 means until interrupted.",
    )
    parser.add_argument(
        "--live-pid",
        type=int,
        default=None,
        help="Optional process ID filter for live mode.",
    )
    parser.add_argument(
        "--process-name",
        help="Resolve a running process name to a PID for live or memory modes.",
    )
    parser.add_argument(
        "--window-title",
        help="Resolve a visible window title to a PID for live or memory modes.",
    )
    parser.add_argument(
        "--memory-pid",
        type=int,
        default=None,
        help="Read memory from this live process ID.",
    )
    parser.add_argument(
        "--memory-address",
        help="Memory address to read, in hex or decimal form.",
    )
    parser.add_argument(
        "--memory-size",
        type=int,
        default=64,
        help="Number of bytes to read from the address.",
    )
    parser.add_argument(
        "--process-memory-path",
        help="Optional path to the native process memory reader.",
    )
    return parser


def default_pipeline(config: TriageConfig | None = None) -> AnalysisPipeline:
    return build_pipeline(config)


def _resolve_dynamic_pid(pid: int | None, process_name: str | None, window_title: str | None) -> int | None:
    candidate = resolve_process_candidate(pid=pid, process_name=process_name, window_title=window_title)
    return None if candidate is None else candidate.pid


def launch_gui() -> int:
    try:
        from reverse_framework.gui import main as gui_main
    except Exception as exc:
        print(f"GUI unavailable: {exc}", file=sys.stderr)
        return 2

    return gui_main()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        return launch_gui()

    if args.code_text is not None and args.evidence_text is not None:
        print("Choose only one of --code-text or --evidence-text.")
        return 2

    has_memory_mode = args.memory_pid is not None or args.memory_address is not None
    if has_memory_mode and (
        args.code_text is not None
        or args.evidence_text is not None
        or args.live
        or args.list_analyzers
        or args.target is not None
    ):
        print("Choose only one of --code-text, --evidence-text, --memory-pid, --live, or --list-analyzers.")
        return 2

    if args.live:
        if args.target is not None:
            print("Live mode ignores the target path.", file=sys.stderr)
        try:
            live_pid = _resolve_dynamic_pid(args.live_pid, args.process_name, args.window_title)
            for event in stream_live_kernel_events(
                process_id=live_pid,
                duration_seconds=args.live_duration or None,
            ):
                print(json.dumps(event.to_dict(), ensure_ascii=False))
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"Live monitor error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.code_text is not None:
        try:
            config = load_config(args.config)
            if args.min_string is not None:
                config.min_string = args.min_string
            if args.max_strings is not None:
                config.max_strings = args.max_strings
        except Exception as exc:
            print(f"Configuration error: {exc}")
            return 2

        selected_analyzers = _parse_analyzers(args.analyzers)
        _, written = analyze_code_text_and_write_reports(
            args.code_text,
            out_dir=args.out,
            report_format=args.format,
            target_name=args.code_name,
            config=config,
            analyzers=selected_analyzers,
        )
        print("Analysis complete.")
        for path in written:
            print(path)
        return 0

    if args.evidence_text is not None:
        try:
            config = load_config(args.config)
            if args.min_string is not None:
                config.min_string = args.min_string
            if args.max_strings is not None:
                config.max_strings = args.max_strings
        except Exception as exc:
            print(f"Configuration error: {exc}")
            return 2

        selected_analyzers = _parse_analyzers(args.analyzers)
        _, written = analyze_execution_evidence_and_write_reports(
            args.evidence_text,
            out_dir=args.out,
            report_format=args.format,
            static_code=args.static_code,
            target_name=args.evidence_name,
            config=config,
            analyzers=selected_analyzers,
        )
        print("Analysis complete.")
        for path in written:
            print(path)
        return 0

    if has_memory_mode:
        if args.memory_address is None:
            print("Choose --memory-address for memory mode.")
            return 2

        try:
            config = load_config(args.config)
            if args.min_string is not None:
                config.min_string = args.min_string
            if args.max_strings is not None:
                config.max_strings = args.max_strings
            if args.process_memory_path is not None:
                config.process_memory_path = args.process_memory_path
            if args.process_name is not None or args.window_title is not None:
                memory_pid = _resolve_dynamic_pid(args.memory_pid, args.process_name, args.window_title)
            else:
                memory_pid = args.memory_pid
            if memory_pid is None:
                print("Choose --memory-pid, --process-name, or --window-title.")
                return 2
            config.process_memory_pid = memory_pid
            config.process_memory_address = args.memory_address
            config.process_memory_size = args.memory_size
        except Exception as exc:
            print(f"Configuration error: {exc}")
            return 2

        selected_analyzers = _parse_analyzers(args.analyzers)
        _, written = analyze_process_memory_and_write_reports(
            memory_pid,
            args.memory_address,
            size=args.memory_size,
            out_dir=args.out,
            report_format=args.format,
            config=config,
            analyzers=selected_analyzers,
        )
        print("Analysis complete.")
        for path in written:
            print(path)
        return 0

    if args.list_analyzers:
        for name in available_analyzers():
            print(name)
        return 0

    if args.target is None:
        print("Target is required unless --list-analyzers is used.")
        return 2

    target = args.target.resolve()

    if not target.exists():
        print(f"Target not found: {target}")
        return 2

    if not target.is_file():
        print(f"Target is not a file: {target}")
        return 2

    try:
        config = load_config(args.config)
        if args.min_string is not None:
            config.min_string = args.min_string
        if args.max_strings is not None:
            config.max_strings = args.max_strings
    except Exception as exc:
        print(f"Configuration error: {exc}")
        return 2

    selected_analyzers = _parse_analyzers(args.analyzers)
    result, written = analyze_and_write_reports(
        target=target,
        out_dir=args.out,
        report_format=args.format,
        config=config,
        analyzers=selected_analyzers,
    )

    print("Analysis complete.")
    for path in written:
        print(path)
    return 0


def _parse_analyzers(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
