from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverse_framework.analyzers.code_structure import CodeStructureAnalyzer, INPUT_SOURCE_APIS
from reverse_framework.core.addressing import format_address, parse_int_value
from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding


def _symbol_name(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return re.sub(r"^[%@]+", "", text).strip().lower().strip("_")


SOURCE_NAME_TO_KIND = {
    _symbol_name(name): kind
    for kind, names in INPUT_SOURCE_APIS.items()
    for name in names
}

CALLLIKE_RE = re.compile(r"^(?:call|enter|invoke|->)\s+(?P<name>[A-Za-z_.$?@][\w.$?@<>~\-]*)")
SYSCALL_RE = re.compile(r"^(?:syscall|int\s+0x2e|int\s+2eh)\s*(?P<name>[A-Za-z_.$?@][\w.$?@<>~\-]*)?", re.I)
MEMORY_RE = re.compile(
    r"^(?P<kind>read|write|load|store|mem\s+read|mem\s+write|memory\s+read|memory\s+write)"
    r"(?:[^0-9A-Za-z_@%$]+(?P<addr>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|\d+))?"
    r"(?:[^0-9A-Za-z_@%$]+(?P<value>.+))?$",
    re.I,
)
IO_RE = re.compile(
    r"^(?:io|input)\s*[:=]\s*(?P<input>.+?)(?:\s*(?:->|=>|=>)\s*(?P<output>.+))?$",
    re.I,
)
STATE_RE = re.compile(
    r"^(?:state|reg|register|flag|var)\s*(?P<name>[A-Za-z_.$?@][\w.$?@<>~\-]*)?\s*[:=]?\s*(?P<before>.+?)\s*->\s*(?P<after>.+)$",
    re.I,
)
BRANCH_RE = re.compile(
    r"^(?:branch|cond|guard)\s*(?P<condition>.+?)(?:\s*(?:->|=>)\s*(?P<target>.+))?$",
    re.I,
)


@dataclass(slots=True)
class RuntimeEvent:
    index: int
    kind: str
    line: int | None = None
    function: str | None = None
    syscall: str | None = None
    address: int | None = None
    address_hint: str | None = None
    value: str | None = None
    input_value: str | None = None
    output_value: str | None = None
    before: str | None = None
    after: str | None = None
    condition: str | None = None
    taken: bool | None = None
    target: str | None = None
    source: str | None = None
    destination: str | None = None
    label: str | None = None
    sources: list[str] = field(default_factory=list)
    raw: Any = field(default_factory=dict)

    def node_id(self) -> str:
        if self.kind == "call":
            return f"call:{_symbol_name(self.function or self.label or f'event-{self.index}')}"
        if self.kind == "syscall":
            return f"syscall:{_symbol_name(self.syscall or self.label or f'event-{self.index}')}"
        if self.kind == "memory":
            return f"memory:{_symbol_name(self.address_hint or self.label or self.address_label() or f'event-{self.index}')}"
        if self.kind == "io":
            return f"io:{self.index}"
        if self.kind == "state":
            return f"state:{_symbol_name(self.label or self.source or f'event-{self.index}')}"
        if self.kind == "branch":
            return f"branch:{_symbol_name(self.condition or self.target or f'event-{self.index}')}"
        if self.kind == "input":
            return f"input:{self.index}"
        return f"{self.kind}:{self.index}"

    def address_label(self) -> str | None:
        return format_address(self.address) if self.address is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "line": self.line,
            "node_id": self.node_id(),
            "function": self.function,
            "syscall": self.syscall,
            "address": self.address_label(),
            "address_hint": self.address_hint,
            "value": self.value,
            "input_value": self.input_value,
            "output_value": self.output_value,
            "before": self.before,
            "after": self.after,
            "condition": self.condition,
            "taken": self.taken,
            "target": self.target,
            "source": self.source,
            "destination": self.destination,
            "label": self.label,
            "sources": list(self.sources),
            "raw": self.raw,
        }


@dataclass(slots=True)
class ExecutionBundle:
    raw_text: str | None = None
    static_code: str | None = None
    static_report: dict[str, Any] | None = None
    events: list[RuntimeEvent] = field(default_factory=list)


class ExecutionTraceAnalyzer:
    name = "execution_trace"

    def run(self, context: AnalysisContext) -> None:
        bundle = _load_bundle(context.read_bytes())
        if bundle is None:
            return

        if not bundle.events and not bundle.raw_text and not bundle.static_code and not bundle.static_report:
            return

        runtime = _build_runtime_model(bundle)
        static_baseline = _build_static_baseline(bundle, context)
        exec_flow = _build_exec_flow(runtime, static_baseline)
        state = _build_state(runtime)
        dataflow = _build_dataflow(runtime, static_baseline, state)
        diff = _build_diff(exec_flow, state, dataflow, static_baseline)
        exec_model = _build_exec_model(runtime, static_baseline, exec_flow, state, dataflow, diff)
        memory_model = _build_memory_model(runtime, dataflow)
        state_transition = _build_state_transition(runtime, state)
        uncertainty = _build_uncertainty(runtime, static_baseline, exec_flow, state, dataflow, diff)

        context.add_finding(
            self.name,
            {
                "EXEC_FLOW": exec_flow,
                "STATE": state,
                "DATAFLOW": dataflow,
                "DIFF": diff,
                "EXEC_MODEL": exec_model,
                "MEMORY_MODEL": memory_model,
                "STATE_TRANSITION": state_transition,
                "UNCERTAINTY": uncertainty,
            },
        )

        if diff["difference_score"] >= 60:
            context.add_issue(
                Finding(
                    id="execution_static_mismatch",
                    title="Execution diverges from static prediction",
                    severity="medium" if diff["difference_score"] < 80 else "high",
                    category="execution",
                    summary="The runtime trace does not fully match the static control or data flow model.",
                    confidence=diff["confidence"],
                    evidence={
                        "difference_score": diff["difference_score"],
                        "hidden_paths": diff["hidden_paths"][:8],
                        "runtime_only_paths": diff["runtime_only_paths"][:8],
                    },
                    tags=["execution", "diff", "trace"],
                    recommendation="Review the hidden static paths and runtime-only transitions side by side.",
                )
            )


def _load_bundle(data: bytes) -> ExecutionBundle | None:
    text = _decode_text(data)
    if text is None:
        return None

    stripped = text.strip()
    if not stripped:
        return None

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return ExecutionBundle(raw_text=text, events=_parse_runtime_text(text))

    if isinstance(payload, list):
        return ExecutionBundle(events=_normalize_event_list(payload))

    if isinstance(payload, dict):
        bundle = ExecutionBundle(
            raw_text=_coerce_text(
                payload.get("raw_text")
                or payload.get("trace_text")
                or payload.get("runtime_text")
                or payload.get("text")
            ),
            static_code=_coerce_text(
                payload.get("static_code")
                or payload.get("code")
                or payload.get("static_text")
                or payload.get("static_source")
            ),
            static_report=payload.get("static_report") if isinstance(payload.get("static_report"), dict) else None,
        )

        if _looks_like_event_object(payload):
            bundle.events.append(_normalize_event(payload, 1))
        else:
            bundle.events.extend(_collect_events_from_mapping(payload))

        if bundle.raw_text is not None and not bundle.events:
            bundle.events.extend(_parse_runtime_text(bundle.raw_text))
        return bundle

    return None


def _build_runtime_model(bundle: ExecutionBundle) -> dict[str, Any]:
    events = bundle.events
    ordered_events = [event.to_dict() for event in events]
    sources: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    state_changes: list[dict[str, Any]] = []
    call_sequence: list[str] = []
    syscall_sequence: list[str] = []
    memory_accesses: list[dict[str, Any]] = []
    io_pairs: list[dict[str, Any]] = []
    branch_events: list[dict[str, Any]] = []
    return_events: list[dict[str, Any]] = []
    exception_events: list[dict[str, Any]] = []
    active_sources: list[str] = []
    taint_sources: dict[str, str] = {}

    for event in events:
        event_sources = _event_sources(event)
        node_id = event.node_id()
        if not event_sources and _is_source_event(event):
            event_sources = [event.node_id()]

        if event.kind == "call" and event.function:
            call_sequence.append(event.function)
        elif event.kind == "syscall" and event.syscall:
            syscall_sequence.append(event.syscall)
        elif event.kind == "memory":
            memory_accesses.append(
                {
                    "index": event.index,
                    "node_id": node_id,
                    "kind": _memory_access_kind(event),
                    "address": event.address_label(),
                    "address_hint": event.address_hint,
                    "value": event.value,
                    "sources": list(event_sources),
                    "source": event.source,
                    "raw": event.raw,
                }
            )
        elif event.kind == "io":
            io_pairs.append(
                {
                    "index": event.index,
                    "node_id": node_id,
                    "input": event.input_value,
                    "output": event.output_value,
                    "sources": list(event_sources),
                    "raw": event.raw,
                }
            )
        elif event.kind == "branch":
            branch_events.append(
                {
                    "index": event.index,
                    "node_id": node_id,
                    "condition": event.condition,
                    "taken": event.taken,
                    "target": event.target,
                    "sources": list(event_sources),
                    "raw": event.raw,
                }
            )
        elif event.kind == "return":
            return_events.append({"index": event.index, "source": event.source, "raw": event.raw})
        elif event.kind == "exception":
            exception_events.append({"index": event.index, "source": event.source, "raw": event.raw})

        if event_sources:
            for source_id in event_sources:
                paths.append(
                    {
                        "from": source_id,
                        "to": node_id,
                        "kind": event.kind,
                        "line": event.line,
                        "source": event.source,
                    }
                )

        if _is_source_event(event):
            source_kind, source_name = _classify_source_event(event)
            source_id = _source_id(source_kind, source_name, event.index)
            sources.append(
                {
                    "id": source_id,
                    "kind": source_kind,
                    "name": source_name,
                    "event": event.kind,
                    "line": event.line,
                    "label": event.label,
                    "raw": event.raw,
                }
            )
            active_sources.append(source_id)
            taint_sources[_symbol_name(source_name)] = source_id
            event_sources = _merge_sources(event_sources, [source_id])

        if event.kind in {"memory", "io", "state", "branch"}:
            if event.kind == "memory" and event.address is not None:
                taint_name = event.address_label() or f"memory:{event.index}"
                taint_sources[_symbol_name(taint_name)] = node_id
            elif event.kind == "io":
                taint_name = event.input_value or event.output_value or f"io:{event.index}"
                taint_sources[_symbol_name(taint_name)] = node_id
            elif event.kind == "state":
                taint_name = event.label or event.source or f"state:{event.index}"
                taint_sources[_symbol_name(taint_name)] = node_id
            elif event.kind == "branch":
                taint_name = event.condition or event.target or f"branch:{event.index}"
                taint_sources[_symbol_name(taint_name)] = node_id

        if event_sources:
            active_sources = _merge_sources(active_sources, event_sources)
        elif event.kind in {"call", "syscall", "memory", "io", "state", "branch"} and active_sources:
            event_sources = list(active_sources[-3:])
            for source_id in event_sources:
                paths.append(
                    {
                        "from": source_id,
                        "to": node_id,
                        "kind": event.kind,
                        "line": event.line,
                        "source": event.source,
                    }
                )

        if event.kind in {"memory", "io", "state"} and node_id not in active_sources:
            active_sources = _merge_sources(active_sources, [node_id])

        if event.kind == "call" and event.function and _classify_source_name(event.function):
            source_kind = _classify_source_name(event.function)
            source_id = _source_id(source_kind, event.function, event.index)
            if source_id not in active_sources:
                active_sources.append(source_id)

        if event.kind == "syscall" and event.syscall and _classify_source_name(event.syscall):
            source_kind = _classify_source_name(event.syscall)
            source_id = _source_id(source_kind, event.syscall, event.index)
            if source_id not in active_sources:
                active_sources.append(source_id)

        if event.kind == "memory" and event.value and event.address is not None:
            before_after = _extract_transition(event.value)
            if before_after is not None:
                before, after = before_after
            else:
                before, after = None, event.value
            state_changes.append(
                {
                    "key": f"memory[{event.address_label()}]",
                    "kind": "memory_write" if _memory_event_is_write(event) else "memory_read",
                    "before": before,
                    "after": after,
                    "triggered_by": list(event_sources or active_sources[-3:]),
                    "line": event.line,
                    "source": event.source,
                }
            )

        if event.kind == "io":
            state_changes.append(
                {
                    "key": f"io[{event.input_value or event.index}]",
                    "kind": "io_pair",
                    "before": event.input_value,
                    "after": event.output_value,
                    "triggered_by": list(event_sources or active_sources[-3:]),
                    "line": event.line,
                    "source": event.source,
                }
            )

        if event.kind == "state":
            state_changes.append(
                {
                    "key": event.label or event.source or f"state[{event.index}]",
                    "kind": "state_transition",
                    "before": event.before,
                    "after": event.after,
                    "triggered_by": list(event_sources or active_sources[-3:]),
                    "line": event.line,
                    "source": event.source,
                }
            )

        if event.kind == "branch":
            state_changes.append(
                {
                    "key": f"branch[{event.condition or event.target or event.index}]",
                    "kind": "branch_transition",
                    "before": "pending",
                    "after": "taken" if event.taken else "not_taken" if event.taken is not None else event.target,
                    "triggered_by": list(event_sources or active_sources[-3:]),
                    "line": event.line,
                    "source": event.source,
                }
            )

    return {
        "events": ordered_events,
        "sources": sources,
        "paths": _dedupe_records(paths),
        "state_changes": state_changes,
        "call_sequence": call_sequence,
        "syscall_sequence": syscall_sequence,
        "memory_accesses": memory_accesses,
        "io_pairs": io_pairs,
        "branch_events": branch_events,
        "return_events": return_events,
        "exception_events": exception_events,
        "taint_sources": taint_sources,
    }


def _build_static_baseline(bundle: ExecutionBundle, context: AnalysisContext) -> dict[str, Any]:
    report = bundle.static_report
    code_structure = _extract_code_structure(report)

    if code_structure is None and bundle.static_code:
        static_context = AnalysisContext(
            target=Path("static-code.txt"),
            config=context.config,
            data=bundle.static_code.encode("utf-8"),
        )
        CodeStructureAnalyzer().run(static_context)
        code_structure = static_context.findings.get("code_structure") or None

    if code_structure is None:
        return {
            "available": False,
            "source": None,
            "code_structure": None,
            "cfg": {},
            "dfg": {},
            "call": {},
            "semantics": {},
            "summary": "Static baseline was not provided.",
        }

    cfg = code_structure.get("CFG", {}) if isinstance(code_structure, dict) else {}
    dfg = code_structure.get("DFG", {}) if isinstance(code_structure, dict) else {}
    call = code_structure.get("CALL", {}) if isinstance(code_structure, dict) else {}
    semantics = code_structure.get("SEMANTICS", {}) if isinstance(code_structure, dict) else {}

    return {
        "available": True,
        "source": "static_report" if report is not None else "static_code",
        "code_structure": code_structure,
        "cfg": cfg,
        "dfg": dfg,
        "call": call,
        "semantics": semantics,
        "summary": _static_summary(code_structure),
    }


def _build_exec_flow(runtime: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    static_cfg = baseline.get("cfg") or {}
    static_call = baseline.get("call") or {}
    execution_path = _reconstruct_execution_path(runtime.get("events", []))

    static_functions = _unique_strings(
        [item.get("callee") for item in static_call.get("calls", []) if isinstance(item, dict)]
    )
    observed_functions = _unique_strings(runtime.get("call_sequence", []))
    observed_syscalls = _unique_strings(runtime.get("syscall_sequence", []))
    observed_memory = runtime.get("memory_accesses", [])
    observed_io = runtime.get("io_pairs", [])
    observed_branches = runtime.get("branch_events", [])
    observed_returns = runtime.get("return_events", [])
    observed_exceptions = runtime.get("exception_events", [])

    static_branch_paths = static_cfg.get("branch_paths", []) if isinstance(static_cfg, dict) else []
    observed_branch_signatures = _branch_signatures(observed_branches)
    hidden_static_paths = [
        item
        for item in static_branch_paths
        if _branch_signature(item) not in observed_branch_signatures
    ]
    observed_branch_targets = _unique_strings(
        [item.get("target") or item.get("condition") for item in observed_branches if isinstance(item, dict)]
    )
    runtime_only_branch_paths = [
        item
        for item in observed_branches
        if _branch_signature(item) not in {_branch_signature(path) for path in static_branch_paths}
    ]

    return {
        "actual_execution": {
            "function_sequence": observed_functions,
            "syscall_sequence": observed_syscalls,
            "memory_accesses": observed_memory,
            "io_pairs": observed_io,
            "branches": observed_branches,
            "returns": observed_returns,
            "exceptions": observed_exceptions,
            "execution_path": execution_path["path"],
            "call_stack_frames": execution_path["frames"],
            "call_edges": execution_path["edges"],
            "execution_segments": execution_path["segments"],
            "phase_sequence": execution_path["phase_sequence"],
            "max_call_depth": execution_path["max_depth"],
        },
        "static_cfg_diff": {
            "baseline_available": bool(baseline.get("available")),
            "static_functions": static_functions,
            "observed_functions": observed_functions,
            "missing_static_functions": [item for item in static_functions if item not in observed_functions],
            "runtime_only_functions": [item for item in observed_functions if item not in static_functions],
            "static_branch_paths": _compact_static_paths(static_branch_paths),
            "observed_branch_paths": observed_branches,
            "observed_branch_targets": observed_branch_targets,
            "hidden_static_paths": hidden_static_paths,
            "runtime_only_branch_paths": runtime_only_branch_paths,
            "function_coverage": _coverage_ratio(static_functions, observed_functions),
            "branch_coverage": _coverage_ratio(
                [_branch_signature(item) for item in static_branch_paths],
                list(observed_branch_signatures),
            ),
            "path_signature": execution_path["signature"],
        },
    }


def _reconstruct_execution_path(events: list[dict[str, Any]]) -> dict[str, Any]:
    path: list[dict[str, Any]] = []
    frames: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    segments: list[dict[str, Any]] = []
    call_stack: list[dict[str, Any]] = []
    max_depth = 0

    for event in events:
        kind = str(event.get("kind") or "event")
        phase = _execution_phase(kind, event)
        node_id = str(event.get("node_id") or f"{kind}:{event.get('index', len(path) + 1)}")
        current_depth = len(call_stack)
        record = {
            "index": event.get("index"),
            "kind": kind,
            "phase": phase,
            "node_id": node_id,
            "depth": current_depth,
            "function": event.get("function"),
            "syscall": event.get("syscall"),
            "address": event.get("address"),
            "address_hint": event.get("address_hint"),
            "input_value": event.get("input_value"),
            "output_value": event.get("output_value"),
            "before": event.get("before"),
            "after": event.get("after"),
            "condition": event.get("condition"),
            "target": event.get("target"),
            "taken": event.get("taken"),
            "label": event.get("label"),
            "source": event.get("source"),
            "destination": event.get("destination"),
        }

        if kind == "call":
            callee = event.get("function") or event.get("label") or node_id
            caller = call_stack[-1]["function"] if call_stack else "entry"
            frame = {
                "function": callee,
                "caller": caller,
                "entry_index": event.get("index"),
                "entry_node": node_id,
                "depth": current_depth,
                "role": _function_role(callee),
            }
            call_stack.append(frame)
            frames.append({**frame, "kind": "call"})
            edges.append(
                {
                    "from": caller,
                    "to": callee,
                    "kind": "call",
                    "index": event.get("index"),
                    "depth": current_depth + 1,
                }
            )
            record["caller"] = caller
            record["callee"] = callee
            record["depth_after"] = len(call_stack)
            max_depth = max(max_depth, len(call_stack))
        elif kind == "return":
            frame = call_stack.pop() if call_stack else None
            record["callee"] = frame["function"] if frame else None
            record["return_to"] = call_stack[-1]["function"] if call_stack else "entry"
            record["depth_after"] = len(call_stack)
            if frame is None:
                record["unmatched_return"] = True
            else:
                frames.append(
                    {
                        "kind": "return",
                        "function": frame["function"],
                        "return_to": record["return_to"],
                        "index": event.get("index"),
                        "node_id": node_id,
                        "depth": len(call_stack),
                    }
                )
        elif kind == "exception":
            record["unwound_from"] = call_stack[-1]["function"] if call_stack else None
            record["depth_after"] = len(call_stack)

        path.append(record)

    segments = _segment_execution_path(path)
    return {
        "path": path,
        "frames": frames,
        "edges": edges,
        "segments": segments,
        "phase_sequence": [item.get("phase") for item in path],
        "signature": [item.get("node_id") for item in path],
        "max_depth": max_depth,
    }


def _segment_execution_path(path: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not path:
        return []

    segments: list[dict[str, Any]] = []
    current = {
        "phase": path[0].get("phase"),
        "start_index": path[0].get("index"),
        "end_index": path[0].get("index"),
        "nodes": [path[0].get("node_id")],
        "kinds": [path[0].get("kind")],
        "depth_range": [path[0].get("depth"), path[0].get("depth_after", path[0].get("depth"))],
    }

    for item in path[1:]:
        same_phase = item.get("phase") == current["phase"]
        same_kind = item.get("kind") == current["kinds"][-1]
        if not same_phase or not same_kind:
            segments.append(
                {
                    "phase": current["phase"],
                    "start_index": current["start_index"],
                    "end_index": current["end_index"],
                    "nodes": _unique_strings(current["nodes"]),
                    "kinds": _unique_strings(current["kinds"]),
                    "depth_range": current["depth_range"],
                }
            )
            current = {
                "phase": item.get("phase"),
                "start_index": item.get("index"),
                "end_index": item.get("index"),
                "nodes": [item.get("node_id")],
                "kinds": [item.get("kind")],
                "depth_range": [item.get("depth"), item.get("depth_after", item.get("depth"))],
            }
            continue

        current["end_index"] = item.get("index")
        current["nodes"].append(item.get("node_id"))
        current["kinds"].append(item.get("kind"))
        current["depth_range"][1] = item.get("depth_after", item.get("depth"))

    segments.append(
        {
            "phase": current["phase"],
            "start_index": current["start_index"],
            "end_index": current["end_index"],
            "nodes": _unique_strings(current["nodes"]),
            "kinds": _unique_strings(current["kinds"]),
            "depth_range": current["depth_range"],
        }
    )
    return segments


def _execution_phase(kind: str, event: dict[str, Any]) -> str:
    if kind == "call":
        role = _function_role(event.get("function") or event.get("label"))
        if "input source" in role:
            return "ingest"
        if "memory creation" in role:
            return "allocate"
        if "resource destruction" in role:
            return "release"
        if "output or persistence" in role:
            return "emit"
        if "data transformation" in role:
            return "transform"
        return "dispatch"
    if kind == "syscall":
        return "kernel_boundary"
    if kind == "memory":
        return "memory_write" if _memory_access_kind_from_dict(event) == "write" else "memory_read"
    if kind == "io":
        return "input_output"
    if kind == "state":
        return "state_transition"
    if kind == "branch":
        return "decision"
    if kind == "return":
        return "return"
    if kind == "exception":
        return "exception"
    return "event"


def _memory_access_kind_from_dict(event: dict[str, Any]) -> str:
    label = str(event.get("label") or "").lower()
    if "write" in label or "store" in label:
        return "write"
    if "read" in label or "load" in label:
        return "read"
    return "write" if event.get("value") is not None else "read"


def _build_state(runtime: dict[str, Any]) -> dict[str, Any]:
    changes = runtime.get("state_changes", [])
    input_triggers = {}
    switch_points = []
    for change in changes:
        triggered_by = change.get("triggered_by") or []
        if change.get("before") != change.get("after"):
            switch_points.append(
                {
                    "key": change.get("key"),
                    "kind": change.get("kind"),
                    "before": change.get("before"),
                    "after": change.get("after"),
                    "triggered_by": triggered_by,
                    "line": change.get("line"),
                    "source": change.get("source"),
                }
            )
        for source_id in triggered_by:
            input_triggers.setdefault(source_id, []).append(change.get("key"))

    return {
        "state_changes": changes,
        "switch_points": switch_points,
        "input_triggers": [
            {"input": source_id, "state_keys": _unique_strings(keys)}
            for source_id, keys in input_triggers.items()
        ],
        "state_change_count": len(changes),
        "switch_count": len(switch_points),
    }


def _build_dataflow(runtime: dict[str, Any], baseline: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    observed_sources = runtime.get("sources", [])
    observed_paths = runtime.get("paths", [])
    static_dfg = baseline.get("dfg") or {}
    static_sources = static_dfg.get("input_sources", []) if isinstance(static_dfg, dict) else []
    static_paths = static_dfg.get("key_variable_influence_paths", []) if isinstance(static_dfg, dict) else []

    matched_static_sources, unmatched_static_sources = _match_static_sources(static_sources, observed_sources)
    triggered_static_paths, untriggered_static_paths = _match_static_paths(static_paths, matched_static_sources)
    propagation_chains = _build_propagation_chains(observed_paths)
    matched_observed_source_ids = {
        str(entry.get("matched_by", {}).get("id"))
        for entry in matched_static_sources
        if isinstance(entry, dict) and isinstance(entry.get("matched_by"), dict)
    }
    runtime_only_sources = [
        item for item in observed_sources if str(item.get("id")) not in matched_observed_source_ids
    ]

    observed_path_nodes = [
        {
            "from": item.get("from"),
            "to": item.get("to"),
            "kind": item.get("kind"),
            "line": item.get("line"),
            "source": item.get("source"),
        }
        for item in observed_paths
    ]

    return {
        "observed_sources": observed_sources,
        "observed_paths": observed_path_nodes,
        "propagation_chains": propagation_chains,
        "triggered_static_sources": matched_static_sources,
        "runtime_only_sources": runtime_only_sources,
        "triggered_static_paths": triggered_static_paths,
        "untriggered_static_paths": untriggered_static_paths,
        "unmatched_static_sources": unmatched_static_sources,
        "validation": {
            "matched_source_count": len(matched_static_sources),
            "unmatched_source_count": len(unmatched_static_sources),
            "triggered_path_count": len(triggered_static_paths),
            "untriggered_path_count": len(untriggered_static_paths),
            "state_trigger_count": len(state.get("input_triggers", [])),
            "source_coverage": _coverage_ratio(
                [_source_coverage_key(item) for item in static_sources if isinstance(item, dict)],
                [_source_coverage_key(item) for item in observed_sources if isinstance(item, dict)],
            ),
            "path_coverage": _coverage_ratio(
                [str(item.get("line") or item.get("source")) for item in static_paths if isinstance(item, dict)],
                [str(item.get("line") or item.get("source")) for item in observed_paths if isinstance(item, dict)],
            ),
        },
    }


def _build_diff(
    exec_flow: dict[str, Any],
    state: dict[str, Any],
    dataflow: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    baseline_available = bool(baseline.get("available"))
    static_cfg = baseline.get("cfg") or {}
    static_dfg = baseline.get("dfg") or {}
    static_call = baseline.get("call") or {}
    static_semantics = baseline.get("semantics") or {}

    static_functions = _unique_strings(
        [item.get("callee") for item in static_call.get("calls", []) if isinstance(item, dict)]
    )
    observed_functions = exec_flow.get("actual_execution", {}).get("function_sequence", [])
    runtime_only_functions = [item for item in observed_functions if item not in static_functions]
    missing_static_functions = [item for item in static_functions if item not in observed_functions]

    hidden_paths = list(exec_flow.get("static_cfg_diff", {}).get("hidden_static_paths", []))
    hidden_paths.extend(dataflow.get("untriggered_static_paths", []))
    hidden_paths.extend(dataflow.get("unmatched_static_sources", []))
    hidden_paths.extend(exec_flow.get("static_cfg_diff", {}).get("runtime_only_branch_paths", []))

    runtime_only_paths = []
    if runtime_only_functions:
        runtime_only_paths.extend(
            {"kind": "runtime_only_function", "value": name} for name in runtime_only_functions
        )
    if exec_flow.get("actual_execution", {}).get("syscall_sequence"):
        observed_syscalls = exec_flow["actual_execution"]["syscall_sequence"]
        static_sources = _static_source_names(static_dfg)
        for syscall in observed_syscalls:
            if syscall not in static_sources:
                runtime_only_paths.append({"kind": "runtime_only_syscall", "value": syscall})
    for item in exec_flow.get("static_cfg_diff", {}).get("runtime_only_branch_paths", []):
        runtime_only_paths.append({"kind": "runtime_only_branch", "value": _branch_signature(item)})

    differences = []
    for name in missing_static_functions:
        differences.append({"kind": "missing_static_function", "value": name})
    for name in runtime_only_functions:
        differences.append({"kind": "runtime_only_function", "value": name})
    for item in hidden_paths[:40]:
        differences.append({"kind": "hidden_static_path", "value": _compact_value(item)})
    for item in state.get("switch_points", []):
        if not item.get("triggered_by"):
            differences.append({"kind": "unattributed_state_change", "value": item.get("key")})

    difference_score = _diff_score(hidden_paths, runtime_only_paths, differences)
    confidence = min(0.95, 0.45 + difference_score / 200)

    static_prediction = {
        "available": baseline_available,
        "summary": baseline.get("summary"),
        "functions": static_functions,
        "sources": _static_source_names(static_dfg),
        "semantics": static_semantics,
        "function_coverage": exec_flow.get("static_cfg_diff", {}).get("function_coverage"),
        "branch_coverage": exec_flow.get("static_cfg_diff", {}).get("branch_coverage"),
    }
    actual_execution = {
        "functions": observed_functions,
        "syscalls": exec_flow.get("actual_execution", {}).get("syscall_sequence", []),
        "state_change_count": state.get("state_change_count", 0),
        "source_count": len(dataflow.get("observed_sources", [])),
        "path_length": len(exec_flow.get("actual_execution", {}).get("execution_path", [])),
        "branch_count": len(exec_flow.get("actual_execution", {}).get("branches", [])),
        "memory_access_count": len(exec_flow.get("actual_execution", {}).get("memory_accesses", [])),
        "max_call_depth": exec_flow.get("actual_execution", {}).get("max_call_depth", 0),
        "path_signature": exec_flow.get("static_cfg_diff", {}).get("path_signature", []),
    }

    return {
        "baseline_status": "available" if baseline_available else "missing",
        "static_prediction": static_prediction,
        "actual_execution": actual_execution,
        "differences": differences,
        "hidden_paths": hidden_paths,
        "runtime_only_paths": runtime_only_paths,
        "difference_score": difference_score,
        "confidence": round(confidence, 2),
        "notes": (
            "Static baseline is unavailable."
            if not baseline_available
            else "Comparison is based on the provided static control and data flow summary."
        ),
    }


def _build_exec_model(
    runtime: dict[str, Any],
    baseline: dict[str, Any],
    exec_flow: dict[str, Any],
    state: dict[str, Any],
    dataflow: dict[str, Any],
    diff: dict[str, Any],
) -> dict[str, Any]:
    actual = exec_flow.get("actual_execution", {})
    functions = actual.get("function_sequence", [])
    syscalls = actual.get("syscall_sequence", [])
    branches = actual.get("branches", [])
    returns = actual.get("returns", [])
    exceptions = actual.get("exceptions", [])
    sources = dataflow.get("observed_sources", [])
    execution_segments = actual.get("execution_segments", [])
    phase_sequence = [item for item in actual.get("phase_sequence", []) if item]
    phase_states = _unique_strings(phase_sequence)
    call_stack_frames = actual.get("call_stack_frames", [])

    behavior_steps = []
    for item in actual.get("execution_path", []):
        kind = item.get("kind")
        step = {
            "index": item.get("index"),
            "kind": kind,
            "phase": item.get("phase"),
            "node_id": item.get("node_id"),
            "depth": item.get("depth"),
        }
        if kind == "call":
            step.update(
                {
                    "name": item.get("function"),
                    "role": _function_role(item.get("function")),
                    "caller": item.get("caller"),
                    "callee": item.get("callee"),
                }
            )
        elif kind == "syscall":
            step.update({"name": item.get("syscall"), "role": _function_role(item.get("syscall"))})
        elif kind == "memory":
            step.update(
                {
                    "address": item.get("address"),
                    "address_hint": item.get("address_hint"),
                    "role": item.get("phase"),
                }
            )
        elif kind == "io":
            step.update(
                {
                    "input": item.get("input_value"),
                    "output": item.get("output_value"),
                    "role": item.get("phase"),
                }
            )
        elif kind == "state":
            step.update(
                {
                    "before": item.get("before"),
                    "after": item.get("after"),
                    "role": item.get("phase"),
                }
            )
        elif kind == "branch":
            step.update(
                {
                    "condition": item.get("condition"),
                    "taken": item.get("taken"),
                    "target": item.get("target"),
                    "role": item.get("phase"),
                }
            )
        elif kind in {"return", "exception"}:
            step.update({"role": item.get("phase")})
        behavior_steps.append(step)

    return {
        "model_kind": "observed_runtime_semantics",
        "behavior_intent": _infer_runtime_intent(runtime, baseline),
        "runtime_abstraction": {
            "entry_points": functions[:1] or syscalls[:1] or ["observed-event-stream"],
            "external_inputs": _source_summary(sources),
            "behavior_steps": behavior_steps,
            "execution_path": actual.get("execution_path", []),
            "execution_segments": execution_segments,
            "phase_sequence": phase_sequence,
            "call_stack_frames": call_stack_frames,
            "branch_decisions": branches,
            "terminal_paths": {
                "returns": returns,
                "exceptions": exceptions,
            },
        },
        "state_machine": {
            "entry_state": phase_sequence[0] if phase_sequence else "entry",
            "states": _state_nodes(state.get("switch_points", [])),
            "transitions": _state_transitions_from_changes(state.get("switch_points", [])),
            "phase_states": phase_states,
            "phase_segments": execution_segments,
            "guard_conditions": [
                {
                    "condition": item.get("condition"),
                    "taken": item.get("taken"),
                    "target": item.get("target"),
                    "kind": "branch_guard",
                }
                for item in branches
            ],
            "input_triggers": state.get("input_triggers", []),
            "terminal_states": [
                {"kind": "return", "count": len(returns)},
                {"kind": "exception", "count": len(exceptions)},
            ],
        },
        "static_alignment": {
            "baseline_available": bool(baseline.get("available")),
            "static_semantics": baseline.get("semantics") or {},
            "difference_score": diff.get("difference_score", 0),
            "confidence": diff.get("confidence", 0.0),
        },
    }


def _build_memory_model(runtime: dict[str, Any], dataflow: dict[str, Any]) -> dict[str, Any]:
    accesses = runtime.get("memory_accesses", [])
    paths = dataflow.get("observed_paths", [])
    objects = _memory_patterns(accesses)
    writes = [item for item in accesses if item.get("kind") == "write"]
    reads = [item for item in accesses if item.get("kind") == "read"]
    unknown_address_accesses = [item for item in accesses if not item.get("address")]

    lifecycle = {
        "creation": _memory_creations(runtime, writes, objects),
        "propagation": _memory_propagations(paths, objects),
        "destruction": _memory_destructions(runtime, objects),
    }

    return {
        "access_patterns": {
            "read_count": len(reads),
            "write_count": len(writes),
            "unknown_address_count": len(unknown_address_accesses),
            "by_address": objects,
            "address_kinds": _unique_strings([item.get("object_kind") for item in objects]),
        },
        "objects": objects,
        "object_count": len(objects),
        "data_lifecycle": lifecycle,
        "pointer_or_buffer_paths": [
            item for item in paths if _path_mentions_memory(item) or _path_mentions_object(item, objects)
        ],
        "potential_exception_structures": _memory_uncertain_structures(accesses, objects),
        "scope": "runtime model only; no exploit guidance",
    }


def _build_state_transition(runtime: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    changes = state.get("switch_points", [])
    branches = runtime.get("branch_events", [])
    transitions = _state_transitions_from_changes(changes)
    transition_rules = []

    for branch in branches:
        condition = branch.get("condition") or branch.get("target") or f"branch:{branch.get('index')}"
        transitions.append(
            {
                "from": "branch-pending",
                "to": "branch-taken" if branch.get("taken") else "branch-not-taken",
                "key": condition,
                "kind": "branch_condition",
                "condition": branch.get("condition"),
                "triggered_by": branch.get("sources", []),
                "target": branch.get("target"),
            }
        )
        transition_rules.append(
            {
                "condition": branch.get("condition"),
                "target": branch.get("target"),
                "taken": branch.get("taken"),
                "source": branch.get("sources", []),
                "rule": condition,
            }
        )

    return {
        "transitions": transitions,
        "transition_rules": transition_rules,
        "input_state_map": state.get("input_triggers", []),
        "conditions": [
            {
                "condition": item.get("condition"),
                "taken": item.get("taken"),
                "target": item.get("target"),
                "triggered_by": item.get("sources", []),
            }
            for item in branches
        ],
        "summary": {
            "state_count": len(_state_nodes(changes)),
            "transition_count": len(transitions),
            "input_trigger_count": len(state.get("input_triggers", [])),
            "guard_count": len(transition_rules),
        },
    }


def _build_uncertainty(
    runtime: dict[str, Any],
    baseline: dict[str, Any],
    exec_flow: dict[str, Any],
    state: dict[str, Any],
    dataflow: dict[str, Any],
    diff: dict[str, Any],
) -> dict[str, Any]:
    events = runtime.get("events", [])
    unknown_events = [event for event in events if event.get("kind") == "event"]
    observed_modalities = _observed_modalities(runtime)
    uncertain_points = []
    execution_path = exec_flow.get("actual_execution", {}).get("execution_path", [])
    unmatched_returns = [item for item in execution_path if item.get("unmatched_return")]
    unresolved_branch_targets = [
        item
        for item in runtime.get("branch_events", [])
        if not item.get("target") or _looks_indirect_target(str(item.get("target") or ""))
    ]
    symbolic_memory_objects = [
        {
            "index": access.get("index"),
            "address": access.get("address"),
            "address_hint": access.get("address_hint"),
            "object_kind": _memory_object_kind(access),
        }
        for access in runtime.get("memory_accesses", [])
        if _memory_object_kind(access) in {"symbolic_address", "unknown"}
    ]

    if not baseline.get("available"):
        uncertain_points.append({"kind": "missing_static_baseline", "detail": "static comparison unavailable"})
    if not runtime.get("memory_accesses"):
        uncertain_points.append({"kind": "missing_memory_log", "detail": "memory reads and writes were not observed"})
    if not runtime.get("branch_events"):
        uncertain_points.append({"kind": "missing_branch_log", "detail": "branch decisions were not observed"})
    if not runtime.get("syscall_sequence"):
        uncertain_points.append({"kind": "missing_syscall_log", "detail": "syscall behavior was not observed"})
    if unknown_events:
        uncertain_points.append(
            {
                "kind": "unparsed_events",
                "detail": "some runtime records could not be typed",
                "count": len(unknown_events),
            }
        )
    if diff.get("hidden_paths"):
        uncertain_points.append(
            {
                "kind": "untriggered_static_paths",
                "detail": "static paths were not present in the supplied trace",
                "count": len(diff.get("hidden_paths", [])),
            }
        )
    if unmatched_returns:
        uncertain_points.append(
            {
                "kind": "unmatched_return",
                "detail": "return events were observed without a matching caller frame",
                "count": len(unmatched_returns),
            }
        )
    if unresolved_branch_targets:
        uncertain_points.append(
            {
                "kind": "unresolved_branch_target",
                "detail": "branch targets are missing or indirect",
                "count": len(unresolved_branch_targets),
            }
        )
    if symbolic_memory_objects:
        uncertain_points.append(
            {
                "kind": "symbolic_memory_object",
                "detail": "memory objects were only partially resolved",
                "count": len(symbolic_memory_objects),
            }
        )

    return {
        "observed_modalities": observed_modalities,
        "uncertain_points": uncertain_points,
        "possible_hidden_paths": diff.get("hidden_paths", []),
        "runtime_only_paths": diff.get("runtime_only_paths", []),
        "untriggered_data_paths": dataflow.get("untriggered_static_paths", []),
        "state_gaps": [
            item for item in state.get("switch_points", []) if not item.get("triggered_by")
        ],
        "unresolved_branch_targets": unresolved_branch_targets,
        "unmatched_returns": unmatched_returns,
        "symbolic_memory_objects": symbolic_memory_objects,
        "confidence": _uncertainty_confidence(runtime, baseline, observed_modalities, uncertain_points),
        "scope": "uncertainty annotation only; no exploit guidance",
        "static_cfg_diff": exec_flow.get("static_cfg_diff", {}),
    }


def _collect_events_from_mapping(payload: dict[str, Any]) -> list[RuntimeEvent]:
    events: list[RuntimeEvent] = []
    sequence = 1

    primary = payload.get("events")
    if primary is None:
        primary = payload.get("trace")

    if primary is not None:
        if isinstance(primary, list):
            events.extend(_normalize_event_list(primary))
        elif isinstance(primary, dict):
            events.append(_normalize_event(primary, sequence))
        elif isinstance(primary, str):
            events.extend(_parse_runtime_text(primary, start_index=sequence))
        return events

    key_map = [
        ("call_trace", "call"),
        ("syscalls", "syscall"),
        ("syscall_trace", "syscall"),
        ("memory_accesses", "memory"),
        ("memory", "memory"),
        ("io_pairs", "io"),
        ("input_output", "io"),
        ("state_changes", "state"),
        ("branches", "branch"),
        ("returns", "return"),
        ("exceptions", "exception"),
    ]

    for key, default_kind in key_map:
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                events.append(_normalize_event(item, sequence, default_kind=default_kind))
                sequence += 1
        elif isinstance(value, dict):
            events.append(_normalize_event(value, sequence, default_kind=default_kind))
            sequence += 1
        elif isinstance(value, str):
            for line_event in _parse_runtime_text(value, start_index=sequence):
                events.append(line_event)
                sequence = line_event.index + 1

    if not events and _looks_like_event_object(payload):
        events.append(_normalize_event(payload, sequence))

    return _dedupe_runtime_events(events)


def _normalize_event_list(items: list[Any]) -> list[RuntimeEvent]:
    events: list[RuntimeEvent] = []
    for index, item in enumerate(items, start=1):
        events.append(_normalize_event(item, index))
    return _dedupe_runtime_events(events)


def _normalize_event(item: Any, index: int, default_kind: str | None = None) -> RuntimeEvent:
    if isinstance(item, RuntimeEvent):
        return item

    if isinstance(item, dict):
        kind = _normalize_kind(str(item.get("kind") or item.get("type") or default_kind or "event"))
        label = _coerce_text(item.get("label") or item.get("name"))
        function = _coerce_text(item.get("function") or item.get("callee") or item.get("target"))
        syscall = _coerce_text(item.get("syscall") or item.get("system_call") or item.get("call"))
        address = _parse_address(
            item.get("address")
            or item.get("addr")
            or item.get("memory_address")
            or item.get("location")
        )
        address_hint = _coerce_text(
            item.get("address")
            or item.get("addr")
            or item.get("memory_address")
            or item.get("location")
            or item.get("pointer")
            or item.get("expr")
        )
        value = _coerce_text(item.get("value") or item.get("data") or item.get("payload"))
        input_value = _coerce_text(item.get("input") or item.get("stdin"))
        output_value = _coerce_text(item.get("output") or item.get("stdout"))
        before = _coerce_text(item.get("before"))
        after = _coerce_text(item.get("after"))
        condition = _coerce_text(item.get("condition"))
        taken = _parse_bool(item.get("taken") if "taken" in item else item.get("branch_taken"))
        target = _coerce_text(item.get("target") or item.get("dest"))
        source = _coerce_text(item.get("source") or item.get("from") or item.get("origin"))
        destination = _coerce_text(item.get("destination") or item.get("to"))
        line = _parse_int(item.get("line") or item.get("line_number") or item.get("ln"))
        sources = _normalize_sources(item.get("sources") or item.get("taint") or item.get("taints"))
        return RuntimeEvent(
            index=index,
            kind=kind,
            line=line,
            function=function,
            syscall=syscall,
            address=address,
            address_hint=address_hint,
            value=value,
            input_value=input_value,
            output_value=output_value,
            before=before,
            after=after,
            condition=condition,
            taken=taken,
            target=target,
            source=source,
            destination=destination,
            label=label,
            sources=sources,
            raw=item,
        )

    if isinstance(item, str):
        return _normalize_text_event(item, index)

    return RuntimeEvent(index=index, kind=_normalize_kind(default_kind or "event"), raw=item)


def _normalize_text_event(line: str, index: int) -> RuntimeEvent:
    text = line.strip()
    if not text:
        return RuntimeEvent(index=index, kind="event", raw=line)

    if text.startswith("{") and text.endswith("}"):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return _normalize_event(payload, index)
        except json.JSONDecodeError:
            pass

    match = CALLLIKE_RE.match(text)
    if match:
        return RuntimeEvent(index=index, kind="call", function=match.group("name"), raw=line)

    match = SYSCALL_RE.match(text)
    if match and match.group("name"):
        return RuntimeEvent(index=index, kind="syscall", syscall=match.group("name"), raw=line)

    match = MEMORY_RE.match(text)
    if match:
        return RuntimeEvent(
            index=index,
            kind="memory",
            address=_parse_address(match.group("addr")),
            value=_coerce_text(match.group("value")),
            label=match.group("kind"),
            raw=line,
        )

    match = IO_RE.match(text)
    if match:
        return RuntimeEvent(
            index=index,
            kind="io",
            input_value=_coerce_text(match.group("input")),
            output_value=_coerce_text(match.group("output")),
            raw=line,
        )

    match = STATE_RE.match(text)
    if match:
        return RuntimeEvent(
            index=index,
            kind="state",
            label=_coerce_text(match.group("name")) or "state",
            before=_coerce_text(match.group("before")),
            after=_coerce_text(match.group("after")),
            raw=line,
        )

    match = BRANCH_RE.match(text)
    if match:
        return RuntimeEvent(
            index=index,
            kind="branch",
            condition=_coerce_text(match.group("condition")),
            target=_coerce_text(match.group("target")),
            raw=line,
        )

    if re.match(r"^(?:return|ret|retn|retf)\b", text, re.I):
        return RuntimeEvent(index=index, kind="return", raw=line)

    if re.match(r"^(?:exception|throw|raise)\b", text, re.I):
        return RuntimeEvent(index=index, kind="exception", raw=line)

    return RuntimeEvent(index=index, kind="event", label=text, raw=line)


def _parse_runtime_text(text: str, start_index: int = 1) -> list[RuntimeEvent]:
    events: list[RuntimeEvent] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                payload = json.loads(stripped)
                if isinstance(payload, dict):
                    events.append(_normalize_event(payload, start_index + len(events)))
                    continue
            except json.JSONDecodeError:
                pass
        events.append(_normalize_text_event(stripped, start_index + len(events)))
    return _dedupe_runtime_events(events)


def _extract_code_structure(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(report, dict):
        return None
    if "CFG" in report and "DFG" in report and "CALL" in report:
        return report
    findings = report.get("findings")
    if isinstance(findings, dict):
        candidate = findings.get("code_structure")
        if isinstance(candidate, dict):
            return candidate
    candidate = report.get("code_structure")
    if isinstance(candidate, dict):
        return candidate
    return None


def _static_summary(code_structure: dict[str, Any]) -> str:
    cfg = code_structure.get("CFG", {}) if isinstance(code_structure, dict) else {}
    dfg = code_structure.get("DFG", {}) if isinstance(code_structure, dict) else {}
    call = code_structure.get("CALL", {}) if isinstance(code_structure, dict) else {}
    function_count = len(_unique_strings([item.get("callee") for item in call.get("calls", []) if isinstance(item, dict)]))
    branch_count = len(cfg.get("branch_paths", [])) if isinstance(cfg, dict) else 0
    source_count = len(dfg.get("input_sources", [])) if isinstance(dfg, dict) else 0
    return f"static baseline with {function_count} calls, {branch_count} branches, {source_count} data sources"


def _infer_runtime_intent(runtime: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    source_kinds = _unique_strings([item.get("kind") for item in runtime.get("sources", [])])
    traits = []
    if source_kinds:
        traits.append("external-input ingestion")
    if runtime.get("branch_events"):
        traits.append("input or state gated branching")
    if any(item.get("kind") == "write" for item in runtime.get("memory_accesses", [])):
        traits.append("memory mutation")
    if runtime.get("io_pairs"):
        traits.append("input-output transformation")
    if runtime.get("exception_events"):
        traits.append("exception path observed")

    if traits:
        intent = ", ".join(traits)
    elif runtime.get("call_sequence") or runtime.get("syscall_sequence"):
        intent = "call-sequence execution"
    else:
        intent = "observed runtime activity"

    confidence = 0.35
    confidence += min(0.25, len(traits) * 0.05)
    confidence += 0.2 if baseline.get("available") else 0.0
    confidence += min(0.15, len(runtime.get("events", [])) * 0.01)

    return {
        "intent": intent,
        "source_kinds": source_kinds,
        "traits": traits,
        "confidence": round(min(0.9, confidence), 2),
    }


def _function_role(name: Any) -> str:
    value = _symbol_name(name)
    if not value:
        return "unknown"
    if _classify_source_name(value):
        return f"{_classify_source_name(value)} input source"
    if any(token in value for token in ("decrypt", "decode", "unpack", "transform", "parse")):
        return "data transformation"
    if any(token in value for token in ("alloc", "malloc", "virtualalloc", "heapalloc", "mapview")):
        return "memory creation"
    if any(token in value for token in ("free", "close", "delete", "virtualfree", "heapfree")):
        return "resource destruction"
    if any(token in value for token in ("write", "send", "output")):
        return "output or persistence"
    return "control transfer"


def _source_summary(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for source in sources:
        output.append(
            {
                "id": source.get("id"),
                "kind": source.get("kind"),
                "name": source.get("name"),
                "event": source.get("event"),
            }
        )
    return output


def _state_nodes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for change in changes:
        key = change.get("key") or "state"
        for value in (change.get("before"), change.get("after")):
            if value is None:
                continue
            nodes.append({"id": f"{key}:{value}", "key": key, "value": value})
    return _dedupe_records(nodes)


def _state_transitions_from_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transitions = []
    for change in changes:
        transitions.append(
            {
                "from": change.get("before"),
                "to": change.get("after"),
                "key": change.get("key"),
                "kind": change.get("kind"),
                "condition": change.get("condition"),
                "triggered_by": change.get("triggered_by", []),
                "line": change.get("line"),
                "source": change.get("source"),
            }
        )
    return _dedupe_records(transitions)


def _build_propagation_chains(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains: dict[str, dict[str, Any]] = {}
    for path in paths:
        source = str(path.get("from") or "unknown")
        chain = chains.setdefault(
            source,
            {
                "source": source,
                "path_count": 0,
                "target_nodes": [],
                "kinds": [],
                "steps": [],
                "first_seen": path.get("line"),
                "last_seen": path.get("line"),
            },
        )
        chain["path_count"] += 1
        target = path.get("to")
        if target is not None:
            chain["target_nodes"].append(target)
        if path.get("kind") is not None:
            chain["kinds"].append(path.get("kind"))
        chain["steps"].append(
            {
                "to": target,
                "kind": path.get("kind"),
                "line": path.get("line"),
                "source": path.get("source"),
            }
        )
        if path.get("line") is not None:
            chain["first_seen"] = path.get("line") if chain["first_seen"] is None else min(chain["first_seen"], path.get("line"))
            chain["last_seen"] = path.get("line") if chain["last_seen"] is None else max(chain["last_seen"], path.get("line"))

    output = []
    for chain in chains.values():
        chain["target_nodes"] = _unique_strings(chain["target_nodes"])
        chain["kinds"] = _unique_strings(chain["kinds"])
        output.append(chain)
    return sorted(output, key=lambda item: (item.get("first_seen") or 0, item.get("source") or ""))


def _memory_patterns(accesses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for access in accesses:
        object_id = _memory_object_id(access)
        item = grouped.setdefault(
            object_id,
            {
                "object_id": object_id,
                "address": access.get("address"),
                "address_hint": access.get("address_hint"),
                "object_kind": _memory_object_kind(access),
                "read_count": 0,
                "write_count": 0,
                "first_seen": access.get("index"),
                "last_seen": access.get("index"),
                "access_indices": [],
                "sources": [],
                "values": [],
                "phases": [],
            },
        )
        role = _memory_access_role(access)
        if role == "write":
            item["write_count"] += 1
        else:
            item["read_count"] += 1
        index = access.get("index")
        if index is not None:
            item["first_seen"] = index if item["first_seen"] is None else min(item["first_seen"], index)
            item["last_seen"] = index if item["last_seen"] is None else max(item["last_seen"], index)
        item["access_indices"].append(index)
        item["sources"].extend(access.get("sources") or [])
        if access.get("value") is not None:
            item["values"].append(access.get("value"))
        item["phases"].append(role)

    output = []
    for item in grouped.values():
        item["sources"] = _unique_strings(item["sources"])
        item["values"] = _unique_strings(item["values"])
        item["phases"] = _unique_strings(item["phases"])
        item["lifecycle"] = _memory_object_lifecycle(item)
        output.append(item)
    return sorted(output, key=lambda record: (record.get("first_seen") or 0, record.get("object_id") or ""))


def _memory_creations(
    runtime: dict[str, Any],
    writes: list[dict[str, Any]],
    objects: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    creations = []
    for source in runtime.get("sources", []):
        creations.append(
            {
                "kind": "input_source",
                "id": source.get("id"),
                "name": source.get("name"),
                "source_kind": source.get("kind"),
            }
        )
    for write in writes:
        creations.append(
            {
                "kind": "memory_write",
                "address": write.get("address"),
                "address_hint": write.get("address_hint"),
                "value": write.get("value"),
                "sources": write.get("sources", []),
            }
        )
    for obj in objects:
        creations.append(
            {
                "kind": "memory_object_creation",
                "object_id": obj.get("object_id"),
                "object_kind": obj.get("object_kind"),
                "address": obj.get("address"),
                "address_hint": obj.get("address_hint"),
                "first_seen": obj.get("first_seen"),
                "sources": obj.get("sources", []),
            }
        )
    return _dedupe_records(creations)


def _memory_propagations(paths: list[dict[str, Any]], objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for path in paths:
        output.append(
            {
                "from": path.get("from"),
                "to": path.get("to"),
                "kind": path.get("kind"),
                "line": path.get("line"),
            }
        )
    for obj in objects:
        if obj.get("read_count") and obj.get("write_count"):
            output.append(
                {
                    "kind": "memory_object_propagation",
                    "object_id": obj.get("object_id"),
                    "object_kind": obj.get("object_kind"),
                    "address": obj.get("address"),
                    "address_hint": obj.get("address_hint"),
                    "sources": obj.get("sources", []),
                    "phase_sequence": obj.get("lifecycle", {}).get("phase_sequence", []),
                    "read_count": obj.get("read_count"),
                    "write_count": obj.get("write_count"),
                }
            )
    return _dedupe_records(output)


def _memory_destructions(runtime: dict[str, Any], objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    destructions = []
    for name in runtime.get("call_sequence", []):
        if _is_destroy_call(name):
            destructions.append({"kind": "call", "name": name, "role": "release or clear"})
    for access in runtime.get("memory_accesses", []):
        value = _symbol_name(access.get("value"))
        if value in {"0", "null", "nullptr"}:
            destructions.append(
                {
                    "kind": "zero_or_null_write",
                    "address": access.get("address"),
                    "address_hint": access.get("address_hint"),
                    "index": access.get("index"),
                }
            )
    for obj in objects:
        lifecycle = obj.get("lifecycle") or {}
        if lifecycle.get("state") == "destroyed":
            destructions.append(
                {
                    "kind": "memory_object_destruction",
                    "object_id": obj.get("object_id"),
                    "object_kind": obj.get("object_kind"),
                    "address": obj.get("address"),
                    "address_hint": obj.get("address_hint"),
                    "phase_sequence": lifecycle.get("phase_sequence", []),
                }
            )
    return _dedupe_records(destructions)


def _path_mentions_memory(path: dict[str, Any]) -> bool:
    values = (path.get("from"), path.get("to"), path.get("kind"))
    return any("memory" in str(value).lower() for value in values if value is not None)


def _path_mentions_object(path: dict[str, Any], objects: list[dict[str, Any]]) -> bool:
    text = " ".join(str(value) for value in (path.get("from"), path.get("to"), path.get("kind")) if value is not None).lower()
    for obj in objects:
        if str(obj.get("object_id") or "").lower() in text:
            return True
        if str(obj.get("address") or "").lower() in text:
            return True
        if str(obj.get("address_hint") or "").lower() in text:
            return True
    return False


def _memory_uncertain_structures(accesses: list[dict[str, Any]], objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    structures = []
    for access in accesses:
        if not access.get("address") and not access.get("address_hint"):
            structures.append(
                {
                    "kind": "unknown_address_access",
                    "index": access.get("index"),
                    "access": access.get("kind"),
                    "structure": "memory access without resolved address",
                }
            )
        if access.get("kind") == "write" and not access.get("sources"):
            structures.append(
                {
                    "kind": "unattributed_memory_write",
                    "index": access.get("index"),
                    "address": access.get("address"),
                    "structure": "memory write without observed source",
                }
            )
    for obj in objects:
        if obj.get("object_kind") == "symbolic_address":
            structures.append(
                {
                    "kind": "symbolic_memory_object",
                    "object_id": obj.get("object_id"),
                    "address_hint": obj.get("address_hint"),
                    "structure": "memory object resolved only symbolically",
                }
            )
        if obj.get("lifecycle", {}).get("state") == "partially_observed":
            structures.append(
                {
                    "kind": "partial_memory_lifecycle",
                    "object_id": obj.get("object_id"),
                    "structure": "lifecycle observed but not fully closed",
                }
            )
    return _dedupe_records(structures)


def _memory_object_id(access: dict[str, Any]) -> str:
    if access.get("address"):
        return f"addr:{_symbol_name(str(access.get('address')))}"
    if access.get("address_hint"):
        return f"hint:{_symbol_name(str(access.get('address_hint')))}"
    if access.get("node_id"):
        return f"node:{_symbol_name(str(access.get('node_id')))}"
    return f"memory:event-{access.get('index')}"


def _memory_object_kind(access: dict[str, Any]) -> str:
    hint = _symbol_name(access.get("address_hint") or "")
    if any(token in hint for token in ("rsp", "rbp", "stack", "sp", "bp")):
        return "stack_slot"
    if any(token in hint for token in ("heap", "malloc", "alloc", "new", "virtualalloc", "heappool", "pool")):
        return "heap_candidate"
    if any(token in hint for token in ("global", "static", "data", "rdata", "bss")):
        return "global_or_static"
    if access.get("address") is not None:
        return "absolute_address"
    if access.get("address_hint"):
        return "symbolic_address"
    return "unknown"


def _memory_access_role(access: dict[str, Any]) -> str:
    kind = str(access.get("kind") or "").lower()
    if kind in {"write", "store", "memory_write"}:
        return "write"
    if kind in {"read", "load", "memory_read"}:
        return "read"
    return "write" if access.get("value") is not None else "read"


def _memory_object_lifecycle(obj: dict[str, Any]) -> dict[str, Any]:
    phase_sequence = []
    if obj.get("write_count"):
        phase_sequence.append("creation")
    if obj.get("read_count") and obj.get("write_count"):
        phase_sequence.append("propagation")
    if any(_symbol_name(value) in {"0", "null", "nullptr"} for value in obj.get("values", [])):
        phase_sequence.append("destruction")

    state = "observed_only"
    if "destruction" in phase_sequence:
        state = "destroyed"
    elif "propagation" in phase_sequence:
        state = "active"
    elif "creation" in phase_sequence:
        state = "initialized"

    if state == "observed_only" and obj.get("read_count") and not obj.get("write_count"):
        state = "read_only"
    if state == "observed_only" and obj.get("write_count") and not obj.get("read_count"):
        state = "write_only"
    if state == "observed_only" and obj.get("read_count") and obj.get("write_count"):
        state = "partially_observed"

    return {
        "phase_sequence": _unique_strings(phase_sequence),
        "state": state,
        "first_seen": obj.get("first_seen"),
        "last_seen": obj.get("last_seen"),
        "stability": "stable" if state in {"active", "initialized"} else "transient" if state == "destroyed" else "partial",
    }


def _looks_indirect_target(value: str) -> bool:
    text = value.strip().lower()
    return any(token in text for token in ("[", "]", "*", "(", ")")) or re.fullmatch(
        r"r\d+|[re]?[abcd]x|[re]?(?:si|di|bp|sp)", text, flags=re.IGNORECASE
    ) is not None


def _observed_modalities(runtime: dict[str, Any]) -> list[str]:
    modalities = []
    if runtime.get("call_sequence"):
        modalities.append("call_trace")
    if runtime.get("syscall_sequence"):
        modalities.append("syscall_record")
    if runtime.get("memory_accesses"):
        modalities.append("memory_access_log")
    if runtime.get("io_pairs"):
        modalities.append("input_output_pair")
    if runtime.get("branch_events"):
        modalities.append("branch_log")
    if runtime.get("state_changes"):
        modalities.append("state_log")
    return modalities


def _uncertainty_confidence(
    runtime: dict[str, Any],
    baseline: dict[str, Any],
    modalities: list[str],
    uncertain_points: list[dict[str, Any]],
) -> float:
    confidence = 0.25
    confidence += 0.25 if baseline.get("available") else 0.0
    confidence += min(0.25, len(modalities) * 0.05)
    confidence += min(0.2, len(runtime.get("events", [])) * 0.01)
    confidence -= min(0.25, len(uncertain_points) * 0.03)
    return round(max(0.05, min(0.95, confidence)), 2)


def _is_destroy_call(name: Any) -> bool:
    value = _symbol_name(name)
    return any(
        token in value
        for token in (
            "free",
            "delete",
            "closehandle",
            "virtualfree",
            "heapfree",
            "rtlzeromemory",
            "securezeromemory",
        )
    )


def _event_sources(event: RuntimeEvent) -> list[str]:
    sources = list(event.sources)
    if event.source:
        sources.append(event.source)
    if event.destination:
        sources.append(event.destination)
    if event.kind == "memory":
        if event.value:
            sources.append(event.value)
        if event.address_hint:
            sources.append(event.address_hint)
    elif event.kind == "io":
        if event.input_value:
            sources.append(event.input_value)
        if event.output_value:
            sources.append(event.output_value)
    elif event.kind == "state":
        if event.before:
            sources.append(event.before)
        if event.after:
            sources.append(event.after)
        if event.label:
            sources.append(event.label)
    elif event.kind == "branch":
        if event.condition:
            sources.append(event.condition)
        if event.target:
            sources.append(event.target)
    return _unique_strings(sources)


def _classify_source_event(event: RuntimeEvent) -> tuple[str, str]:
    if event.kind == "call" and event.function:
        source_kind = _classify_source_name(event.function)
        if source_kind:
            return source_kind, event.function
    if event.kind == "syscall" and event.syscall:
        source_kind = _classify_source_name(event.syscall)
        if source_kind:
            return source_kind, event.syscall
    if event.kind == "io":
        return "input", event.input_value or event.output_value or f"io-{event.index}"
    if event.kind == "input":
        return "input", event.label or event.input_value or f"input-{event.index}"
    return "event", event.function or event.syscall or event.label or f"event-{event.index}"


def _is_source_event(event: RuntimeEvent) -> bool:
    return _classify_source_name(event.function or "") is not None or _classify_source_name(event.syscall or "") is not None or event.kind in {"input", "io"}


def _classify_source_name(name: str) -> str | None:
    key = _symbol_name(name)
    return SOURCE_NAME_TO_KIND.get(key)


def _source_id(kind: str, name: str | None, index: int) -> str:
    return f"{kind}:{_symbol_name(name or f'event-{index}')}"


def _source_coverage_key(item: dict[str, Any]) -> str:
    kind = _symbol_name(str(item.get("kind") or item.get("source_kind") or ""))
    name = _symbol_name(str(item.get("callee") or item.get("name") or item.get("source") or ""))
    if kind and name:
        return f"{kind}:{name}"
    return name or kind


def _event_sources_from_fields(item: Any) -> list[str]:
    if isinstance(item, dict):
        return _normalize_sources(item.get("sources") or item.get("taint") or item.get("taints"))
    return []


def _match_static_sources(
    static_sources: list[dict[str, Any]],
    observed_sources: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    observed_index = {
        (_symbol_name(item.get("kind")), _symbol_name(item.get("name"))): item for item in observed_sources
    }
    for item in static_sources:
        kind = _symbol_name(str(item.get("kind") or ""))
        name = _symbol_name(str(item.get("callee") or item.get("name") or ""))
        key = (kind, name)
        if key in observed_index:
            matched.append(
                {
                    "static": item,
                    "matched_by": observed_index[key],
                }
            )
        else:
            unmatched.append(item)
    return matched, unmatched


def _match_static_paths(
    static_paths: list[dict[str, Any]],
    matched_static_sources: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matched_source_ids = {
        str(entry.get("static", {}).get("id"))
        for entry in matched_static_sources
        if isinstance(entry, dict) and isinstance(entry.get("static"), dict)
    }
    triggered: list[dict[str, Any]] = []
    untriggered: list[dict[str, Any]] = []
    for item in static_paths:
        source_ids = [str(value) for value in item.get("source_ids", []) if value is not None]
        if matched_source_ids.intersection(source_ids):
            triggered.append(item)
        else:
            untriggered.append(item)
    return triggered, untriggered


def _static_source_names(static_dfg: dict[str, Any]) -> list[str]:
    sources = static_dfg.get("input_sources", []) if isinstance(static_dfg, dict) else []
    return _unique_strings(
        [str(item.get("callee") or item.get("name") or item.get("kind")) for item in sources if isinstance(item, dict)]
    )


def _branch_signature(item: dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return ""
    if item.get("condition"):
        return _symbol_name(str(item.get("condition")))
    if item.get("target"):
        return _symbol_name(str(item.get("target")))
    if item.get("case_targets"):
        return ",".join(_symbol_name(str(value)) for value in item.get("case_targets", []))
    return _symbol_name(str(item.get("kind") or ""))


def _branch_signatures(items: list[dict[str, Any]]) -> set[str]:
    return { _branch_signature(item) for item in items if isinstance(item, dict) }


def _compact_static_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for item in paths:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "line": item.get("line"),
                "kind": item.get("kind"),
                "condition": item.get("condition"),
                "target": item.get("target") or item.get("true_target"),
                "source_block": item.get("source_block"),
            }
        )
    return output


def _compact_value(item: Any) -> Any:
    if isinstance(item, dict):
        for key in ("value", "target", "name", "condition", "key"):
            if item.get(key) is not None:
                return item.get(key)
    return item


def _coverage_ratio(expected: list[str], observed: list[str]) -> float:
    expected_set = {item for item in expected if item}
    if not expected_set:
        return 1.0
    observed_set = {item for item in observed if item}
    return round(len(expected_set.intersection(observed_set)) / len(expected_set), 3)


def _diff_score(
    hidden_paths: list[Any],
    runtime_only_paths: list[Any],
    differences: list[dict[str, Any]],
) -> int:
    score = 0
    score += min(40, len(hidden_paths) * 8)
    score += min(30, len(runtime_only_paths) * 6)
    score += min(30, len(differences) * 2)
    return min(100, score)


def _unique_strings(items: list[Any]) -> list[str]:
    seen = set()
    output = []
    for item in items:
        value = _coerce_text(item)
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _merge_sources(existing: list[str], new_items: list[str]) -> list[str]:
    output = list(existing)
    for item in new_items:
        if item not in output:
            output.append(item)
    return output[-8:]


def _normalize_sources(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return _unique_strings(value)
    if isinstance(value, dict):
        return _unique_strings(list(value.values()))
    return _unique_strings([value])


def _normalize_kind(value: str) -> str:
    kind = value.strip().lower()
    if kind in {"memory_read", "read", "load", "mem read", "memory read"}:
        return "memory"
    if kind in {"memory_write", "write", "store", "mem write", "memory write"}:
        return "memory"
    if kind in {"call", "invoke", "enter"}:
        return "call"
    if kind in {"syscall", "int 0x2e", "int 2eh"}:
        return "syscall"
    if kind in {"io", "input", "output", "input_output"}:
        return "io"
    if kind in {"state", "reg", "register", "flag", "var"}:
        return "state"
    if kind in {"branch", "cond", "guard"}:
        return "branch"
    if kind in {"ret", "return"}:
        return "return"
    if kind in {"throw", "exception", "raise"}:
        return "exception"
    return kind or "event"


def _decode_text(data: bytes) -> str | None:
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        return None
    printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
    if printable / max(len(text), 1) < 0.7:
        return None
    return text


def _coerce_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def _parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return parse_int_value(value)
    return None


def _parse_address(value: Any) -> int | None:
    return _parse_int(value)


def _parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "taken"}:
            return True
        if lowered in {"false", "0", "no", "not_taken", "untaken"}:
            return False
    if isinstance(value, int):
        return bool(value)
    return None


def _extract_transition(value: str) -> tuple[str | None, str | None] | None:
    if "->" not in value and "=>" not in value:
        return None
    delimiter = "->" if "->" in value else "=>"
    left, right = value.split(delimiter, 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        return None
    return left, right


def _memory_event_is_write(event: RuntimeEvent) -> bool:
    if event.label:
        lowered = event.label.lower()
        return "write" in lowered or "store" in lowered
    if event.kind == "memory" and event.value is not None:
        return True
    return False


def _memory_access_kind(event: RuntimeEvent) -> str:
    if event.label:
        lowered = event.label.lower()
        if "write" in lowered or "store" in lowered:
            return "write"
        if "read" in lowered or "load" in lowered:
            return "read"
    return "write" if _memory_event_is_write(event) else "read"


def _dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for record in records:
        key = tuple(sorted((str(key), repr(value)) for key, value in record.items()))
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


def _dedupe_runtime_events(events: list[RuntimeEvent]) -> list[RuntimeEvent]:
    seen = set()
    output: list[RuntimeEvent] = []
    for event in events:
        key = (
            event.kind,
            event.line,
            event.function,
            event.syscall,
            event.address,
            event.address_hint,
            event.value,
            event.input_value,
            event.output_value,
            event.before,
            event.after,
            event.condition,
            event.taken,
            event.target,
            event.source,
            event.destination,
            event.label,
            tuple(event.sources),
            repr(_compact_value(event.raw)),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def _looks_like_event_object(payload: dict[str, Any]) -> bool:
    return any(key in payload for key in ("kind", "type", "function", "syscall", "address", "input", "output", "before", "after"))
