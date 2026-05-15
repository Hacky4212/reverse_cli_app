from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding


MAX_CODE_LINES = 5000
MAX_BLOCK_INSTRUCTIONS = 80

CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
    "try",
    "throw",
    "else",
    "case",
}

IDENTIFIER_STOPWORDS = CONTROL_KEYWORDS | {
    "void",
    "int",
    "i1",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "float",
    "double",
    "char",
    "short",
    "long",
    "unsigned",
    "signed",
    "const",
    "volatile",
    "struct",
    "class",
    "enum",
    "static",
    "extern",
    "ptr",
    "byte",
    "word",
    "dword",
    "qword",
    "xmmword",
    "ptr64",
    "align",
    "alloca",
    "addrspace",
    "alias",
    "call",
    "declare",
    "define",
    "extractvalue",
    "fcmp",
    "fptrunc",
    "getelementptr",
    "global",
    "icmp",
    "inbounds",
    "insertvalue",
    "landingpad",
    "load",
    "local_unnamed_addr",
    "noundef",
    "nonnull",
    "nofree",
    "noreturn",
    "nounwind",
    "phi",
    "ptr",
    "readonly",
    "readnone",
    "resume",
    "ret",
    "select",
    "store",
    "tail",
    "to",
    "unreachable",
    "volatile",
    "true",
    "false",
    "null",
    "nullptr",
}

CONDITIONAL_JUMPS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
    "jcxz",
    "jecxz",
    "jrcxz",
    "loop",
    "loope",
    "loopne",
    "loopnz",
    "loopz",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}

UNCONDITIONAL_JUMPS = {"jmp", "goto", "b", "br", "bra"}
RETURN_TERMS = {"ret", "retn", "retf", "return", "iret", "iretd", "iretq"}
THROW_TERMS = {"throw", "__cxa_throw", "RtlRaiseException", "RaiseException"}

ASSIGNMENT_OPS = {
    "mov",
    "movzx",
    "movsx",
    "lea",
    "xchg",
    "xor",
    "add",
    "sub",
    "imul",
    "mul",
    "and",
    "or",
    "shl",
    "shr",
    "sar",
    "rol",
    "ror",
}

WRITE_FIRST_OPERAND_OPS = ASSIGNMENT_OPS | {
    "stos",
    "stosb",
    "stosw",
    "stosd",
    "stosq",
    "inc",
    "dec",
}

READ_ONLY_OPS = {"cmp", "test", "push", "call", "jmp", "ret"}

INPUT_SOURCE_APIS: dict[str, tuple[str, ...]] = {
    "network": (
        "recv",
        "recvfrom",
        "WSARecv",
        "InternetReadFile",
        "WinHttpReadData",
        "HttpReceiveRequestEntityBody",
        "ReadClient",
    ),
    "file": (
        "ReadFile",
        "NtReadFile",
        "ZwReadFile",
        "fread",
        "read",
        "_read",
        "ifstream",
        "MapViewOfFile",
        "NtMapViewOfSection",
    ),
    "api": (
        "GetCommandLineA",
        "GetCommandLineW",
        "GetEnvironmentVariableA",
        "GetEnvironmentVariableW",
        "RegQueryValueExA",
        "RegQueryValueExW",
        "DeviceIoControl",
        "GetProcAddress",
        "LdrGetProcedureAddress",
    ),
    "syscall": (
        "syscall",
        "sysenter",
        "int 0x2e",
        "int 2eh",
        "NtDeviceIoControlFile",
        "ZwDeviceIoControlFile",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
    ),
}

MEMORY_COPY_APIS = {
    "memcpy",
    "memmove",
    "memset",
    "strcpy",
    "strncpy",
    "strcat",
    "sprintf",
    "snprintf",
    "RtlCopyMemory",
    "RtlMoveMemory",
    "CopyMemory",
}

API_RESOLUTION_APIS = {
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
}

CALLBACK_APIS = {
    "CreateThread",
    "CreateRemoteThread",
    "EnumWindows",
    "EnumChildWindows",
    "EnumThreadWindows",
    "qsort",
    "bsearch",
    "atexit",
    "signal",
    "SetTimer",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "RegisterClassA",
    "RegisterClassW",
    "RegisterClassExA",
    "RegisterClassExW",
}

KERNEL_APIS = {
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "DeviceIoControl",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "ObRegisterCallbacks",
    "MmCopyVirtualMemory",
    "MmMapIoSpace",
    "ZwDeviceIoControlFile",
    "NtDeviceIoControlFile",
}


@dataclass(slots=True)
class CodeLine:
    number: int
    raw: str
    text: str
    label: str | None = None
    address: str | None = None


class CodeStructureAnalyzer:
    name = "code_structure"

    def run(self, context: AnalysisContext) -> None:
        text = _decode_text(context.read_bytes())
        if not text:
            return

        lines = _normalize_lines(text)
        if not lines or not _looks_like_code(lines):
            return

        cfg = _build_cfg(lines)
        call = _build_call(lines)
        dfg = _build_dfg(lines, call)
        memory = _build_memory(lines, dfg)
        semantics = _infer_semantics(cfg, dfg, call, memory)
        risk = _build_risk(cfg, dfg, call, memory)

        finding = {
            "input_kind": _classify_input_kind(lines),
            "line_count": len(lines),
            "CFG": cfg,
            "DFG": dfg,
            "CALL": call,
            "MEMORY": memory,
            "SEMANTICS": semantics,
            "RISK": risk,
        }
        context.add_finding(self.name, finding)

        if risk["score"] >= 50:
            context.add_issue(
                Finding(
                    id="risky_binary_code_structure",
                    title="Risky binary-level structure detected",
                    severity="high" if risk["score"] >= 75 else "medium",
                    category="structure",
                    summary="The code structure contains input-influenced control, indirect dispatch, or memory-write paths.",
                    confidence=risk["confidence"],
                    evidence={"score": risk["score"], "paths": risk["paths"][:5]},
                    tags=["cfg", "dfg", "memory", "structure"],
                    recommendation="Review the marked structural paths during manual reverse engineering.",
                )
            )


def _decode_text(data: bytes) -> str | None:
    if not data:
        return None

    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        return None

    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if printable / max(len(text), 1) < 0.75:
        return None
    return text


def _normalize_lines(text: str) -> list[CodeLine]:
    lines: list[CodeLine] = []
    for raw_number, raw in enumerate(text.splitlines(), start=1):
        if len(lines) >= MAX_CODE_LINES:
            break

        stripped = _strip_comment(raw).strip()
        if not stripped:
            continue

        label = None
        address = None
        body = stripped

        match = re.match(
            r"^(?P<prefix>(?:0x)?[0-9A-Fa-f]{4,16}|[A-Za-z_.$?@][\w.$?@<>~]*):\s*(?P<body>.*)$",
            stripped,
        )
        if match:
            prefix = match.group("prefix")
            body = match.group("body").strip()
            if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{4,16}", prefix):
                address = _normalize_target(prefix)
            else:
                label = prefix

        if not body and label is None and address is None:
            continue

        lines.append(CodeLine(number=raw_number, raw=raw.rstrip(), text=body or stripped, label=label, address=address))
    return lines


def _strip_comment(line: str) -> str:
    for marker in ("//", "#"):
        pos = line.find(marker)
        if pos >= 0:
            return line[:pos]
    return line


def _looks_like_code(lines: list[CodeLine]) -> bool:
    score = 0
    for line in lines[:300]:
        lowered = line.text.lower()
        op = _instruction_op(line.text)
        if line.label or line.address:
            score += 1
        if op in ASSIGNMENT_OPS or op in CONDITIONAL_JUMPS or op in UNCONDITIONAL_JUMPS:
            score += 2
        if _extract_call_from_line(line):
            score += 2
        if any(keyword in lowered for keyword in ("if (", "while (", "for (", "switch (", "return", "goto ")):
            score += 2
        if score >= 4:
            return True
    return False


def _classify_input_kind(lines: list[CodeLine]) -> str:
    asm_score = 0
    decompiled_score = 0
    ir_score = 0

    for line in lines[:200]:
        text = line.text.strip()
        op = _instruction_op(text)
        if op in ASSIGNMENT_OPS or op in CONDITIONAL_JUMPS or op in UNCONDITIONAL_JUMPS or op in RETURN_TERMS:
            asm_score += 1
        if any(token in text for token in ("if (", "while (", "for (", "switch (", "return ")):
            decompiled_score += 1
        if re.search(r"\b(?:phi|br|load|store|icmp|call)\b", text) and "%" in text:
            ir_score += 2

    if ir_score >= max(asm_score, decompiled_score, 1):
        return "ir"
    if asm_score and decompiled_score:
        return "mixed"
    if asm_score:
        return "assembly"
    if decompiled_score:
        return "decompiled"
    return "unknown"


def _build_cfg(lines: list[CodeLine]) -> dict[str, Any]:
    label_to_line: dict[str, int] = {}
    for index, line in enumerate(lines):
        if line.label:
            label_to_line[_normalize_target(line.label)] = index
        if line.address:
            label_to_line[_normalize_target(line.address)] = index

    starts = {0}
    branch_events: list[dict[str, Any]] = []
    exception_paths: list[dict[str, Any]] = []
    return_paths: list[dict[str, Any]] = []

    for index, line in enumerate(lines):
        branch = _extract_branch(line)
        if line.label or line.address:
            starts.add(index)
        if branch:
            branch_events.append({"line_index": index, "line": line.number, **branch})
            if index + 1 < len(lines):
                starts.add(index + 1)
            target_index = _resolve_target_index(branch.get("target"), label_to_line)
            if target_index is not None:
                starts.add(target_index)
        if _is_return(line.text):
            return_paths.append({"line": line.number, "source": line.raw.strip(), "kind": "return"})
            if index + 1 < len(lines):
                starts.add(index + 1)
        if _is_exception_line(line.text):
            exception_paths.append({"line": line.number, "source": line.raw.strip(), "kind": _exception_kind(line.text)})
            if index + 1 < len(lines):
                starts.add(index + 1)

    ordered_starts = sorted(starts)
    line_to_block: dict[int, str] = {}
    blocks: list[dict[str, Any]] = []
    for block_index, start in enumerate(ordered_starts):
        end = ordered_starts[block_index + 1] - 1 if block_index + 1 < len(ordered_starts) else len(lines) - 1
        block_id = f"B{block_index + 1}"
        block_lines = lines[start : end + 1]
        for line_index in range(start, end + 1):
            line_to_block[line_index] = block_id
        blocks.append(
            {
                "id": block_id,
                "start_line": block_lines[0].number,
                "end_line": block_lines[-1].number,
                "label": block_lines[0].label,
                "address": block_lines[0].address,
                "instructions": [item.raw.strip() for item in block_lines[:MAX_BLOCK_INSTRUCTIONS]],
            }
        )

    edges: list[dict[str, Any]] = []
    branch_paths: list[dict[str, Any]] = []
    loops: list[dict[str, Any]] = []

    for event in branch_events:
        source_index = int(event["line_index"])
        source_block = line_to_block.get(source_index)
        if source_block is None:
            continue

        target_index = _resolve_target_index(event.get("target"), label_to_line)
        target_block = line_to_block.get(target_index) if target_index is not None else None
        next_block = line_to_block.get(source_index + 1)
        kind = str(event["kind"])

        if kind == "conditional":
            edges.append(
                {
                    "from": source_block,
                    "to": target_block or "unknown",
                    "kind": "conditional_true",
                    "line": event["line"],
                    "condition": event.get("condition"),
                }
            )
            false_target = event.get("false_target") or next_block
            if false_target:
                edges.append(
                    {
                        "from": source_block,
                        "to": false_target,
                        "kind": "conditional_false",
                        "line": event["line"],
                        "condition": event.get("condition"),
                    }
                )
            branch_paths.append(
                {
                    "line": event["line"],
                    "kind": "conditional",
                    "source_block": source_block,
                    "condition": event.get("condition"),
                    "true_target": target_block or event.get("target") or "structured_true",
                    "false_target": false_target or "fallthrough",
                    "source": event.get("source"),
                }
            )
        elif kind == "switch":
            case_targets = _case_targets(lines)
            for target in case_targets:
                edges.append({"from": source_block, "to": target, "kind": "switch_case", "line": event["line"]})
            branch_paths.append(
                {
                    "line": event["line"],
                    "kind": "switch",
                    "source_block": source_block,
                    "condition": event.get("condition"),
                    "case_targets": case_targets or ["unknown"],
                    "source": event.get("source"),
                }
            )
        else:
            edges.append(
                {
                    "from": source_block,
                    "to": target_block or event.get("target") or "unknown",
                    "kind": kind,
                    "line": event["line"],
                }
            )

        if target_index is not None and target_index <= source_index:
            loops.append(
                {
                    "line": event["line"],
                    "source_block": source_block,
                    "target_block": target_block,
                    "kind": "back_edge",
                    "source": event.get("source"),
                }
            )
        elif _looks_like_loop(lines[source_index].text):
            loops.append(
                {
                    "line": event["line"],
                    "source_block": source_block,
                    "target_block": target_block or next_block or "unknown",
                    "kind": "structured_loop",
                    "source": event.get("source"),
                }
            )

    for block in blocks:
        last_line_index = _line_index_by_number(lines, block["end_line"])
        if last_line_index is None or last_line_index in {int(event["line_index"]) for event in branch_events}:
            continue
        if _is_return(lines[last_line_index].text) or _is_exception_line(lines[last_line_index].text):
            continue
        next_block = _next_block_id(block["id"], blocks)
        if next_block:
            edges.append({"from": block["id"], "to": next_block, "kind": "fallthrough", "line": block["end_line"]})

    for event in branch_events:
        if _looks_like_loop(lines[int(event["line_index"])].text) and not any(loop["line"] == event["line"] for loop in loops):
            loops.append(
                {
                    "line": event["line"],
                    "source_block": line_to_block.get(int(event["line_index"]), "unknown"),
                    "target_block": line_to_block.get(int(event["line_index"]), "unknown"),
                    "kind": "structured_loop",
                    "source": event.get("source"),
                }
            )

    return {
        "nodes": blocks,
        "edges": edges,
        "branch_paths": branch_paths,
        "all_paths": _enumerate_cfg_paths(blocks, edges),
        "edge_index": _edge_index(edges),
        "unresolved_edges": [edge for edge in edges if edge.get("to") in {None, "", "unknown"}],
        "loops": loops,
        "loop_headers": _unique_strings([loop.get("target_block") or loop.get("source_block") for loop in loops]),
        "exception_paths": exception_paths,
        "return_paths": return_paths,
        "terminal_blocks": _terminal_blocks(blocks, edges, return_paths, exception_paths),
        "limits": {"max_lines": MAX_CODE_LINES, "truncated": len(lines) >= MAX_CODE_LINES},
    }


def _build_call(lines: list[CodeLine]) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    implicit_paths: list[dict[str, Any]] = []
    current_function = "entry"

    for line in lines:
        if _is_function_label(line):
            current_function = line.label or line.address or _function_name_from_signature(line.text) or current_function

        call = _extract_call_from_line(line)
        if call:
            callee = call["callee"]
            call_type = _call_type(callee, call["source"])
            calls.append(
                {
                    "line": line.number,
                    "caller": current_function,
                    "callee": callee,
                    "type": call_type,
                    "arguments": call.get("arguments", []),
                    "source": line.raw.strip(),
                }
            )

            if call_type == "indirect":
                implicit_paths.append(
                    {
                        "line": line.number,
                        "kind": "indirect_call",
                        "target": callee,
                        "source": line.raw.strip(),
                    }
                )

            if _name_in_set(callee, CALLBACK_APIS):
                implicit_paths.append(
                    {
                        "line": line.number,
                        "kind": "callback_registration",
                        "target": callee,
                        "callback_candidates": _callback_candidates(call.get("arguments", [])),
                        "source": line.raw.strip(),
                    }
                )

        branch = _extract_branch(line)
        if branch and branch["kind"] in {"indirect_jump", "switch"}:
            implicit_paths.append(
                {
                    "line": line.number,
                    "kind": branch["kind"],
                    "target": branch.get("target") or "unknown",
                    "source": line.raw.strip(),
                }
            )

    chains_by_caller: dict[str, list[str]] = {}
    for call in calls:
        chains_by_caller.setdefault(str(call["caller"]), []).append(str(call["callee"]))

    return {
        "calls": calls,
        "call_chains": [
            {"caller": caller, "sequence": sequence}
            for caller, sequence in chains_by_caller.items()
            if sequence
        ],
        "call_graph_edges": _call_graph_edges(calls),
        "implicit_paths": implicit_paths,
        "indirect_targets": [item for item in implicit_paths if item.get("kind") in {"indirect_call", "indirect_jump"}],
        "callback_registrations": [item for item in implicit_paths if item.get("kind") == "callback_registration"],
        "syscall_calls": [item for item in calls if item.get("type") == "syscall"],
        "api_calls": [item for item in calls if item.get("type") == "api"],
        "dispatch_table_candidates": _dispatch_table_candidates(lines, implicit_paths),
    }


def _build_dfg(lines: list[CodeLine], call: dict[str, Any]) -> dict[str, Any]:
    input_sources: list[dict[str, Any]] = []
    propagation_edges: list[dict[str, Any]] = []
    influence_paths: list[dict[str, Any]] = []
    tainted: set[str] = set()
    source_for: dict[str, str] = {}

    calls_by_line = {item["line"]: item for item in call.get("calls", [])}

    for line in lines:
        call_item = calls_by_line.get(line.number)
        if call_item:
            category = _input_category(str(call_item["callee"]), call_item["source"])
            if category:
                source_id = f"{category}:{call_item['callee']}:{line.number}"
                source_record = {
                    "id": source_id,
                    "line": line.number,
                    "kind": category,
                    "callee": call_item["callee"],
                    "source": call_item["source"],
                }
                input_sources.append(source_record)

                lhs, _ = _assignment_parts(line.text)
                destinations = _input_destinations(str(call_item["callee"]), call_item.get("arguments", []), lhs)
                if not destinations and _is_assembly_call(line.text):
                    destinations = ["rax", "eax"]

                for destination in destinations:
                    clean = _clean_operand(destination)
                    if not clean:
                        continue
                    tainted.add(clean)
                    source_for[clean] = source_id
                    propagation_edges.append(
                        {
                            "from": source_id,
                            "to": clean,
                            "line": line.number,
                            "operation": "input_source",
                        }
                    )

        lhs, rhs = _assignment_parts(line.text)
        if lhs and rhs:
            destination = _clean_operand(lhs)
            source_vars = _extract_identifiers(rhs)
            for source in source_vars:
                propagation_edges.append(
                    {
                        "from": source,
                        "to": destination,
                        "line": line.number,
                        "operation": _instruction_op(line.text) or "assign",
                    }
                )
            tainted_sources = [source for source in source_vars if source in tainted]
            if tainted_sources and destination:
                tainted.add(destination)
                source_for[destination] = source_for.get(tainted_sources[0], tainted_sources[0])

        branch = _extract_branch(line)
        if branch:
            used = _extract_identifiers(str(branch.get("condition") or branch.get("source") or line.text))
            tainted_used = [item for item in used if item in tainted]
            if tainted_used:
                influence_paths.append(
                    {
                        "line": line.number,
                        "kind": "input_to_branch",
                        "variables": tainted_used,
                        "source_ids": sorted({source_for.get(item, item) for item in tainted_used}),
                        "source": line.raw.strip(),
                    }
                )

        if call_item:
            used = _extract_identifiers(" ".join(str(arg) for arg in call_item.get("arguments", [])))
            tainted_used = [item for item in used if item in tainted]
            if tainted_used:
                influence_paths.append(
                    {
                        "line": line.number,
                        "kind": "input_to_call",
                        "variables": tainted_used,
                        "callee": call_item["callee"],
                        "source_ids": sorted({source_for.get(item, item) for item in tainted_used}),
                        "source": line.raw.strip(),
                    }
                )

    return {
        "input_sources": input_sources,
        "propagation_edges": propagation_edges,
        "propagation_chains": _static_propagation_chains(propagation_edges),
        "key_variable_influence_paths": influence_paths,
        "register_flows": _register_flows(propagation_edges),
        "stack_slot_flows": _stack_slot_flows(propagation_edges),
        "memory_data_edges": _memory_data_edges(propagation_edges),
        "flag_dependencies": _flag_dependencies(lines, tainted, source_for),
        "tainted_variables": sorted(tainted),
    }


def _build_memory(lines: list[CodeLine], dfg: dict[str, Any]) -> dict[str, Any]:
    tainted = set(dfg.get("tainted_variables", []))
    reads: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    pointer_paths: list[dict[str, Any]] = []
    potential_exceptions: list[dict[str, Any]] = []

    for index, line in enumerate(lines):
        text = line.text
        op = _instruction_op(text)
        operands = _instruction_operands(text)

        if operands:
            for operand_index, operand in enumerate(operands):
                memory_refs = _memory_refs(operand)
                if not memory_refs and op in {"load", "store", "getelementptr"} and any(symbol in operand for symbol in ("%", "@")):
                    memory_refs = [_clean_operand(operand)]
                for ref in memory_refs:
                    access = _asm_memory_access(op, operand_index)
                    record = {
                        "line": line.number,
                        "location": ref,
                        "operation": op or "memory",
                        "source": line.raw.strip(),
                    }
                    if access in {"read", "read_write"}:
                        reads.append(record)
                    if access in {"write", "read_write"}:
                        writes.append(record)
                        if _tainted_in_text(ref, tainted) or _tainted_in_text(text, tainted):
                            potential_exceptions.append(
                                {
                                    "line": line.number,
                                    "kind": "input_influenced_memory_write",
                                    "structure": "input-derived value reaches a memory write",
                                    "source": line.raw.strip(),
                                }
                            )

        lhs, rhs = _assignment_parts(text)
        if lhs and _is_memory_expression(lhs):
            writes.append(
                {
                    "line": line.number,
                    "location": lhs.strip(),
                    "operation": "write",
                    "source": line.raw.strip(),
                }
            )
            if _tainted_in_text(lhs + " " + rhs, tainted):
                potential_exceptions.append(
                    {
                        "line": line.number,
                        "kind": "input_influenced_memory_write",
                        "structure": "input-derived value reaches a memory write",
                        "source": line.raw.strip(),
                    }
                )
        if rhs:
            for ref in _pseudo_memory_refs(rhs):
                reads.append({"line": line.number, "location": ref, "operation": "read", "source": line.raw.strip()})

        for ref in _pseudo_memory_refs(text):
            if "[" in ref and _has_variable_index(ref) and not _has_near_check(lines, index, _extract_identifiers(ref)):
                potential_exceptions.append(
                    {
                        "line": line.number,
                        "kind": "unchecked_indexed_access",
                        "structure": "indexed memory access without nearby bounds check",
                        "source": line.raw.strip(),
                    }
                )
            if ref.startswith("*") and not _has_near_check(lines, index, _extract_identifiers(ref)):
                potential_exceptions.append(
                    {
                        "line": line.number,
                        "kind": "unchecked_pointer_deref",
                        "structure": "pointer dereference without nearby null or range check",
                        "source": line.raw.strip(),
                    }
                )

        call = _extract_call_from_line(line)
        if call and _name_in_set(call["callee"], MEMORY_COPY_APIS):
            args = call.get("arguments", [])
            writes.append({"line": line.number, "location": args[0] if args else "destination", "operation": call["callee"], "source": line.raw.strip()})
            if len(args) > 1:
                reads.append({"line": line.number, "location": args[1], "operation": call["callee"], "source": line.raw.strip()})
            if len(args) >= 3 and not _is_constant(args[2]):
                potential_exceptions.append(
                    {
                        "line": line.number,
                        "kind": "variable_length_memory_operation",
                        "structure": "memory operation length is variable",
                        "source": line.raw.strip(),
                    }
                )

        pointer_edge = _pointer_assignment(line)
        if pointer_edge:
            pointer_paths.append(pointer_edge)

    return {
        "reads": _dedupe_records(reads),
        "writes": _dedupe_records(writes),
        "access_sequence": _memory_access_sequence(reads, writes),
        "memory_objects": _memory_objects(reads, writes),
        "pointer_propagation_paths": _dedupe_records(pointer_paths),
        "pointer_chains": _pointer_chains(pointer_paths),
        "potential_exception_structures": _dedupe_records(potential_exceptions),
    }


def _infer_semantics(
    cfg: dict[str, Any],
    dfg: dict[str, Any],
    call: dict[str, Any],
    memory: dict[str, Any],
) -> dict[str, Any]:
    calls = call.get("calls", [])
    callee_names = [str(item["callee"]) for item in calls]
    traits: list[str] = []
    evidence: list[str] = []

    input_kinds = {item["kind"] for item in dfg.get("input_sources", [])}
    has_input = bool(input_kinds)
    has_loop = bool(cfg.get("loops"))
    has_indirect = any(item.get("type") == "indirect" for item in calls) or any(
        item.get("kind") in {"indirect_jump", "switch"} for item in call.get("implicit_paths", [])
    )
    has_memory_transform = has_loop and bool(memory.get("reads")) and bool(memory.get("writes"))
    has_api_resolution = any(_name_in_set(name, API_RESOLUTION_APIS) for name in callee_names)
    has_kernel = any(_name_in_set(name, KERNEL_APIS) for name in callee_names)
    has_dispatch = len(cfg.get("branch_paths", [])) >= 3 or has_indirect
    has_stack_model = any(item.get("kind") == "stack_slot" for item in memory.get("memory_objects", []))
    has_symbolic_memory = any(item.get("kind") in {"symbolic_memory", "indexed_memory"} for item in memory.get("memory_objects", []))
    path_count = len(cfg.get("all_paths", []))

    if has_input:
        traits.append("external-input processing")
        evidence.append("DFG contains input sources: " + ", ".join(sorted(input_kinds)))
    if has_memory_transform:
        traits.append("buffer transform loop")
        evidence.append("CFG loop overlaps with memory reads and writes")
    if has_api_resolution:
        traits.append("dynamic API resolution")
        evidence.append("CALL contains loader or resolver APIs")
    if has_dispatch:
        traits.append("control dispatcher")
        evidence.append("CFG contains multiple branches or indirect dispatch")
    if has_kernel:
        traits.append("kernel-facing behavior")
        evidence.append("CALL contains kernel or driver APIs")
    if has_stack_model:
        traits.append("stack-backed state")
        evidence.append("MEMORY contains stack-slot objects")
    if has_symbolic_memory:
        traits.append("symbolic or indexed memory access")
        evidence.append("MEMORY contains symbolic or indexed memory objects")
    if path_count > 1:
        traits.append("multi-path execution model")
        evidence.append(f"CFG enumerates {path_count} bounded paths")

    if has_api_resolution and has_indirect:
        intent = "dynamic routine resolver and indirect dispatcher"
        confidence = 0.78
    elif has_input and has_memory_transform:
        intent = "external data parser or transformer"
        confidence = 0.72
    elif has_dispatch:
        intent = "branch-driven dispatcher or validator"
        confidence = 0.66
    elif has_kernel:
        intent = "kernel-facing control path"
        confidence = 0.65
    elif has_memory_transform:
        intent = "memory transformation routine"
        confidence = 0.62
    else:
        intent = "behavior intent is weakly constrained by structure"
        confidence = 0.45

    return {
        "intent": intent,
        "confidence": confidence,
        "behavior_traits": traits,
        "basis": [
            "control-flow shape",
            "data-source categories",
            "call target categories",
            "memory access structure",
        ],
        "structural_evidence": evidence,
        "execution_model_hints": {
            "path_count": path_count,
            "has_external_input": has_input,
            "has_loop_transform": has_memory_transform,
            "has_indirect_dispatch": has_indirect,
            "has_stack_state": has_stack_model,
            "has_symbolic_memory": has_symbolic_memory,
        },
    }


def _build_risk(
    cfg: dict[str, Any],
    dfg: dict[str, Any],
    call: dict[str, Any],
    memory: dict[str, Any],
) -> dict[str, Any]:
    paths: list[dict[str, Any]] = []
    structures: list[dict[str, Any]] = []
    score = 0

    for item in dfg.get("key_variable_influence_paths", []):
        if item["kind"] == "input_to_branch":
            paths.append(
                {
                    "kind": "input_influenced_branch",
                    "line": item["line"],
                    "structure": "external input influences a branch condition",
                    "source_ids": item.get("source_ids", []),
                    "source": item.get("source"),
                }
            )
            score += 10
        elif item["kind"] == "input_to_call":
            paths.append(
                {
                    "kind": "input_influenced_call",
                    "line": item["line"],
                    "structure": "external input reaches a call argument",
                    "callee": item.get("callee"),
                    "source_ids": item.get("source_ids", []),
                    "source": item.get("source"),
                }
            )
            score += 12

    for item in memory.get("potential_exception_structures", []):
        structures.append(item)
        if item["kind"] == "input_influenced_memory_write":
            score += 25
        elif item["kind"] == "variable_length_memory_operation":
            score += 18
        else:
            score += 12

    for item in call.get("implicit_paths", []):
        if item.get("kind") in {"indirect_call", "indirect_jump", "switch"}:
            structures.append(
                {
                    "line": item.get("line"),
                    "kind": item.get("kind"),
                    "structure": "target is selected indirectly or through a dispatch table",
                    "source": item.get("source"),
                }
            )
            score += 15
        elif item.get("kind") == "callback_registration":
            structures.append(
                {
                    "line": item.get("line"),
                    "kind": "callback_registration",
                    "structure": "execution may continue through a registered callback",
                    "source": item.get("source"),
                }
            )
            score += 8

    if cfg.get("exception_paths"):
        structures.append(
            {
                "kind": "exception_path",
                "structure": "function contains explicit exception or raise path",
                "count": len(cfg.get("exception_paths", [])),
            }
        )
        score += min(15, 5 * len(cfg.get("exception_paths", [])))

    if cfg.get("unresolved_edges"):
        structures.append(
            {
                "kind": "unresolved_control_target",
                "structure": "control edge target could not be resolved statically",
                "count": len(cfg.get("unresolved_edges", [])),
            }
        )
        score += min(18, 6 * len(cfg.get("unresolved_edges", [])))

    for item in memory.get("memory_objects", []):
        if item.get("kind") in {"symbolic_memory", "indexed_memory"} and item.get("write_count"):
            structures.append(
                {
                    "kind": "symbolic_memory_write",
                    "structure": "write target is symbolic or indexed",
                    "object": item.get("object"),
                    "first_line": item.get("first_line"),
                    "last_line": item.get("last_line"),
                }
            )
            score += 10

    for item in dfg.get("flag_dependencies", []):
        if item.get("source_ids"):
            structures.append(
                {
                    "kind": "input_influenced_flag",
                    "structure": "external input reaches a flag-setting comparison",
                    "line": item.get("line"),
                    "source_ids": item.get("source_ids"),
                }
            )
            score += 8

    score = min(score, 100)
    confidence = 0.45 + min(0.45, (len(paths) + len(structures)) * 0.05)

    return {
        "score": score,
        "confidence": round(confidence, 2),
        "paths": _dedupe_records(paths),
        "structures": _dedupe_records(structures),
        "scope": "structural only; no exploit guidance",
    }


def _enumerate_cfg_paths(blocks: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not blocks:
        return []

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source = str(edge.get("from") or "")
        if not source:
            continue
        adjacency.setdefault(source, []).append(edge)

    entry = str(blocks[0].get("id"))
    terminal_ids = {str(block.get("id")) for block in blocks if str(block.get("id")) not in adjacency}
    output: list[dict[str, Any]] = []
    stack: list[tuple[str, list[str], list[str], int]] = [(entry, [entry], [], 0)]
    max_depth = max(4, len(blocks) * 2)
    max_paths = 128

    while stack and len(output) < max_paths:
        node, path, edge_kinds, depth = stack.pop()
        next_edges = adjacency.get(node, [])
        if not next_edges or node in terminal_ids or depth >= max_depth:
            output.append(
                {
                    "path": path,
                    "edge_kinds": edge_kinds,
                    "terminal": node,
                    "truncated": depth >= max_depth and bool(next_edges),
                }
            )
            continue
        for edge in reversed(next_edges):
            target = str(edge.get("to") or "unknown")
            if target in path and edge.get("kind") not in {"conditional_true", "conditional_false", "fallthrough"}:
                output.append(
                    {
                        "path": [*path, target],
                        "edge_kinds": [*edge_kinds, str(edge.get("kind") or "edge")],
                        "terminal": target,
                        "truncated": True,
                        "reason": "loop_or_indirect_cycle",
                    }
                )
                continue
            stack.append((target, [*path, target], [*edge_kinds, str(edge.get("kind") or "edge")], depth + 1))

    return output


def _edge_index(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = []
    for index, edge in enumerate(edges, start=1):
        indexed.append(
            {
                "id": f"E{index}",
                "from": edge.get("from"),
                "to": edge.get("to"),
                "kind": edge.get("kind"),
                "line": edge.get("line"),
                "condition": edge.get("condition"),
            }
        )
    return indexed


def _terminal_blocks(
    blocks: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    return_paths: list[dict[str, Any]],
    exception_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    outgoing = {edge.get("from") for edge in edges}
    terminals = []
    for block in blocks:
        block_id = block.get("id")
        if block_id in outgoing:
            continue
        reason = "fallthrough_end"
        if any(block.get("start_line") <= item.get("line", -1) <= block.get("end_line") for item in return_paths):
            reason = "return"
        if any(block.get("start_line") <= item.get("line", -1) <= block.get("end_line") for item in exception_paths):
            reason = "exception"
        terminals.append(
            {
                "block": block_id,
                "start_line": block.get("start_line"),
                "end_line": block.get("end_line"),
                "reason": reason,
            }
        )
    return terminals


def _call_graph_edges(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _dedupe_records(
        [
            {
                "from": item.get("caller"),
                "to": item.get("callee"),
                "line": item.get("line"),
                "kind": item.get("type"),
            }
            for item in calls
        ]
    )


def _dispatch_table_candidates(lines: list[CodeLine], implicit_paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = []
    for item in implicit_paths:
        if item.get("kind") in {"indirect_jump", "switch"}:
            candidates.append(
                {
                    "line": item.get("line"),
                    "kind": item.get("kind"),
                    "target": item.get("target"),
                    "source": item.get("source"),
                }
            )
    for line in lines:
        lowered = line.text.lower()
        if "jumptable" in lowered or "switch" in lowered or "case " in lowered:
            candidates.append({"line": line.number, "kind": "dispatch_table_hint", "source": line.raw.strip()})
    return _dedupe_records(candidates)


def _static_propagation_chains(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains: dict[str, dict[str, Any]] = {}
    for edge in edges:
        source = str(edge.get("from") or "unknown")
        chain = chains.setdefault(
            source,
            {"source": source, "targets": [], "operations": [], "lines": [], "steps": []},
        )
        chain["targets"].append(edge.get("to"))
        chain["operations"].append(edge.get("operation"))
        chain["lines"].append(edge.get("line"))
        chain["steps"].append(
            {
                "to": edge.get("to"),
                "line": edge.get("line"),
                "operation": edge.get("operation"),
            }
        )
    output = []
    for chain in chains.values():
        line_numbers = [line for line in chain["lines"] if isinstance(line, int)]
        output.append(
            {
                "source": chain["source"],
                "targets": _unique_strings(chain["targets"]),
                "operations": _unique_strings(chain["operations"]),
                "first_line": min(line_numbers) if line_numbers else None,
                "last_line": max(line_numbers) if line_numbers else None,
                "steps": chain["steps"],
            }
        )
    return output


def _register_flows(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flows = []
    for edge in edges:
        source = str(edge.get("from") or "")
        target = str(edge.get("to") or "")
        if _operand_kind(source) == "register" or _operand_kind(target) == "register":
            flows.append(
                {
                    "from": source,
                    "to": target,
                    "from_family": _register_family(source),
                    "to_family": _register_family(target),
                    "line": edge.get("line"),
                    "operation": edge.get("operation"),
                }
            )
    return _dedupe_records(flows)


def _stack_slot_flows(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flows = []
    for edge in edges:
        source = str(edge.get("from") or "")
        target = str(edge.get("to") or "")
        if _operand_kind(source) == "stack_slot" or _operand_kind(target) == "stack_slot":
            flows.append(
                {
                    "from": source,
                    "to": target,
                    "line": edge.get("line"),
                    "operation": edge.get("operation"),
                }
            )
    return _dedupe_records(flows)


def _memory_data_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flows = []
    for edge in edges:
        source = str(edge.get("from") or "")
        target = str(edge.get("to") or "")
        if "memory" in {_operand_kind(source), _operand_kind(target), _operand_kind(source + target)}:
            flows.append(
                {
                    "from": source,
                    "to": target,
                    "line": edge.get("line"),
                    "operation": edge.get("operation"),
                }
            )
    return _dedupe_records(flows)


def _flag_dependencies(lines: list[CodeLine], tainted: set[str], source_for: dict[str, str]) -> list[dict[str, Any]]:
    dependencies = []
    for line in lines:
        op = _instruction_op(line.text)
        if op not in {"cmp", "test", "icmp", "fcmp"} and not line.text.strip().lower().startswith(("if ", "if(")):
            continue
        used = _extract_identifiers(line.text)
        tainted_used = [item for item in used if item in tainted]
        dependencies.append(
            {
                "line": line.number,
                "operation": op or "condition",
                "variables": used,
                "tainted_variables": tainted_used,
                "source_ids": sorted({source_for.get(item, item) for item in tainted_used}),
                "source": line.raw.strip(),
            }
        )
    return _dedupe_records(dependencies)


def _memory_access_sequence(reads: list[dict[str, Any]], writes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sequence = []
    for item in reads:
        sequence.append({**item, "access": "read", "object_kind": _memory_object_kind(item.get("location"))})
    for item in writes:
        sequence.append({**item, "access": "write", "object_kind": _memory_object_kind(item.get("location"))})
    return sorted(_dedupe_records(sequence), key=lambda item: (item.get("line") or 0, item.get("access") or ""))


def _memory_objects(reads: list[dict[str, Any]], writes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for access, items in (("read", reads), ("write", writes)):
        for item in items:
            location = str(item.get("location") or "unknown")
            object_id = _memory_object_id(location)
            record = grouped.setdefault(
                object_id,
                {
                    "object": object_id,
                    "location": location,
                    "kind": _memory_object_kind(location),
                    "read_count": 0,
                    "write_count": 0,
                    "first_line": item.get("line"),
                    "last_line": item.get("line"),
                    "operations": [],
                },
            )
            if access == "read":
                record["read_count"] += 1
            else:
                record["write_count"] += 1
            if isinstance(item.get("line"), int):
                record["first_line"] = min(record["first_line"], item["line"]) if record["first_line"] is not None else item["line"]
                record["last_line"] = max(record["last_line"], item["line"]) if record["last_line"] is not None else item["line"]
            record["operations"].append(item.get("operation"))
    output = []
    for record in grouped.values():
        record["operations"] = _unique_strings(record["operations"])
        output.append(record)
    return sorted(output, key=lambda item: (item.get("first_line") or 0, item.get("object") or ""))


def _pointer_chains(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains = []
    for item in paths:
        chains.append(
            {
                "from": item.get("from"),
                "to": item.get("to"),
                "kind": item.get("kind"),
                "line": item.get("line"),
                "source_kind": _memory_object_kind(item.get("from")),
                "target_kind": _memory_object_kind(item.get("to")),
            }
        )
    return _dedupe_records(chains)


def _operand_kind(value: str) -> str:
    text = _clean_operand(value).lower()
    if not text:
        return "unknown"
    if _register_family(text):
        return "register"
    if any(reg in text for reg in ("rsp", "rbp", "esp", "ebp", "sp", "bp")) and ("[" in text or "+" in text or "-" in text):
        return "stack_slot"
    if "[" in text or "]" in text or text.startswith("*"):
        return "memory"
    if re.fullmatch(r"0x[0-9a-f]+|[0-9a-f]+h|\d+", text):
        return "constant"
    return "symbol"


def _register_family(value: str) -> str | None:
    text = _clean_operand(value).lower().strip("[]")
    aliases = {
        "rax": {"rax", "eax", "ax", "al", "ah"},
        "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
        "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},
        "rsp": {"rsp", "esp", "sp", "spl"},
    }
    for family, names in aliases.items():
        if text in names:
            return family
    match = re.fullmatch(r"(r1[0-5]|r[8-9]|r\d+)(?:d|w|b)?", text)
    if match:
        return match.group(1)
    return None


def _memory_object_id(value: Any) -> str:
    text = _clean_operand(str(value or "unknown")).lower()
    if not text:
        return "mem:unknown"
    return "mem:" + re.sub(r"\s+", "", text)


def _memory_object_kind(value: Any) -> str:
    text = _clean_operand(str(value or "")).lower()
    if any(reg in text for reg in ("rsp", "rbp", "esp", "ebp", "sp", "bp")):
        return "stack_slot"
    if any(token in text for token in ("heap", "malloc", "alloc", "new", "pool")):
        return "heap_candidate"
    if any(token in text for token in ("global", "static", ".data", ".bss", ".rdata")):
        return "global_or_static"
    if "[" in text and _has_variable_index(text):
        return "indexed_memory"
    if "[" in text or text.startswith("*"):
        return "symbolic_memory"
    if re.fullmatch(r"0x[0-9a-f]+|[0-9a-f]+h|\d+", text):
        return "absolute_address"
    return "symbolic_memory" if text else "unknown"


def _extract_branch(line: CodeLine) -> dict[str, Any] | None:
    text = line.text.strip()
    lowered = text.lower()

    if _looks_like_loop(text):
        return {
            "kind": "conditional",
            "condition": _condition_text(text),
            "target": None,
            "source": line.raw.strip(),
        }

    if lowered.startswith("if ") or lowered.startswith("if("):
        goto_match = re.search(r"\bgoto\s+([^;\s]+)", text, flags=re.IGNORECASE)
        return {
            "kind": "conditional",
            "condition": _condition_text(text),
            "target": _normalize_target(goto_match.group(1)) if goto_match else None,
            "source": line.raw.strip(),
        }

    if lowered.startswith("switch") or lowered.startswith("case "):
        return {
            "kind": "switch",
            "condition": _condition_text(text),
            "target": None,
            "source": line.raw.strip(),
        }

    goto_match = re.match(r"goto\s+([^;\s]+)", text, flags=re.IGNORECASE)
    if goto_match:
        return {
            "kind": "unconditional",
            "condition": None,
            "target": _normalize_target(goto_match.group(1)),
            "source": line.raw.strip(),
        }

    op = _instruction_op(text)
    if not op:
        return None

    operands = _instruction_operands(text)
    target = _normalize_target(operands[0]) if operands else None
    if op in CONDITIONAL_JUMPS or (op.startswith("b.") and op != "b"):
        return {
            "kind": "conditional",
            "condition": op,
            "target": target,
            "source": line.raw.strip(),
        }
    if op == "br":
        if len(operands) >= 3 and operands[0].strip().lower().startswith("i1"):
            return {
                "kind": "conditional",
                "condition": operands[0].strip(),
                "target": _normalize_target(operands[1]),
                "false_target": _normalize_target(operands[2]),
                "source": line.raw.strip(),
            }
        if operands:
            return {
                "kind": "unconditional",
                "condition": None,
                "target": _normalize_target(operands[-1]),
                "source": line.raw.strip(),
            }
    if op in UNCONDITIONAL_JUMPS:
        return {
            "kind": "indirect_jump" if target and _is_indirect_target(target) else "unconditional",
            "condition": None,
            "target": target,
            "source": line.raw.strip(),
        }
    return None


def _extract_call_from_line(line: CodeLine) -> dict[str, Any] | None:
    text = line.text.strip()
    lowered = text.lower()
    if lowered.startswith(("define ", "declare ")):
        return None

    ir = re.search(
        r"\b(?:tail\s+)?call\b.*?(?:@|%)([A-Za-z_.$?@][\w.$?@<>~\-]*)\s*\((.*?)\)",
        text,
    )
    if ir:
        callee = ir.group(1)
        return {
            "callee": f"@{callee}" if not callee.startswith(("@", "%")) else callee,
            "arguments": _split_operands(ir.group(2)),
            "source": line.raw.strip(),
        }

    asm = re.match(r"^(?:call|bl|blr)\s+(.+)$", text, flags=re.IGNORECASE)
    if asm:
        target = _normalize_target(asm.group(1))
        return {"callee": target or "unknown", "arguments": [], "source": line.raw.strip()}

    for match in re.finditer(r"\b([A-Za-z_.$?@][\w.$?@<>~]*)\s*\(([^()]*)\)", text):
        callee = match.group(1)
        if callee in CONTROL_KEYWORDS:
            continue
        if _looks_like_function_definition(text, match):
            continue
        return {
            "callee": callee,
            "arguments": _split_operands(match.group(2)),
            "source": line.raw.strip(),
        }
    return None


def _assignment_parts(text: str) -> tuple[str | None, str | None]:
    stripped = text.strip().rstrip(";")
    lowered = stripped.lower()
    if lowered.startswith(("if ", "if(", "while ", "while(", "for ", "for(", "switch ", "switch(", "return ")):
        return None, None

    asm_op = _instruction_op(stripped)
    if asm_op in ASSIGNMENT_OPS:
        operands = _instruction_operands(stripped)
        if len(operands) >= 2:
            if asm_op == "xor" and _clean_operand(operands[0]) == _clean_operand(operands[1]):
                return _clean_operand(operands[0]), "0"
            return operands[0], ", ".join(operands[1:])

    match = re.match(r"^(.+?)\s*([+\-*/&|^]?=)\s*(.+)$", stripped)
    if not match:
        return None, None
    lhs = match.group(1).strip()
    rhs = match.group(3).strip()
    if any(token in lhs for token in ("==", "!=", "<=", ">=")) or len(lhs) > 120:
        return None, None
    return lhs, rhs


def _instruction_op(text: str) -> str | None:
    match = re.match(r"^\s*([A-Za-z.][\w.]*)\b", text)
    if not match:
        return None
    return match.group(1).lower()


def _instruction_operands(text: str) -> list[str]:
    match = re.match(r"^\s*[A-Za-z.][\w.]*\s+(.+)$", text)
    if not match:
        return []
    return _split_operands(match.group(1))


def _split_operands(value: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    depth = 0
    for char in value:
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        items.append(item)
    return items


def _resolve_target_index(target: Any, label_to_line: dict[str, int]) -> int | None:
    if not target:
        return None
    normalized = _normalize_target(str(target))
    candidates = {normalized}
    if normalized.startswith("0x"):
        candidates.add(normalized[2:])
    else:
        candidates.add("0x" + normalized)
    for candidate in candidates:
        if candidate in label_to_line:
            return label_to_line[candidate]
    return None


def _normalize_target(value: str | None) -> str:
    if not value:
        return ""
    cleaned = value.strip().strip(",;")
    cleaned = re.sub(r"^(?:label\s+|blockaddress\s+)", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.lstrip("%@")
    cleaned = re.sub(r"\b(?:short|near|far|ptr|offset|qword|dword|word|byte)\b", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip()
    if cleaned.endswith("h") and re.fullmatch(r"[0-9A-Fa-f]+h", cleaned):
        cleaned = "0x" + cleaned[:-1]
    if re.fullmatch(r"0x[0-9A-Fa-f]+", cleaned):
        return "0x" + cleaned[2:].lower()
    if re.fullmatch(r"[0-9A-Fa-f]{4,16}", cleaned):
        return cleaned.lower()
    return cleaned


def _line_index_by_number(lines: list[CodeLine], number: int) -> int | None:
    for index, line in enumerate(lines):
        if line.number == number:
            return index
    return None


def _next_block_id(block_id: str, blocks: list[dict[str, Any]]) -> str | None:
    for index, block in enumerate(blocks):
        if block["id"] == block_id and index + 1 < len(blocks):
            return str(blocks[index + 1]["id"])
    return None


def _case_targets(lines: list[CodeLine]) -> list[str]:
    targets = []
    for line in lines:
        text = line.text.strip().lower()
        if line.label and line.label.lower().startswith("case"):
            targets.append(line.label)
        elif text.startswith("case "):
            targets.append(f"line:{line.number}")
    return targets[:64]


def _looks_like_loop(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered.startswith(("while ", "while(", "for ", "for(", "do ")) or _instruction_op(lowered) in {
        "loop",
        "loope",
        "loopne",
        "loopnz",
        "loopz",
    }


def _condition_text(text: str) -> str:
    match = re.search(r"\((.*)\)", text)
    if match:
        return match.group(1).strip()
    return text.strip()


def _is_return(text: str) -> bool:
    op = _instruction_op(text)
    return op in RETURN_TERMS or text.strip().lower().startswith("return")


def _is_exception_line(text: str) -> bool:
    lowered = text.lower()
    return any(term.lower() in lowered for term in THROW_TERMS) or any(
        token in lowered for token in ("__try", "__except", " catch", " catch(", " finally", "seh")
    )


def _exception_kind(text: str) -> str:
    lowered = text.lower()
    if "catch" in lowered or "__except" in lowered:
        return "handler"
    if "finally" in lowered:
        return "cleanup"
    if "try" in lowered:
        return "protected_region"
    return "raise"


def _is_function_label(line: CodeLine) -> bool:
    if line.label and re.search(r"^(?:sub_|func_|fn_|[A-Za-z_.$?@][\w.$?@<>~]*)$", line.label):
        return True
    return bool(_function_name_from_signature(line.text))


def _function_name_from_signature(text: str) -> str | None:
    match = re.match(r"^(?:[\w:*&<>]+\s+)+([A-Za-z_.$?@][\w.$?@<>~]*)\s*\([^;]*\)\s*\{?$", text.strip())
    return match.group(1) if match else None


def _looks_like_function_definition(text: str, match: re.Match[str]) -> bool:
    prefix = text[: match.start()].strip()
    suffix = text[match.end() :].strip()
    return not prefix and suffix in {"", "{"} and bool(_function_name_from_signature(text))


def _call_type(callee: str, source: str) -> str:
    lowered = callee.lower()
    if _is_indirect_target(callee):
        return "indirect"
    if lowered in {"syscall", "sysenter"} or "int 0x2e" in source.lower() or "int 2eh" in source.lower():
        return "syscall"
    if any(_name_equals(callee, api) for values in INPUT_SOURCE_APIS.values() for api in values):
        return "api"
    if _name_in_set(callee, API_RESOLUTION_APIS | MEMORY_COPY_APIS | CALLBACK_APIS | KERNEL_APIS):
        return "api"
    return "direct"


def _is_indirect_target(target: str) -> bool:
    return any(token in target for token in ("[", "]", "*", "(", ")")) or re.fullmatch(r"r\d+|[re]?[abcd]x|[re]?(si|di|bp|sp)", target, flags=re.IGNORECASE) is not None


def _name_in_set(name: str, values: set[str]) -> bool:
    return any(_name_equals(name, item) for item in values)


def _name_equals(name: str, expected: str) -> bool:
    return _symbol_name(name) == _symbol_name(expected)


def _callback_candidates(arguments: list[str]) -> list[str]:
    candidates = []
    for argument in arguments:
        identifiers = _extract_identifiers(argument)
        for identifier in identifiers:
            if identifier.lower() not in {"null", "0"}:
                candidates.append(identifier)
    return candidates[:8]


def _input_category(callee: str, source: str) -> str | None:
    lowered_source = source.lower()
    for category, apis in INPUT_SOURCE_APIS.items():
        for api in apis:
            if _name_equals(callee, api) or api.lower() in lowered_source:
                return category
    return None


def _input_destinations(callee: str, arguments: list[str], lhs: str | None) -> list[str]:
    destinations: list[str] = []
    if lhs:
        destinations.append(lhs)

    lowered = callee.lower()
    buffer_index_by_api = {
        "recv": 1,
        "recvfrom": 1,
        "wsarecv": 1,
        "readfile": 1,
        "ntreadfile": 5,
        "zwreadfile": 5,
        "fread": 0,
        "read": 1,
        "_read": 1,
        "internetreadfile": 1,
        "winhttpreaddata": 1,
        "deviceiocontrol": 5,
    }
    for api, index in buffer_index_by_api.items():
        if api in lowered and len(arguments) > index:
            destinations.append(arguments[index])
    return destinations


def _is_assembly_call(text: str) -> bool:
    return bool(re.match(r"^\s*(?:call|bl|blr)\b", text, flags=re.IGNORECASE))


def _extract_identifiers(text: str) -> list[str]:
    cleaned = re.sub(r'"[^"]*"|\'[^\']*\'', " ", text)
    cleaned = re.sub(r"\b(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|\d+)\b", " ", cleaned)
    identifiers: list[str] = []
    for match in re.finditer(
        r"(?:[%@][A-Za-z_.$?][\w.$?@<>~\-]*)|\b[A-Za-z_][\w@$?]*\b|\b(?:r\d+|[re]?[abcd]x|[re]?(?:si|di|bp|sp)|[abcd][lh])\b",
        cleaned,
    ):
        item = match.group(0)
        if _symbol_name(item) in IDENTIFIER_STOPWORDS:
            continue
        if item not in identifiers:
            identifiers.append(item)
    return identifiers


def _clean_operand(value: str | None) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"\b(?:qword|dword|word|byte|ptr|short|near|far|offset)\b", "", value, flags=re.IGNORECASE)
    cleaned = cleaned.strip().strip("();")
    return cleaned


def _memory_refs(operand: str) -> list[str]:
    refs = []
    for match in re.finditer(r"\[[^\]]+\]", operand):
        refs.append(match.group(0))
    return refs


def _pseudo_memory_refs(text: str) -> list[str]:
    refs = []
    for match in re.finditer(r"\*[A-Za-z_@$][\w@$?]*(?:\s*\+\s*[^;,)]+)?", text):
        refs.append(match.group(0).strip())
    for match in re.finditer(r"\b[A-Za-z_@$][\w@$?]*\s*\[[^\]]+\]", text):
        refs.append(match.group(0).strip())
    return refs


def _asm_memory_access(op: str | None, operand_index: int) -> str:
    if op == "lea":
        return "address"
    if op == "store":
        return "write" if operand_index > 0 else "read"
    if op == "load":
        return "read"
    if op == "getelementptr":
        return "address"
    if op in READ_ONLY_OPS:
        return "read"
    if op in WRITE_FIRST_OPERAND_OPS and operand_index == 0:
        return "write"
    if op in {"add", "sub", "xor", "and", "or", "inc", "dec"} and operand_index == 0:
        return "read_write"
    return "read"


def _is_memory_expression(text: str) -> bool:
    stripped = text.strip()
    return stripped.startswith("*") or "[" in stripped or "]" in stripped


def _tainted_in_text(text: str, tainted: set[str]) -> bool:
    return any(identifier in tainted for identifier in _extract_identifiers(text))


def _has_variable_index(ref: str) -> bool:
    inside = ref[ref.find("[") + 1 : ref.rfind("]")] if "[" in ref and "]" in ref else ref
    identifiers = _extract_identifiers(inside)
    return bool(identifiers)


def _has_near_check(lines: list[CodeLine], index: int, identifiers: list[str]) -> bool:
    if not identifiers:
        return False
    start = max(0, index - 6)
    window = " ".join(line.text for line in lines[start:index])
    lowered = window.lower()
    if not any(identifier.lower() in lowered for identifier in identifiers):
        return False
    return any(token in lowered for token in ("cmp", "test", "if", "<", ">", "==", "!=", "length", "size", "count", "bound", "limit"))


def _is_constant(value: str) -> bool:
    return bool(re.fullmatch(r"\s*(?:0x[0-9A-Fa-f]+|[0-9]+|sizeof\s*\(.+\))\s*", value))


def _pointer_assignment(line: CodeLine) -> dict[str, Any] | None:
    lhs, rhs = _assignment_parts(line.text)
    op = _instruction_op(line.text)
    if op == "lea" and lhs and rhs:
        return {"line": line.number, "from": rhs, "to": lhs, "kind": "address_calculation", "source": line.raw.strip()}
    if op == "getelementptr" and lhs and rhs:
        return {"line": line.number, "from": rhs, "to": lhs, "kind": "pointer_arithmetic", "source": line.raw.strip()}
    if lhs and rhs and ("&" in rhs or _is_memory_expression(rhs)):
        return {"line": line.number, "from": rhs, "to": lhs, "kind": "pointer_propagation", "source": line.raw.strip()}
    return None


def _unique_strings(items: list[Any]) -> list[str]:
    seen = set()
    output = []
    for item in items:
        if item is None:
            continue
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for record in records:
        key = tuple(sorted((str(key), str(value)) for key, value in record.items()))
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


def _symbol_name(value: str) -> str:
    return re.sub(r"^[%@]+", "", value).lower().strip("_")
