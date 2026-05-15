from pathlib import Path

from reverse_framework.api import analyze_code_text, analyze_execution_evidence, analyze_target, available_analyzers
from reverse_framework.core.config import TriageConfig


def test_available_analyzers_include_kernel_security() -> None:
    assert "kernel_security" in available_analyzers()
    assert "obfuscation_profile" in available_analyzers()
    assert "code_structure" in available_analyzers()
    assert "execution_trace" in available_analyzers()
    assert "process_memory" in available_analyzers()
    assert "perf_scan" in available_analyzers()
    assert "dll_audit" in available_analyzers()


def test_analyze_target_returns_kernel_security_finding(tmp_path: Path) -> None:
    sample = tmp_path / "driver.sys"
    sample.write_bytes(
        b"\\Device\\AcmeDrv\x00"
        b"IoCreateDevice\x00"
        b"IRP_MJ_DEVICE_CONTROL\x00"
        b"MmMapIoSpace\x00"
    )

    result = analyze_target(sample, config=TriageConfig(enabled_analyzers=["kernel_security"]))

    assert "kernel_security" in result.findings
    assert result.findings["kernel_security"]["driver_like"] is True


def test_analyze_code_text_returns_structured_sections() -> None:
    result = analyze_code_text(
        "call recv\nmov [rsp+20h], rax\ncmp eax, 0\njle loc_exit\nloc_exit:\nret\n",
        config=TriageConfig(enabled_analyzers=["code_structure"]),
    )

    structure = result.findings["code_structure"]
    assert set(["CFG", "DFG", "CALL", "MEMORY", "SEMANTICS", "RISK"]).issubset(structure.keys())


def test_analyze_execution_evidence_uses_static_baseline() -> None:
    static_report = {
        "CFG": {
            "branch_paths": [
                {
                    "line": 3,
                    "kind": "conditional",
                    "condition": "len > 0",
                    "true_target": "decrypt_buffer",
                    "false_target": "exit",
                },
                {
                    "line": 8,
                    "kind": "conditional",
                    "condition": "guard_hidden",
                    "true_target": "hidden_path",
                    "false_target": "exit",
                },
            ]
        },
        "DFG": {
            "input_sources": [
                {"id": "network:recv:1", "kind": "network", "callee": "recv", "source": "recv"},
                {
                    "id": "api:LoadLibraryA:2",
                    "kind": "api",
                    "callee": "LoadLibraryA",
                    "source": "LoadLibraryA",
                },
            ],
            "key_variable_influence_paths": [
                {
                    "line": 3,
                    "kind": "input_to_branch",
                    "source_ids": ["network:recv:1"],
                    "variables": ["len"],
                    "source": "len > 0",
                },
                {
                    "line": 4,
                    "kind": "input_to_call",
                    "source_ids": ["network:recv:1"],
                    "variables": ["buf"],
                    "callee": "decrypt_buffer",
                    "source": "decrypt_buffer(buf)",
                },
                {
                    "line": 8,
                    "kind": "input_to_branch",
                    "source_ids": ["api:LoadLibraryA:2"],
                    "variables": ["flag"],
                    "source": "flag",
                },
            ],
        },
        "CALL": {
            "calls": [
                {"callee": "recv"},
                {"callee": "LoadLibraryA"},
                {"callee": "decrypt_buffer"},
            ]
        },
        "SEMANTICS": {"intent": "external-input processing"},
    }

    evidence = {
        "events": [
            {"kind": "call", "function": "recv"},
            {"kind": "call", "function": "decrypt_buffer"},
            {"kind": "syscall", "syscall": "NtReadFile"},
            {"kind": "memory", "label": "write", "address": "0x401000", "value": "0x01"},
            {"kind": "io", "input": "seed", "output": "active"},
            {"kind": "state", "name": "mode", "before": "idle", "after": "active"},
            {"kind": "branch", "condition": "len > 0", "taken": True, "target": "decrypt_buffer"},
        ]
    }

    result = analyze_execution_evidence(
        evidence,
        static_report=static_report,
        config=TriageConfig(enabled_analyzers=["execution_trace"]),
    )

    trace = result.findings["execution_trace"]
    assert trace["EXEC_FLOW"]["actual_execution"]["function_sequence"] == ["recv", "decrypt_buffer"]
    assert "LoadLibraryA" in trace["EXEC_FLOW"]["static_cfg_diff"]["missing_static_functions"]
    assert trace["STATE"]["switch_count"] >= 1
    assert trace["DATAFLOW"]["triggered_static_paths"]
    assert trace["DATAFLOW"]["untriggered_static_paths"]
    assert trace["DATAFLOW"]["validation"]["source_coverage"] == 0.5
    assert not any(item.get("name") == "recv" for item in trace["DATAFLOW"]["runtime_only_sources"])
    assert trace["DIFF"]["baseline_status"] == "available"
    assert trace["DIFF"]["hidden_paths"]
    assert set(["EXEC_MODEL", "MEMORY_MODEL", "STATE_TRANSITION", "UNCERTAINTY"]).issubset(trace.keys())
    assert trace["EXEC_MODEL"]["state_machine"]["transitions"]
    assert trace["MEMORY_MODEL"]["data_lifecycle"]["creation"]
    assert trace["STATE_TRANSITION"]["summary"]["transition_count"] >= 1
    assert trace["UNCERTAINTY"]["possible_hidden_paths"]


def test_execution_evidence_maps_io_to_state_transition() -> None:
    result = analyze_execution_evidence(
        {"events": [{"kind": "io", "input": "seed", "output": "active"}]},
        config=TriageConfig(enabled_analyzers=["execution_trace"]),
    )

    trace = result.findings["execution_trace"]
    assert trace["STATE"]["state_change_count"] == 1
    assert trace["STATE_TRANSITION"]["transitions"]
    assert trace["EXEC_MODEL"]["runtime_abstraction"]["external_inputs"]


def test_execution_evidence_reconstructs_path_and_memory_objects() -> None:
    result = analyze_execution_evidence(
        {
            "events": [
                {"kind": "call", "function": "recv"},
                {"kind": "memory", "label": "write", "address": "rsp+20h", "value": "0x01"},
                {"kind": "memory", "label": "write", "address": "mystery_ptr", "value": "0x02"},
                {"kind": "call", "function": "decrypt_buffer"},
                {"kind": "return"},
                {"kind": "branch", "condition": "len > 0", "taken": True, "target": "decrypt_buffer"},
            ]
        },
        static_code="call recv\ncall decrypt_buffer\nret\n",
        config=TriageConfig(enabled_analyzers=["execution_trace"]),
    )

    trace = result.findings["execution_trace"]
    assert trace["EXEC_FLOW"]["actual_execution"]["execution_path"]
    assert trace["EXEC_FLOW"]["actual_execution"]["call_stack_frames"]
    assert trace["EXEC_FLOW"]["actual_execution"]["call_edges"]
    assert trace["EXEC_FLOW"]["actual_execution"]["execution_segments"]
    assert trace["EXEC_FLOW"]["static_cfg_diff"]["path_signature"]
    assert trace["MEMORY_MODEL"]["objects"]
    assert "stack_slot" in trace["MEMORY_MODEL"]["access_patterns"]["address_kinds"]
    assert "symbolic_address" in trace["MEMORY_MODEL"]["access_patterns"]["address_kinds"]
    assert trace["DATAFLOW"]["propagation_chains"]
    assert trace["EXEC_MODEL"]["runtime_abstraction"]["phase_sequence"]
    assert trace["STATE_TRANSITION"]["transition_rules"]
    assert trace["UNCERTAINTY"]["symbolic_memory_objects"]


def test_execution_evidence_json_string_with_static_code_is_expanded() -> None:
    evidence = (
        '{"events":['
        '{"kind":"call","function":"recv"},'
        '{"kind":"memory","label":"write","address":"rsp+20h","value":"0x01"},'
        '{"kind":"branch","condition":"len > 0","taken":true,"target":"decrypt_buffer"}'
        "]}"
    )

    result = analyze_execution_evidence(
        evidence,
        static_code="call recv\ncall decrypt_buffer\nret\n",
        config=TriageConfig(enabled_analyzers=["execution_trace"]),
    )

    trace = result.findings["execution_trace"]
    assert len(trace["EXEC_FLOW"]["actual_execution"]["execution_path"]) == 3
    assert trace["MEMORY_MODEL"]["objects"]
    assert trace["STATE_TRANSITION"]["transition_rules"]
