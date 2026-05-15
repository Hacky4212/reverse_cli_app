from reverse_framework.api import analyze_code_text, available_analyzers
from reverse_framework.core.config import TriageConfig


def test_available_analyzers_include_code_structure() -> None:
    assert "code_structure" in available_analyzers()


def test_analyze_code_text_structures_reverse_flow() -> None:
    code = """
sub_1000:
    call recv
    mov [rsp+20h], rax
    cmp eax, 0
    jle loc_exit
    mov rcx, [rsp+20h]
    call GetProcAddress
loc_loop:
    mov al, [rsi+rcx]
    xor al, dl
    mov [rdi+rcx], al
    inc rcx
    cmp rcx, rbx
    jl loc_loop
loc_exit:
    ret
"""

    result = analyze_code_text(
        code,
        target_name="sample.asm",
        config=TriageConfig(enabled_analyzers=["code_structure"]),
    )

    structure = result.findings["code_structure"]
    assert structure["input_kind"] in {"assembly", "mixed"}
    assert structure["CFG"]["loops"]
    assert structure["CFG"]["all_paths"]
    assert structure["CFG"]["edge_index"]
    assert structure["DFG"]["input_sources"]
    assert structure["DFG"]["propagation_chains"]
    assert structure["DFG"]["register_flows"]
    assert structure["DFG"]["stack_slot_flows"]
    assert structure["CALL"]["calls"]
    assert structure["CALL"]["call_graph_edges"]
    assert structure["MEMORY"]["writes"]
    assert structure["MEMORY"]["memory_objects"]
    assert structure["MEMORY"]["access_sequence"]
    assert structure["SEMANTICS"]["intent"]
    assert structure["SEMANTICS"]["execution_model_hints"]
    assert structure["RISK"]["score"] >= 0
