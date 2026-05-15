from reverse_framework.analyzers.indicators import _detect_capabilities


def test_detects_process_injection_capability() -> None:
    capabilities = _detect_capabilities(b"VirtualAlloc WriteProcessMemory")

    assert "process_injection" in capabilities
    assert "VirtualAlloc" in capabilities["process_injection"]

