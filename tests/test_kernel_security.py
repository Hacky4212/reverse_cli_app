from pathlib import Path

from reverse_framework.analyzers.kernel_security import KernelSecurityAnalyzer
from reverse_framework.core.context import AnalysisContext


def test_kernel_security_detects_risky_ioctl_surface(tmp_path: Path) -> None:
    sample = tmp_path / "driver.sys"
    sample.write_bytes(
        b"\\Device\\AcmeDrv\x00"
        b"IoCreateDevice\x00"
        b"IRP_MJ_DEVICE_CONTROL\x00"
        b"MmMapIoSpace\x00"
    )
    context = AnalysisContext(target=sample)

    KernelSecurityAnalyzer().run(context)

    finding = context.findings["kernel_security"]
    assert finding["driver_like"] is True
    assert "ioctl_surface" in finding["capabilities"]
    assert "kernel_memory_access" in finding["capabilities"]
    assert any(issue.id == "risky_kernel_ioctl_surface" for issue in context.issues)

