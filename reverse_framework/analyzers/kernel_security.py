from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, Indicator


KERNEL_TERMS = {
    "device_interface": [
        b"IoCreateDevice",
        b"IoCreateDeviceSecure",
        b"IoCreateSymbolicLink",
        b"\\Device\\",
        b"\\DosDevices\\",
    ],
    "ioctl_surface": [
        b"IRP_MJ_DEVICE_CONTROL",
        b"DeviceIoControl",
        b"IOCTL",
        b"METHOD_BUFFERED",
        b"METHOD_NEITHER",
        b"FILE_ANY_ACCESS",
    ],
    "kernel_memory_access": [
        b"MmMapIoSpace",
        b"MmCopyVirtualMemory",
        b"MmGetPhysicalAddress",
        b"MmMapLockedPagesSpecifyCache",
        b"ZwMapViewOfSection",
    ],
    "process_thread_access": [
        b"PsLookupProcessByProcessId",
        b"PsGetCurrentProcess",
        b"PsSetCreateProcessNotifyRoutine",
        b"PsSetCreateThreadNotifyRoutine",
        b"PsSetLoadImageNotifyRoutine",
        b"ObOpenObjectByPointer",
    ],
    "registry_or_driver_loading": [
        b"ZwLoadDriver",
        b"ZwUnloadDriver",
        b"ZwCreateKey",
        b"ZwSetValueKey",
        b"RtlWriteRegistryValue",
    ],
    "kernel_callbacks": [
        b"ObRegisterCallbacks",
        b"CmRegisterCallback",
        b"PsSetCreateProcessNotifyRoutine",
        b"PsSetCreateThreadNotifyRoutine",
        b"PsSetLoadImageNotifyRoutine",
    ],
    "kernel_tamper": [
        b"KeServiceDescriptorTable",
        b"KiServiceTable",
        b"SSDT",
        b"PatchGuard",
        b"g_CiOptions",
        b"DisableIntegrityChecks",
        b"CR0",
        b"MSR",
    ],
    "known_vulnerable_driver_reference": [
        b"WinRing0",
        b"RTCore64",
        b"RTCore32",
        b"ASIO",
        b"GDRV",
        b"DBUtil",
        b"iqvw64e",
        b"eneio64",
        b"PROCEXP",
        b"NalDrv",
    ],
}

DEVICE_PATTERNS = {
    "kernel_device": re.compile(rb"\\Device\\[A-Za-z0-9_.-]{2,80}"),
    "dos_device": re.compile(rb"\\DosDevices\\[A-Za-z0-9_.-]{2,80}"),
    "nt_device_alias": re.compile(rb"\\\?\?\\[A-Za-z0-9_.-]{2,80}"),
}

SUBSYSTEMS = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
}


class KernelSecurityAnalyzer:
    name = "kernel_security"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        pe = _parse_pe_kernel_metadata(data)
        capabilities = _detect_kernel_capabilities(data)
        device_names = _extract_device_names(data)
        driver_like = _is_driver_like(context.target, pe, capabilities, device_names)
        risk_score = _risk_score(driver_like, pe, capabilities)

        for item in device_names:
            context.add_indicator(
                Indicator(
                    kind=item["kind"],
                    value=item["value"],
                    source=self.name,
                    offset=item["offset"],
                )
            )

        context.add_finding(
            self.name,
            {
                "driver_like": driver_like,
                "risk_score": risk_score,
                "pe": pe,
                "capabilities": capabilities,
                "device_names": device_names,
            },
        )

        _add_kernel_issues(context, driver_like, risk_score, pe, capabilities)


def _parse_pe_kernel_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"format": "not_pe"}

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return {"format": "invalid_pe"}

    _, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data) or optional_size < 72:
        return {
            "format": "PE",
            "valid": False,
            "sections": sections,
            "characteristics": hex(characteristics),
            "error": "Optional header is truncated.",
        }

    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    data_directory_offset = optional_offset + 96 if optional_magic == 0x10B else optional_offset + 112
    subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
    dll_characteristics = struct.unpack_from("<H", data, optional_offset + 70)[0]
    cert_size = 0
    if data_directory_offset + 8 * 5 <= len(data):
        _, cert_size = struct.unpack_from("<II", data, data_directory_offset + 8 * 4)

    return {
        "format": "PE",
        "valid": True,
        "sections": sections,
        "optional_header_magic": "PE32" if optional_magic == 0x10B else "PE32+" if optional_magic == 0x20B else hex(optional_magic),
        "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
        "subsystem_value": subsystem,
        "characteristics": hex(characteristics),
        "dll_characteristics": hex(dll_characteristics),
        "certificate_table_size": cert_size,
        "certificate_table_present": cert_size > 0,
    }


def _detect_kernel_capabilities(data: bytes) -> dict[str, list[str]]:
    lowered = data.lower()
    found: dict[str, list[str]] = {}
    for category, terms in KERNEL_TERMS.items():
        hits = []
        for term in terms:
            if term.lower() in lowered:
                hits.append(term.decode("ascii", errors="replace"))
        if hits:
            found[category] = hits
    return found


def _extract_device_names(data: bytes) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen = set()
    for kind, pattern in DEVICE_PATTERNS.items():
        for match in pattern.finditer(data):
            value = match.group(0).decode("ascii", errors="replace")
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            items.append({"kind": kind, "value": value, "offset": match.start()})
    return items[:100]


def _is_driver_like(
    target: Path,
    pe: dict[str, Any],
    capabilities: dict[str, list[str]],
    device_names: list[dict[str, Any]],
) -> bool:
    if target.suffix.lower() == ".sys":
        return True
    if pe.get("subsystem") == "NATIVE":
        return True
    if "device_interface" in capabilities or device_names:
        return True
    return False


def _risk_score(driver_like: bool, pe: dict[str, Any], capabilities: dict[str, list[str]]) -> int:
    score = 0
    if driver_like:
        score += 20
    if "ioctl_surface" in capabilities:
        score += 20
    if "kernel_memory_access" in capabilities:
        score += 25
    if "kernel_tamper" in capabilities:
        score += 30
    if "known_vulnerable_driver_reference" in capabilities:
        score += 25
    if driver_like and pe.get("format") == "PE" and not pe.get("certificate_table_present"):
        score += 10
    return min(score, 100)


def _add_kernel_issues(
    context: AnalysisContext,
    driver_like: bool,
    risk_score: int,
    pe: dict[str, Any],
    capabilities: dict[str, list[str]],
) -> None:
    if driver_like:
        context.add_issue(
            Finding(
                id="kernel_driver_candidate",
                title="Kernel driver candidate detected",
                severity="low",
                category="kernel",
                summary="The sample has signals commonly seen in Windows kernel drivers.",
                confidence=0.7,
                evidence={"pe": pe, "capability_categories": list(capabilities)},
                tags=["kernel", "driver", "ring0"],
                recommendation="Analyze the sample in an isolated kernel-debugging lab.",
            )
        )

    if driver_like and pe.get("format") == "PE" and not pe.get("certificate_table_present"):
        context.add_issue(
            Finding(
                id="driver_signature_not_detected",
                title="Driver certificate table not detected",
                severity="medium",
                category="kernel",
                summary="The PE certificate table is missing or not visible in static parsing.",
                confidence=0.55,
                evidence={"certificate_table_size": pe.get("certificate_table_size")},
                tags=["kernel", "driver", "signature"],
                recommendation="Verify Authenticode signature with a trusted signing tool.",
            )
        )

    if "ioctl_surface" in capabilities and "kernel_memory_access" in capabilities:
        context.add_issue(
            Finding(
                id="risky_kernel_ioctl_surface",
                title="Risky kernel IOCTL surface indicators",
                severity="high",
                category="kernel",
                summary="The sample exposes IOCTL-related strings and kernel memory access terms.",
                confidence=0.65,
                evidence={
                    "ioctl_surface": capabilities.get("ioctl_surface", []),
                    "kernel_memory_access": capabilities.get("kernel_memory_access", []),
                },
                tags=["kernel", "driver", "ioctl", "memory"],
                recommendation="Review IOCTL handlers for access checks and memory safety.",
            )
        )

    if "kernel_tamper" in capabilities:
        context.add_issue(
            Finding(
                id="kernel_tamper_indicators",
                title="Kernel tamper indicators detected",
                severity="high",
                category="kernel",
                summary="The sample contains strings linked to kernel tampering or integrity bypass attempts.",
                confidence=0.6,
                evidence={"matched_terms": capabilities["kernel_tamper"]},
                tags=["kernel", "tamper", "integrity"],
                recommendation="Treat as high risk and inspect in a controlled analysis VM.",
            )
        )

    if "known_vulnerable_driver_reference" in capabilities:
        context.add_issue(
            Finding(
                id="byovd_reference_indicators",
                title="Known vulnerable driver references detected",
                severity="high",
                category="kernel",
                summary="The sample references names commonly associated with vulnerable driver abuse.",
                confidence=0.6,
                evidence={"matched_terms": capabilities["known_vulnerable_driver_reference"]},
                tags=["kernel", "byovd", "driver"],
                recommendation="Check the sample against your vulnerable-driver blocklist.",
            )
        )

    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 50:
        severity = "high"
    else:
        return

    context.add_issue(
        Finding(
            id="kernel_risk_score",
            title="Elevated kernel risk score",
            severity=severity,
            category="kernel",
            summary="Multiple kernel-risk signals were found in the sample.",
            confidence=0.6,
            evidence={"risk_score": risk_score, "capability_categories": list(capabilities)},
            tags=["kernel", "risk-score"],
            recommendation="Prioritize manual review before allowing this driver in any environment.",
        )
    )

