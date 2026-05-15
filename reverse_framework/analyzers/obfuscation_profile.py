from __future__ import annotations

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding


DYNAMIC_RESOLUTION_TERMS = {
    "api_resolution": [
        b"LoadLibraryA",
        b"LoadLibraryW",
        b"LoadLibraryExA",
        b"LoadLibraryExW",
        b"GetProcAddress",
        b"LdrLoadDll",
        b"LdrGetProcedureAddress",
        b"GetModuleHandleA",
        b"GetModuleHandleW",
        b"GetModuleHandleExA",
        b"GetModuleHandleExW",
    ],
    "memory_rewrite": [
        b"VirtualProtect",
        b"VirtualProtectEx",
        b"NtProtectVirtualMemory",
        b"VirtualAlloc",
        b"VirtualAllocEx",
        b"NtAllocateVirtualMemory",
        b"MapViewOfFile",
        b"MapViewOfFileEx",
        b"NtMapViewOfSection",
        b"WriteProcessMemory",
    ],
    "anti_analysis": [
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
        b"OutputDebugStringA",
        b"OutputDebugStringW",
        b"SetUnhandledExceptionFilter",
        b"AddVectoredExceptionHandler",
        b"Sleep",
        b"GetTickCount",
        b"QueryPerformanceCounter",
    ],
    "packing_or_crypto": [
        b"CryptDecrypt",
        b"CryptUnprotectData",
        b"BCryptDecrypt",
        b"RtlDecompressBuffer",
        b"RtlDecompressBufferEx",
        b"RtlCompressBuffer",
    ],
}


class ObfuscationProfileAnalyzer:
    name = "obfuscation_profile"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        file_profile = context.findings.get("file_profile", {})
        strings = context.findings.get("strings", {})
        entropy_regions = context.findings.get("entropy_regions", {})
        pe_header = context.findings.get("pe_header", {})

        entropy = float(file_profile.get("entropy", 0.0) or 0.0)
        string_count = int(strings.get("count", 0) or 0)
        region_count = int(entropy_regions.get("region_count", 0) or 0)
        signals = _detect_signals(data)
        address_model = _build_address_model(pe_header, signals)
        score = _score_profile(entropy, string_count, region_count, signals, address_model)

        context.add_finding(
            self.name,
            {
                "obfuscation_score": score,
                "entropy": round(entropy, 4),
                "string_count": string_count,
                "entropy_region_count": region_count,
                "signals": signals,
                "addressing": address_model,
                "recommended_display": "module+rva"
                if address_model["display_mode"] != "absolute"
                or signals.get("api_resolution")
                or signals.get("memory_rewrite")
                else "absolute",
            },
        )

        if score >= 55:
            severity = "high" if score >= 80 else "medium"
            context.add_issue(
                Finding(
                    id="obfuscation_or_randomized_addressing",
                    title="Obfuscation or randomized addressing likely",
                    severity=severity,  # type: ignore[arg-type]
                    category="obfuscation",
                    summary=(
                        "The sample looks easier to reason about in RVA or module-relative form "
                        "than by absolute address."
                    ),
                    confidence=0.72,
                    evidence={
                        "obfuscation_score": score,
                        "signals": signals,
                        "addressing": address_model,
                    },
                    tags=["obfuscation", "addressing", "rva"],
                    recommendation=(
                        "Normalize addresses to module-relative offsets and compare samples in "
                        "relative form before diffing."
                    ),
                )
            )


def _detect_signals(data: bytes) -> dict[str, list[str]]:
    lowered = data.lower()
    found: dict[str, list[str]] = {}

    for category, terms in DYNAMIC_RESOLUTION_TERMS.items():
        hits = []
        for term in terms:
            if term.lower() in lowered:
                hits.append(term.decode("ascii", errors="replace"))
        if hits:
            found[category] = hits

    return found


def _build_address_model(pe_header: dict[str, object], signals: dict[str, list[str]]) -> dict[str, object]:
    display_mode = str(pe_header.get("addressing", {}).get("display_mode", "absolute"))
    aslr_enabled = bool(pe_header.get("addressing", {}).get("aslr_enabled", False))
    relocations_stripped = bool(pe_header.get("addressing", {}).get("relocations_stripped", False))
    preferred_image_base = pe_header.get("preferred_image_base")
    entry_point_rva = pe_header.get("entry_point_rva")

    if signals.get("api_resolution") or signals.get("memory_rewrite"):
        display_mode = "module+rva"
    elif aslr_enabled:
        display_mode = "rva"
    elif relocations_stripped:
        display_mode = "absolute"

    return {
        "display_mode": display_mode,
        "aslr_enabled": aslr_enabled,
        "relocations_stripped": relocations_stripped,
        "preferred_image_base": preferred_image_base,
        "entry_point_rva": entry_point_rva,
        "stable_reference": "module+rva" if display_mode != "absolute" else "absolute",
    }


def _score_profile(
    entropy: float,
    string_count: int,
    region_count: int,
    signals: dict[str, list[str]],
    address_model: dict[str, object],
) -> int:
    score = 0

    if entropy >= 7.5:
        score += 30
    elif entropy >= 6.8:
        score += 20
    elif entropy >= 6.0:
        score += 10

    if region_count > 0:
        score += min(20, region_count * 3)

    if string_count <= 8:
        score += 10
    elif string_count <= 32:
        score += 5

    dynamic_hits = sum(len(items) for items in signals.values())
    if dynamic_hits:
        score += min(30, 8 + dynamic_hits * 3)

    if address_model.get("aslr_enabled"):
        score += 8

    if address_model.get("display_mode") == "module+rva":
        score += 10

    return min(score, 100)
