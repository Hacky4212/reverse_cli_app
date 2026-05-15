from __future__ import annotations

import re

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding, Indicator


PATTERNS = {
    "url": re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}"),
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "registry": re.compile(rb"\bHK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[ -~]{4,}"),
    "windows_path": re.compile(rb"\b[A-Za-z]:\\[ -~]{4,}"),
}

SUSPICIOUS_TERMS = {
    "process_injection": [
        b"VirtualAlloc",
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"NtCreateThreadEx",
        b"QueueUserAPC",
    ],
    "dynamic_loading": [
        b"LoadLibrary",
        b"GetProcAddress",
    ],
    "networking": [
        b"InternetOpen",
        b"InternetConnect",
        b"HttpSendRequest",
        b"WinHttpOpen",
        b"WSAStartup",
    ],
    "script_execution": [
        b"powershell",
        b"cmd.exe",
        b"wscript",
        b"cscript",
        b"rundll32",
        b"regsvr32",
        b"mshta",
    ],
    "persistence": [
        b"Run\\",
        b"RunOnce\\",
        b"schtasks",
        b"CreateService",
        b"StartService",
    ],
    "defense_evasion": [
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
        b"vssadmin",
        b"wevtutil",
    ],
}


class IndicatorAnalyzer:
    name = "indicators"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        indicators = []
        seen = set()

        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(data):
                value = match.group(0).decode("ascii", errors="replace")
                key = (kind, value)
                if key in seen:
                    continue
                seen.add(key)
                indicator = Indicator(kind=kind, value=value, source=self.name, offset=match.start())
                indicators.append(indicator.to_dict())
                context.add_indicator(indicator)

        capabilities = _detect_capabilities(data)
        context.add_finding(
            self.name,
            {
                "indicator_count": len(indicators),
                "indicators": indicators[:200],
                "capabilities": capabilities,
            },
        )

        _add_capability_issues(context, capabilities)


def _detect_capabilities(data: bytes) -> dict[str, list[str]]:
    lowered = data.lower()
    found: dict[str, list[str]] = {}

    for category, terms in SUSPICIOUS_TERMS.items():
        hits = []
        for term in terms:
            if term.lower() in lowered:
                hits.append(term.decode("ascii", errors="replace"))
        if hits:
            found[category] = hits

    return found


def _add_capability_issues(context: AnalysisContext, capabilities: dict[str, list[str]]) -> None:
    severity_by_category = {
        "process_injection": "high",
        "script_execution": "medium",
        "persistence": "medium",
        "defense_evasion": "medium",
        "networking": "low",
        "dynamic_loading": "low",
    }

    for category, hits in capabilities.items():
        context.add_issue(
            Finding(
                id=f"capability_{category}",
                title=f"Suspicious capability: {category}",
                severity=severity_by_category.get(category, "low"),  # type: ignore[arg-type]
                category="capability",
                summary="The sample contains strings commonly linked to this behavior.",
                confidence=0.55,
                evidence={"matched_terms": hits},
                tags=["capability", category],
                recommendation="Confirm through imports, cross references, or dynamic analysis.",
            )
        )

