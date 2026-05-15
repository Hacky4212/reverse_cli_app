from __future__ import annotations

import math
from collections import Counter

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import Finding


class EntropyAnalyzer:
    name = "entropy_regions"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        window = max(context.config.entropy_window, 256)
        threshold = context.config.entropy_threshold
        regions = []

        if not data:
            context.add_finding(self.name, {"window": window, "regions": []})
            return

        for offset in range(0, len(data), window):
            chunk = data[offset : offset + window]
            entropy = round(_entropy(chunk), 4)
            if entropy >= threshold:
                regions.append(
                    {
                        "offset": offset,
                        "size": len(chunk),
                        "entropy": entropy,
                    }
                )
            if len(regions) >= context.config.max_entropy_regions:
                break

        context.add_finding(
            self.name,
            {
                "window": window,
                "threshold": threshold,
                "region_count": len(regions),
                "regions": regions,
            },
        )

        if regions:
            context.add_issue(
                Finding(
                    id="high_entropy_regions",
                    title="High entropy regions detected",
                    severity="medium",
                    category="packing",
                    summary="The sample contains regions that may be packed, encrypted, or compressed.",
                    confidence=0.65,
                    evidence={"regions": regions[:5]},
                    tags=["packing", "crypto", "triage"],
                    recommendation="Review these offsets in a disassembler or unpacking workflow.",
                )
            )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

