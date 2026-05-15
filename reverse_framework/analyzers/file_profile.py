from __future__ import annotations

import hashlib
import math
from collections import Counter

from reverse_framework.core.context import AnalysisContext


class FileProfileAnalyzer:
    name = "file_profile"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        context.add_finding(
            self.name,
            {
                "name": context.target.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
                "entropy": round(_entropy(data), 4),
                "magic": data[:16].hex(" "),
            },
        )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

