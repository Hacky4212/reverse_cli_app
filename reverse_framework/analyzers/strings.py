from __future__ import annotations

import string

from reverse_framework.core.context import AnalysisContext


class StringsAnalyzer:
    name = "strings"

    def __init__(self, min_length: int = 4, limit: int = 300) -> None:
        self.min_length = min_length
        self.limit = limit

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        strings = list(_extract_ascii_strings(data, self.min_length, self.limit))
        context.add_finding(
            self.name,
            {
                "min_length": self.min_length,
                "count": len(strings),
                "items": strings,
            },
        )


def _extract_ascii_strings(data: bytes, min_length: int, limit: int) -> list[str]:
    printable = set(string.printable.encode("ascii")) - {0x0B, 0x0C}
    current = bytearray()
    found: list[str] = []

    for byte in data:
        if byte in printable and byte not in {0x0A, 0x0D, 0x09}:
            current.append(byte)
            continue

        _flush(current, found, min_length, limit)
        if len(found) >= limit:
            break

    if len(found) < limit:
        _flush(current, found, min_length, limit)

    return found


def _flush(current: bytearray, found: list[str], min_length: int, limit: int) -> None:
    if len(current) >= min_length and len(found) < limit:
        found.append(current.decode("ascii", errors="replace"))
    current.clear()

