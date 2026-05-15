from __future__ import annotations

from typing import Any


def parse_int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith(("0x", "-0x")) else int(value)
        except ValueError:
            return None
    return None


def format_address(value: int | None) -> str | None:
    if value is None:
        return None
    if value < 0:
        return f"-0x{abs(value):X}"
    return f"0x{value:X}"


def normalize_offset(address: int | None, base: int | None) -> int | None:
    if address is None or base is None:
        return None
    return address - base


def module_address_model(
    *,
    preferred_base: int | None,
    loaded_base: int | None,
    image_size: int | None = None,
    module_name: str | None = None,
) -> dict[str, Any]:
    slide = normalize_offset(loaded_base, preferred_base)
    return {
        "module_name": module_name,
        "preferred_base": preferred_base,
        "loaded_base": loaded_base,
        "slide": slide,
        "preferred_base_hex": format_address(preferred_base),
        "loaded_base_hex": format_address(loaded_base),
        "slide_hex": format_address(slide),
        "display_mode": "rva" if slide is not None else "absolute",
        "image_size": image_size,
    }
