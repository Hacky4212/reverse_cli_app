import json
from pathlib import Path

import pytest

from reverse_framework.core.config import load_config


def test_load_config_from_json(tmp_path: Path) -> None:
    path = tmp_path / "reverse-tools.json"
    path.write_text(json.dumps({"min_string": 6, "max_strings": 10}), encoding="utf-8")

    config = load_config(path)

    assert config.min_string == 6
    assert config.max_strings == 10


def test_load_config_rejects_binary_file(tmp_path: Path) -> None:
    path = tmp_path / "reverse-tools.exe"
    path.write_bytes(b"MZ\x90\x00\x03\x00")

    with pytest.raises(ValueError, match="UTF-8 JSON"):
        load_config(path)
