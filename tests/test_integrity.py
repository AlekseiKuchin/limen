from __future__ import annotations

from pathlib import Path

import pytest

from limen.integrity import IntegrityError, require_match, sha256_file, sha256_json


def test_sha256_file_and_json(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_bytes(b"abc")
    assert sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_json({"a": 1, "b": [1, 2]}) == sha256_json({"b": [1, 2], "a": 1})


def test_require_match() -> None:
    require_match("x", None, "abc")  # не зафиксировано — проверять нечего
    require_match("x", "abc", "abc")
    with pytest.raises(IntegrityError):
        require_match("x", "abc", "abd")
