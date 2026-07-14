from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from fieldtrue.canonical import (
    CanonicalizationError,
    atomic_write,
    canonical_json,
    canonical_json_pretty,
    sha256_file,
    sha256_value,
)


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"z": 1, "a": [2, 3]}) == b'{"a":[2,3],"z":1}'
    assert canonical_json({"values": {"b", "a"}}) == b'{"values":["a","b"]}'
    assert canonical_json_pretty({"b": 1}).endswith(b"\n")


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        b"opaque",
        {1: "non-string"},
        datetime.fromisoformat("2026-01-01"),
    ],
)
def test_canonical_json_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


def test_atomic_write_and_hash(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "artifact.json"
    atomic_write(target, b"first")
    first = sha256_file(target)
    atomic_write(target, b"second")
    assert target.read_bytes() == b"second"
    assert sha256_file(target) != first
    assert sha256_value({"x": 1}) == sha256_value({"x": 1})
