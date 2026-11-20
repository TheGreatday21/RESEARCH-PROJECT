"""Tests for deterministic JSON and fixed-prefix hashing."""

import math
from io import BytesIO

import pytest

from common.canonical import canonical_json_bytes, hash_stream, sha256_bytes


def test_canonical_json_is_sorted_compact_utf8() -> None:
    """Canonical bytes do not depend on insertion order or ASCII escaping."""
    first = canonical_json_bytes({"z": "é", "a": {"b": 2, "a": 1}})
    second = canonical_json_bytes({"a": {"a": 1, "b": 2}, "z": "é"})
    assert first == second
    assert first == '{"a":{"a":1,"b":2},"z":"é"}'.encode()
    assert b" " not in first


def test_canonical_json_rejects_non_finite_numbers() -> None:
    """NaN and infinity cannot create platform-dependent JSON output."""
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": math.nan})


def test_prefix_hash_ignores_later_growth() -> None:
    """The first size_at_open bytes retain their hash when a file grows."""
    original = b"first line\nsecond line\n"
    grown = original + b"written after open\n"
    result = hash_stream(BytesIO(grown), len(original))
    assert result.sha256 == sha256_bytes(original)
    assert result.bytes_read == len(original)


def test_hash_stream_reports_short_input() -> None:
    """A short read is visible to the caller instead of raising or hanging."""
    result = hash_stream(BytesIO(b"abc"), 10)
    assert result.bytes_read == 3
    assert result.sha256 == sha256_bytes(b"abc")


def test_hash_stream_rejects_negative_limit() -> None:
    """Negative prefix lengths are programming errors."""
    with pytest.raises(ValueError, match="negative"):
        hash_stream(BytesIO(b"abc"), -1)
