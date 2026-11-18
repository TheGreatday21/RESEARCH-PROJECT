"""Tests for canonical custody entries and append-only hash chaining."""

from pathlib import Path

import pytest

from elijah.canonical import canonical_json_bytes
from elijah.prov.custody import (
    ZERO_HASH,
    CustodyFormatError,
    append_entry,
    build_entry,
    chain_errors,
    load_entries,
    parse_custody_bytes,
)


def _entry(seq: int = 1, prev_hash: str = ZERO_HASH) -> dict[str, object]:
    return build_entry(
        seq=seq,
        ts_utc="2026-11-11T00:00:00Z",
        actor="researcher",
        action="acquire",
        evidence_id="evidence-1",
        details={"case_id": "C001"},
        prev_hash=prev_hash,
    )


def test_genesis_entry_has_zero_previous_hash() -> None:
    """The first entry uses the specified all-zero previous hash."""
    entry = _entry()
    assert entry["prev_hash"] == ZERO_HASH
    assert len(str(entry["entry_hash"])) == 64
    assert chain_errors([entry]) == []


def test_append_preserves_existing_bytes(tmp_path: Path) -> None:
    """Appending a second entry does not rewrite the first line."""
    path = tmp_path / "custody.jsonl"
    first = _entry()
    append_entry(path, first)
    first_bytes = path.read_bytes()
    second = _entry(seq=2, prev_hash=str(first["entry_hash"]))
    append_entry(path, second)
    assert path.read_bytes().startswith(first_bytes)
    assert chain_errors(load_entries(path)) == []


def test_tampering_with_custody_details_breaks_chain() -> None:
    """A modified details object is detected by entry-hash replay."""
    entry = _entry()
    entry["details"] = {"case_id": "C999"}
    assert any("entry_hash mismatch" in error for error in chain_errors([entry]))


def test_invalid_custody_line_is_not_discarded() -> None:
    """Malformed input fails with its line number rather than being skipped."""
    data = canonical_json_bytes(_entry()) + b"\nnot-json\n"
    with pytest.raises(CustodyFormatError, match="line 2"):
        parse_custody_bytes(data)


def test_missing_previous_hash_link_is_detected() -> None:
    """A valid entry cannot silently become a new genesis entry at sequence two."""
    first = _entry()
    second = _entry(seq=2)
    errors = chain_errors([first, second])
    assert any("prev_hash" in error for error in errors)
