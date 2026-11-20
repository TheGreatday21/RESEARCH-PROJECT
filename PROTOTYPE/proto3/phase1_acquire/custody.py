"""Append-only JSONL custody entries and hash-chain validation."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from common.canonical import canonical_json_bytes, sha256_bytes

ZERO_HASH = "0" * 64
CUSTODY_ACTIONS = {"acquire", "verify", "store", "analyze", "export"}


class CustodyFormatError(ValueError):
    """Identify a malformed custody line with its one-based line number."""


def utc_now() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def compute_entry_hash(entry: Mapping[str, Any]) -> str:
    """Hash the previous hash's ASCII representation and canonical entry bytes."""
    unsigned = {key: value for key, value in entry.items() if key != "entry_hash"}
    prev_hash = unsigned.get("prev_hash")
    if not isinstance(prev_hash, str):
        raise ValueError("custody prev_hash must be a string")
    return sha256_bytes(prev_hash.encode("ascii") + canonical_json_bytes(unsigned))


def build_entry(
    *,
    seq: int,
    actor: str,
    action: str,
    evidence_id: str,
    details: Mapping[str, Any],
    prev_hash: str = ZERO_HASH,
    ts_utc: str | None = None,
) -> dict[str, Any]:
    """Build and hash one custody entry."""
    if action not in CUSTODY_ACTIONS:
        raise ValueError(f"unsupported custody action: {action}")
    entry: dict[str, Any] = {
        "seq": seq,
        "ts_utc": ts_utc or utc_now(),
        "actor": actor,
        "action": action,
        "evidence_id": evidence_id,
        "details": dict(details),
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = compute_entry_hash(entry)
    return entry


def append_entry(path: Path, entry: Mapping[str, Any]) -> None:
    """Append one canonical entry without truncating or rewriting prior lines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical_json_bytes(entry) + b"\n")


def parse_custody_bytes(data: bytes) -> list[dict[str, Any]]:
    """Parse every custody line and reject blank, invalid, or non-object lines."""
    if not data:
        raise CustodyFormatError("custody log is empty")
    entries: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(data.splitlines(), start=1):
        if not raw_line.strip():
            raise CustodyFormatError(f"custody line {line_number} is blank")
        try:
            entry = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CustodyFormatError(f"custody line {line_number} is not valid JSON") from error
        if not isinstance(entry, dict):
            raise CustodyFormatError(f"custody line {line_number} is not a JSON object")
        entries.append(entry)
    return entries


def load_entries(path: Path) -> list[dict[str, Any]]:
    """Load every entry from a custody JSONL file."""
    return parse_custody_bytes(path.read_bytes())


def chain_errors(entries: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return every sequence, previous-hash, and entry-hash chain violation."""
    errors: list[str] = []
    if not entries:
        return ["custody log has no entries"]

    previous_hash = ZERO_HASH
    for index, entry in enumerate(entries, start=1):
        if entry.get("seq") != index:
            errors.append(f"entry {index}: expected seq {index}, found {entry.get('seq')!r}")
        if entry.get("prev_hash") != previous_hash:
            errors.append(f"entry {index}: prev_hash does not match the preceding entry")
        try:
            expected_hash = compute_entry_hash(entry)
        except (ValueError, TypeError) as error:
            errors.append(f"entry {index}: cannot compute entry_hash: {error}")
        else:
            if entry.get("entry_hash") != expected_hash:
                errors.append(f"entry {index}: entry_hash mismatch")
        current_hash = entry.get("entry_hash")
        previous_hash = current_hash if isinstance(current_hash, str) else ZERO_HASH
    return errors
