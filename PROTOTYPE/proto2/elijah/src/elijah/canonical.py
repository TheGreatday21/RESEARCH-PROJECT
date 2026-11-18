"""Deterministic JSON encoding and SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, BinaryIO

CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class HashResult:
    """Describe bytes consumed while computing a SHA-256 digest."""

    sha256: str
    bytes_read: int


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a JSON value with sorted keys, compact separators, and UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_stream(stream: BinaryIO, limit: int | None = None) -> HashResult:
    """Hash at most limit bytes, or the complete stream when limit is None."""
    if limit is not None and limit < 0:
        raise ValueError("hash limit cannot be negative")

    digest = hashlib.sha256()
    bytes_read = 0
    while limit is None or bytes_read < limit:
        request_size = CHUNK_SIZE if limit is None else min(CHUNK_SIZE, limit - bytes_read)
        chunk = stream.read(request_size)
        if not chunk:
            break
        digest.update(chunk)
        bytes_read += len(chunk)
    return HashResult(sha256=digest.hexdigest(), bytes_read=bytes_read)


def hash_file(path: str, limit: int | None = None) -> HashResult:
    """Hash a file or a fixed-length prefix without changing the file."""
    with open(path, "rb") as stream:
        return hash_stream(stream, limit)
