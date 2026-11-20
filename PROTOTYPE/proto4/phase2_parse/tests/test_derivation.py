"""Unit tests for Phase 2 Parquet derivation, working-copy checks, and DuckDB SQL queries."""

from collections.abc import Mapping
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import pytest

from common.canonical import canonical_json_bytes, sha256_bytes
from phase1_acquire.custody import build_entry
from phase1_acquire.manifest import build_manifest
from phase1_acquire.signing import generate_keypair, sign_manifest
from phase1_acquire.store import EvidenceStore
from phase1_acquire.verify import verify_evidence
from phase2_parse.dataset import DerivedError, create_derived_dataset, verify_derived_dataset
from phase2_parse.sql import run_query


class MemoryStore(EvidenceStore):
    """Provide an in-memory store boundary for derivation tests."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        self.objects[(evidence_id, relative_path)] = (
            bytes_or_stream if isinstance(bytes_or_stream, bytes) else bytes_or_stream.read()
        )

    def get(self, evidence_id: str, relative_path: str) -> bytes:
        try:
            return self.objects[(evidence_id, relative_path)]
        except KeyError as error:
            raise FileNotFoundError(relative_path) from error

    def list(self, evidence_id: str) -> list[str]:
        return sorted(path for item_id, path in self.objects if item_id == evidence_id)

    def exists(self, evidence_id: str, relative_path: str) -> bool:
        return (evidence_id, relative_path) in self.objects


@pytest.fixture
def signed_store(tmp_path: Path) -> tuple[MemoryStore, str, Path]:
    """Create signed evidence with one log and one context artifact."""
    private_path, public_path = generate_keypair(tmp_path / "keys")
    store = MemoryStore()
    evidence_id = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
    acquisition_id = "ee650768-83d9-4f04-a7f0-1b4d81be176e"
    original = b"one\ntwo\n"
    grown = original + b"three\n"
    context = b"worker_processes 1;\n"
    custody = build_entry(
        seq=1,
        ts_utc="2026-11-11T00:00:00Z",
        actor="researcher",
        action="acquire",
        evidence_id=evidence_id,
        details={"acquisition_id": acquisition_id},
    )
    unsigned = build_manifest(
        case_id="C001",
        evidence_id=evidence_id,
        acquisition_id=acquisition_id,
        acquirer={"tool": "lapa", "version": "0.1.0"},
        target={"hostname": "target", "cloud": {}},
        timing={"started_utc": "2026-11-11T00:00:00Z"},
        artifacts=[
            {
                "logical_name": "access.log",
                "source_path": "/var/log/nginx/access.log",
                "size_at_open": len(original),
                "sha256_source": sha256_bytes(original),
                "sha256_destination": sha256_bytes(original),
                "sha256_full": sha256_bytes(grown),
                "stored_size": len(grown),
                "stored_as": "artifacts/access.log",
                "changed_during_read": False,
                "verified": True,
            }
        ],
        context_artifacts=[
            {
                "logical_name": "nginx_config",
                "size_at_open": len(context),
                "sha256_source": sha256_bytes(context),
                "sha256_destination": sha256_bytes(context),
                "sha256_full": sha256_bytes(context),
                "stored_size": len(context),
                "stored_as": "context/nginx_config.txt",
                "changed_during_read": False,
                "verified": True,
            }
        ],
        footprint={"commands": [], "files_created": []},
        custody_ref=str(custody["entry_hash"]),
    )
    signed = sign_manifest(unsigned, private_path)
    store.put(evidence_id, "artifacts/access.log", grown)
    store.put(evidence_id, "context/nginx_config.txt", context)
    store.put(evidence_id, "manifest.json", canonical_json_bytes(signed))
    store.put(evidence_id, "custody.jsonl", canonical_json_bytes(custody) + b"\n")
    return store, evidence_id, public_path


def test_derivation_verifies_and_traces_unparsed_rows(
    signed_store: tuple[MemoryStore, str, Path],
    tmp_path: Path,
) -> None:
    store, evidence_id, public_key = signed_store
    result = create_derived_dataset(
        store,
        "C001",
        evidence_id,
        tmp_path / "derived",
        public_key.with_suffix(".pem"),
        public_key,
    )
    rows = run_query(
        result.output_directory,
        "SELECT case_id, artifact_path, byte_offset, byte_length, raw_bytes, "
        "parse_ok, beyond_prefix"
        " FROM access ORDER BY line_no",
    ).rows
    assert len(rows) == 3
    for case_id, path, offset, length, raw, parsed, _ in rows:
        assert case_id == "C001"
        assert raw == store.get(evidence_id, path)[offset : offset + length]
        assert not parsed
    assert [row[-1] for row in rows] == [False, False, True]
    verified = verify_derived_dataset(store, evidence_id, result.output_directory, public_key)
    assert verified.ok, verified.to_dict()

    report = result.output_directory / "parse_report.json"
    report.write_bytes(report.read_bytes() + b" ")
    tampered = verify_derived_dataset(store, evidence_id, result.output_directory, public_key)
    assert tampered.failed_checks == ("derived_file:parse_report.json",)


def test_parse_rejects_bytes_changed_after_evidence_verification(
    signed_store: tuple[MemoryStore, str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, evidence_id, public_key = signed_store
    original_open = store.open_read

    def changed_copy(item: str, path: str) -> BinaryIO:
        if path == "artifacts/access.log":
            return BytesIO(store.get(item, path)[:-1] + b"X")
        return original_open(item, path)

    monkeypatch.setattr(store, "open_read", changed_copy)
    out = tmp_path / "derived"
    with pytest.raises(DerivedError, match="working copy verification failed: artifact_full:"):
        create_derived_dataset(
            store,
            "C001",
            evidence_id,
            out,
            public_key.with_suffix(".pem"),
            public_key,
        )
    assert not (out / "C001" / evidence_id).exists()
    assert verify_evidence(store, evidence_id, public_key).ok

    monkeypatch.undo()
    store.objects[(evidence_id, "artifacts/access.log")] += b"X"
    with pytest.raises(DerivedError, match="evidence verification failed: artifact_full:"):
        create_derived_dataset(
            store,
            "C001",
            evidence_id,
            out,
            public_key.with_suffix(".pem"),
            public_key,
        )
    assert not (out / "C001" / evidence_id).exists()
