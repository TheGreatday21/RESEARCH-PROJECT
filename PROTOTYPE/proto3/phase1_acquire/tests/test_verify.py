"""End-to-end unit tests for Phase 1 stored evidence verification."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO

import pytest

from common.canonical import canonical_json_bytes, sha256_bytes
from phase1_acquire.custody import build_entry
from phase1_acquire.manifest import build_manifest
from phase1_acquire.signing import generate_keypair, sign_manifest
from phase1_acquire.store import EvidenceStore, LocalStore
from phase1_acquire.verify import verify_evidence


class MemoryStore(EvidenceStore):
    """Provide an in-memory store boundary for verification tests."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        """Store test bytes."""
        self.objects[(evidence_id, relative_path)] = (
            bytes_or_stream if isinstance(bytes_or_stream, bytes) else bytes_or_stream.read()
        )

    def get(self, evidence_id: str, relative_path: str) -> bytes:
        """Retrieve test bytes or raise FileNotFoundError."""
        try:
            return self.objects[(evidence_id, relative_path)]
        except KeyError as error:
            raise FileNotFoundError(relative_path) from error

    def list(self, evidence_id: str) -> list[str]:
        """List sorted test paths."""
        return sorted(path for item_id, path in self.objects if item_id == evidence_id)

    def exists(self, evidence_id: str, relative_path: str) -> bool:
        """Check test object existence."""
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


def test_untouched_evidence_passes(signed_store: tuple[MemoryStore, str, Path]) -> None:
    """Prefix growth, full hashes, signature, and custody all verify."""
    store, evidence_id, public_path = signed_store
    result = verify_evidence(store, evidence_id, public_path)
    assert result.ok, result.to_dict()


def test_log_prefix_tamper_names_hash_check(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """Changing a source-prefix byte fails both prefix and full checks."""
    store, evidence_id, public_path = signed_store
    key = (evidence_id, "artifacts/access.log")
    store.objects[key] = b"X" + store.objects[key][1:]
    result = verify_evidence(store, evidence_id, public_path)
    assert not result.ok
    assert "artifact_prefix:artifacts/access.log" in result.failed_checks
    assert "artifact_full:artifacts/access.log" in result.failed_checks


def test_log_trailing_byte_tamper_is_detected(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """Bytes fetched after size_at_open remain covered by the full hash."""
    store, evidence_id, public_path = signed_store
    key = (evidence_id, "artifacts/access.log")
    store.objects[key] = store.objects[key][:-1] + b"X"
    result = verify_evidence(store, evidence_id, public_path)
    assert "artifact_full:artifacts/access.log" in result.failed_checks
    assert "artifact_prefix:artifacts/access.log" not in result.failed_checks


def test_manifest_tamper_names_signature_check(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """A signed-field modification fails the manifest signature check."""
    store, evidence_id, public_path = signed_store
    key = (evidence_id, "manifest.json")
    manifest = store.objects[key].replace(b'"tool":"lapa"', b'"tool":"tampered"')
    store.objects[key] = manifest
    result = verify_evidence(store, evidence_id, public_path)
    assert "manifest_signature" in result.failed_checks


def test_custody_tamper_names_chain_check(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """Changing an actor without recomputing hashes breaks the chain."""
    store, evidence_id, public_path = signed_store
    key = (evidence_id, "custody.jsonl")
    store.objects[key] = store.objects[key].replace(b"researcher", b"intruder")
    result = verify_evidence(store, evidence_id, public_path)
    assert "custody_chain" in result.failed_checks


def test_invalid_custody_json_is_reported(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """A byte flip that breaks JSON names the custody parser check."""
    store, evidence_id, public_path = signed_store
    store.objects[(evidence_id, "custody.jsonl")] = b"{not-json}\n"
    result = verify_evidence(store, evidence_id, public_path)
    assert "custody_json" in result.failed_checks


def test_missing_artifact_is_reported(
    signed_store: tuple[MemoryStore, str, Path],
) -> None:
    """Deleting a stored artifact cannot be hidden by valid provenance metadata."""
    store, evidence_id, public_path = signed_store
    del store.objects[(evidence_id, "artifacts/access.log")]
    result = verify_evidence(store, evidence_id, public_path)
    assert "artifact_present:artifacts/access.log" in result.failed_checks


def test_stored_schema_v1_fixture_still_verifies() -> None:
    """The complete signed Phase 1 fixture remains valid under the v2 verifier."""
    fixture = Path(__file__).resolve().parent / "fixtures" / "evidence_v1"
    evidence_id = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
    store = LocalStore(fixture, "C001")
    result = verify_evidence(store, evidence_id, fixture / "ed25519.pub")
    assert result.ok, result.to_dict()
    manifest = json.loads(store.get(evidence_id, "manifest.json"))
    assert manifest["schema_version"] == 1
    assert "timezone" not in manifest
    assert "metrics" not in manifest
