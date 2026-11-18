"""Tests for staged hash verification and signed evidence assembly."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO

import pytest

from elijah.acquire.orchestrator import (
    acquire_evidence,
    assemble_signed_acquisition,
    prepare_context_artifacts,
    verify_fetched_artifacts,
)
from elijah.canonical import canonical_json_bytes, sha256_bytes
from elijah.prov.custody import chain_errors
from elijah.prov.signing import generate_keypair, verify_manifest_signature
from elijah.prov.verify import verify_evidence
from elijah.store.base import EvidenceStore


class MemoryStore(EvidenceStore):
    """Record evidence objects without a filesystem or cloud dependency."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        """Store bytes in memory."""
        self.objects[(evidence_id, relative_path)] = (
            bytes_or_stream if isinstance(bytes_or_stream, bytes) else bytes_or_stream.read()
        )

    def get(self, evidence_id: str, relative_path: str) -> bytes:
        """Get bytes in memory."""
        try:
            return self.objects[(evidence_id, relative_path)]
        except KeyError as error:
            raise FileNotFoundError(relative_path) from error

    def list(self, evidence_id: str) -> list[str]:
        """List memory objects."""
        return sorted(path for item_id, path in self.objects if item_id == evidence_id)

    def exists(self, evidence_id: str, relative_path: str) -> bool:
        """Check memory object existence."""
        return (evidence_id, relative_path) in self.objects


def _source(path: str, content: bytes) -> dict[str, object]:
    return {
        "logical_name": Path(path).name,
        "source_path": path,
        "size_at_open": len(content),
        "prefix_bytes_read": len(content),
        "sha256_source": sha256_bytes(content),
        "changed_during_read": False,
    }


def _collector(log_path: str, content: bytes) -> dict[str, object]:
    context = b"worker_processes 1;\n"
    return {
        "hostname": "lab-target",
        "kernel": "test-kernel",
        "os_release": {"ID": "debian"},
        "target_time_before": {
            "utc": "2026-11-11T00:00:02Z",
            "original": "2026-11-11 00:00:02",
        },
        "target_time_after": {
            "utc": "2026-11-11T00:00:12Z",
            "original": "2026-11-11 00:00:12",
        },
        "artifacts": [_source(log_path, content)],
        "context_artifacts": [
            {
                "logical_name": "nginx_config",
                "content": context.decode(),
                "sha256_source": sha256_bytes(context),
                "changed_during_read": False,
            }
        ],
        "collection_errors": [],
        "footprint": {"commands": [["nginx", "-T"]], "files_created": []},
    }


def _metadata() -> dict[str, object]:
    return {
        "control_started_utc": "2026-11-11T00:00:00Z",
        "control_probe_finished_utc": "2026-11-11T00:00:10Z",
        "control_finished_utc": "2026-11-11T00:00:20Z",
        "target_address": "127.0.0.1",
        "ssh_user": "forensic-acq",
        "files_created": ["Ansible temporary files below /tmp"],
        "preflight_commands": ["command -v python3"],
    }


def _stage_log(staging_dir: Path, content: bytes) -> None:
    directory = staging_dir / "artifacts" / "0000"
    directory.mkdir(parents=True)
    (directory / "access.log").write_bytes(content)


def test_fetched_growth_verifies_prefix_and_hashes_full_file(tmp_path: Path) -> None:
    """Extra fetched bytes do not invalidate the matching source prefix."""
    original = b"one\ntwo\n"
    grown = original + b"three\n"
    _stage_log(tmp_path, grown)
    collector = {"artifacts": [_source("/var/log/nginx/access.log", original)]}
    result = verify_fetched_artifacts(collector, tmp_path)[0]
    assert result.metadata["verified"] is True
    assert result.metadata["sha256_destination"] == sha256_bytes(original)
    assert result.metadata["sha256_full"] == sha256_bytes(grown)
    assert result.metadata["stored_size"] == len(grown)


def test_fetched_mismatch_is_marked_and_reported(tmp_path: Path) -> None:
    """A changed fetched prefix is never silently accepted."""
    original = b"one\ntwo\n"
    _stage_log(tmp_path, b"Xne\ntwo\n")
    collector = {"artifacts": [_source("/var/log/nginx/access.log", original)]}
    result = verify_fetched_artifacts(collector, tmp_path)[0]
    assert result.metadata["verified"] is False
    assert "differ" in result.metadata["verification_error"]


def test_context_bytes_and_hashes_are_deterministic() -> None:
    """Context text is removed from the manifest and stored as hashed UTF-8."""
    collector = _collector("/var/log/nginx/access.log", b"one\n")
    result = prepare_context_artifacts(collector)[0]
    assert "content" not in result.metadata
    assert result.content == b"worker_processes 1;\n"
    assert result.metadata["verified"] is True
    assert result.metadata["stored_as"] == "context/0000-nginx_config.txt"


def test_signed_acquisition_has_signature_custody_and_clock_offset(tmp_path: Path) -> None:
    """Signed assembly links custody and estimates midpoint clock offset."""
    private_path, public_path = generate_keypair(tmp_path / "keys")
    original = b"one\ntwo\n"
    _stage_log(tmp_path, original)
    collector = _collector("/var/log/nginx/access.log", original)
    artifacts = verify_fetched_artifacts(collector, tmp_path)
    context = prepare_context_artifacts(collector)
    signed = assemble_signed_acquisition(
        case_id="C001",
        collector=collector,
        run_metadata=_metadata(),
        artifacts=artifacts,
        context_artifacts=context,
        private_key_path=private_path,
        evidence_id="3ea4c29b-1c31-4f4d-9482-58df13506bc5",
        acquisition_id="ee650768-83d9-4f04-a7f0-1b4d81be176e",
    )
    assert signed.manifest["timing"]["estimated_offset_seconds"] == 2.0
    assert signed.manifest["custody_ref"] == signed.custody_entry["entry_hash"]
    assert chain_errors([signed.custody_entry]) == []
    verify_manifest_signature(signed.manifest, public_path)


def test_full_staged_acquisition_stores_verifiable_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The orchestrator stores grown logs, context, custody, and signed manifest."""
    private_path, public_path = generate_keypair(tmp_path / "keys")
    original = b"one\ntwo\n"
    grown = original + b"three\n"
    staging_dir = tmp_path / "staging"
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")

    def fake_ansible(inventory_path: Path, case_id: str, staging: Path) -> None:
        _stage_log(staging, grown)
        collector = _collector("/var/log/nginx/access.log", original)
        staging.joinpath("collector.json").write_text(
            json.dumps(collector), encoding="utf-8"
        )
        staging.joinpath("run_metadata.json").write_text(
            json.dumps(_metadata()), encoding="utf-8"
        )

    monkeypatch.setattr("elijah.acquire.orchestrator._run_ansible", fake_ansible)
    store = MemoryStore()
    result = acquire_evidence(
        store=store,
        inventory=inventory,
        case_id="C001",
        staging_dir=staging_dir,
        private_key_path=private_path,
    )
    assert result.ok
    assert store.objects[(result.evidence_id, "artifacts/0000-access.log")] == grown
    verification = verify_evidence(store, result.evidence_id, public_path)
    assert verification.ok, verification.to_dict()
    manifest = json.loads(store.objects[(result.evidence_id, "manifest.json")])
    assert manifest["case_id"] == "C001"
    assert manifest["artifacts"][0]["verified"] is True
    assert store.objects[(result.evidence_id, "custody.jsonl")].endswith(b"\n")
    assert canonical_json_bytes(manifest) == store.objects[(result.evidence_id, "manifest.json")]
