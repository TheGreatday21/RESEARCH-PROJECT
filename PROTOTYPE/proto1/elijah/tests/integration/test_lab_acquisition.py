"""Opt-in acquisition and bytewise tamper tests against the local Docker lab."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from elijah.acquire.orchestrator import acquire_evidence
from elijah.prov.signing import generate_keypair
from elijah.prov.verify import VerificationResult, verify_evidence
from elijah.store.local import LocalStore

pytestmark = pytest.mark.integration


def _require_lab() -> None:
    """Skip unless the caller explicitly opted into the prepared Docker lab."""
    if os.environ.get("ELIJAH_RUN_LAB_TESTS") != "1":
        pytest.skip("set ELIJAH_RUN_LAB_TESTS=1 and run make lab-up traffic first")


def _flip_first_value_byte(data: bytes, field: bytes) -> bytes:
    """Flip one byte inside a JSON string value while retaining valid JSON."""
    field_offset = data.index(field)
    value_offset = data.index(b':', field_offset) + 1
    quote_offset = data.index(b'"', value_offset)
    mutated = bytearray(data)
    mutated[quote_offset + 1] ^= 1
    return bytes(mutated)


def _with_writable_restore(
    path: Path,
    mutation: Callable[[bytes], bytes],
    check: Callable[[], VerificationResult],
) -> VerificationResult:
    """Mutate one stored object and always restore its original bytes and mode."""
    original = path.read_bytes()
    assert original, f"cannot byte-test an empty artifact: {path}"
    path.chmod(0o644)
    try:
        path.write_bytes(mutation(original))
        result = check()
    finally:
        path.write_bytes(original)
        path.chmod(0o444)
    return result


def test_live_lab_acquisition_and_bytewise_tamper_detection(tmp_path: Path) -> None:
    """Live evidence verifies, then every object class detects a one-byte change."""
    _require_lab()
    repository = Path(__file__).parents[2]
    private_path, public_path = generate_keypair(tmp_path / "keys")
    evidence_root = tmp_path / "evidence"
    store = LocalStore(evidence_root, "C001")
    acquisition = acquire_evidence(
        store=store,
        inventory=repository / "lab" / "inventory.ini",
        case_id="C001",
        staging_dir=tmp_path / "staging",
        private_key_path=private_path,
    )
    assert acquisition.ok, acquisition
    baseline = verify_evidence(store, acquisition.evidence_id, public_path)
    assert baseline.ok, baseline.to_dict()

    evidence_directory = evidence_root / "C001" / acquisition.evidence_id
    stored_paths = [
        path
        for path in store.list(acquisition.evidence_id)
        if path.startswith(("artifacts/", "context/"))
    ]
    assert any(path.endswith("access.log") for path in stored_paths)
    assert any(path.endswith("error.log") for path in stored_paths)
    for relative_path in stored_paths:
        result = _with_writable_restore(
            evidence_directory / relative_path,
            lambda data: bytes([data[0] ^ 1]) + data[1:],
            lambda: verify_evidence(store, acquisition.evidence_id, public_path),
        )
        assert not result.ok, relative_path
        assert any(name.startswith("artifact_") for name in result.failed_checks)
        restored = verify_evidence(store, acquisition.evidence_id, public_path)
        assert restored.ok, restored.to_dict()

    manifest_result = _with_writable_restore(
        evidence_directory / "manifest.json",
        lambda data: _flip_first_value_byte(data, b'"hostname"'),
        lambda: verify_evidence(store, acquisition.evidence_id, public_path),
    )
    assert "manifest_signature" in manifest_result.failed_checks

    custody_result = _with_writable_restore(
        evidence_directory / "custody.jsonl",
        lambda data: _flip_first_value_byte(data, b'"actor"'),
        lambda: verify_evidence(store, acquisition.evidence_id, public_path),
    )
    assert "custody_chain" in custody_result.failed_checks
    assert verify_evidence(store, acquisition.evidence_id, public_path).ok
