"""Tests for Typer commands and on-disk verification failures."""

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from elijah.canonical import canonical_json_bytes
from elijah.cli import app
from elijah.prov.custody import build_entry
from elijah.prov.manifest import build_manifest
from elijah.prov.signing import generate_keypair, sign_manifest
from elijah.store.local import LocalStore

EVIDENCE_ID = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
ACQUISITION_ID = "ee650768-83d9-4f04-a7f0-1b4d81be176e"
runner = CliRunner()


def _create_evidence(root: Path, keys: Path) -> tuple[LocalStore, Path]:
    private_path, public_path = generate_keypair(keys)
    store = LocalStore(root, "C001")
    custody = build_entry(
        seq=1,
        ts_utc="2026-11-11T00:00:00Z",
        actor="researcher",
        action="acquire",
        evidence_id=EVIDENCE_ID,
        details={"acquisition_id": ACQUISITION_ID},
    )
    unsigned = build_manifest(
        case_id="C001",
        evidence_id=EVIDENCE_ID,
        acquisition_id=ACQUISITION_ID,
        acquirer={"tool": "elijah", "version": "0.1.0"},
        target={"hostname": "target", "cloud": {}},
        timing={"started_utc": "2026-11-11T00:00:00Z"},
        artifacts=[],
        context_artifacts=[],
        footprint={"commands": [], "files_created": []},
        custody_ref=str(custody["entry_hash"]),
    )
    signed = sign_manifest(unsigned, private_path)
    store.put(EVIDENCE_ID, "manifest.json", canonical_json_bytes(signed))
    store.put(EVIDENCE_ID, "custody.jsonl", canonical_json_bytes(custody) + b"\n")
    return store, public_path


def test_keygen_creates_private_key_with_mode_0600(tmp_path: Path) -> None:
    """The CLI creates a key pair and never overwrites it on a second run."""
    keys = tmp_path / "keys"
    result = runner.invoke(app, ["keygen", "--key-directory", str(keys)])
    assert result.exit_code == 0, result.output
    private_path = keys / "ed25519.pem"
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    original = private_path.read_bytes()
    repeated = runner.invoke(app, ["keygen", "--key-directory", str(keys)])
    assert repeated.exit_code == 1
    assert private_path.read_bytes() == original


@pytest.mark.parametrize("command", ["parse", "analyze", "report"])
def test_later_phase_commands_are_explicit_stubs(command: str) -> None:
    """Later-phase commands state their status without doing work."""
    result = runner.invoke(app, [command])
    assert result.exit_code == 0
    assert result.output.strip() == "not implemented in this phase"


def test_acquire_rejects_non_local_store_before_any_execution(tmp_path: Path) -> None:
    """Phase 1 cannot accidentally select an S3 or real-AWS backend."""
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["acquire", "--inventory", str(inventory), "--case-id", "C001", "--store", "s3"],
    )
    assert result.exit_code == 2
    assert "only --store local" in result.output


def test_acquire_reports_missing_signing_key(tmp_path: Path) -> None:
    """Acquisition stops before Ansible when the signing key is absent."""
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "acquire",
            "--inventory",
            str(inventory),
            "--case-id",
            "C001",
            "--private-key",
            str(tmp_path / "missing.pem"),
        ],
    )
    assert result.exit_code == 2
    assert "run elijah keygen first" in result.output


def test_verify_and_show_on_disk_evidence(tmp_path: Path) -> None:
    """The CLI verifies and displays actual read-only local evidence."""
    root = tmp_path / "evidence"
    _, public_path = _create_evidence(root, tmp_path / "keys")
    verified = runner.invoke(
        app,
        ["verify", "C001", "--evidence-root", str(root), "--public-key", str(public_path)],
    )
    assert verified.exit_code == 0, verified.output
    report = json.loads(verified.output)
    assert report["ok"] is True
    assert report["results"][0]["evidence_id"] == EVIDENCE_ID

    shown = runner.invoke(app, ["show", "C001", "--evidence-root", str(root)])
    assert shown.exit_code == 0
    assert json.loads(shown.output)["evidence"][0]["case_id"] == "C001"


def test_manifest_byte_change_fails_cli_and_names_signature(tmp_path: Path) -> None:
    """A real manifest edit is reported through the structured CLI result."""
    root = tmp_path / "evidence"
    store, public_path = _create_evidence(root, tmp_path / "keys")
    manifest_path = root / "C001" / EVIDENCE_ID / "manifest.json"
    manifest_path.chmod(0o644)
    manifest = json.loads(store.get(EVIDENCE_ID, "manifest.json"))
    manifest["target"]["hostname"] = "tampered"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    result = runner.invoke(
        app,
        ["verify", "C001", "--evidence-root", str(root), "--public-key", str(public_path)],
    )
    assert result.exit_code == 1
    report = json.loads(result.output)
    assert "manifest_signature" in report["results"][0]["failed_checks"]


def test_custody_byte_change_fails_cli_and_names_chain(tmp_path: Path) -> None:
    """A real custody edit is reported as a custody-chain failure."""
    root = tmp_path / "evidence"
    _, public_path = _create_evidence(root, tmp_path / "keys")
    custody_path = root / "C001" / EVIDENCE_ID / "custody.jsonl"
    custody_path.chmod(0o644)
    custody_path.write_bytes(custody_path.read_bytes().replace(b"researcher", b"intruder"))
    result = runner.invoke(
        app,
        ["verify", "C001", "--evidence-root", str(root), "--public-key", str(public_path)],
    )
    assert result.exit_code == 1
    report = json.loads(result.output)
    assert "custody_chain" in report["results"][0]["failed_checks"]


def test_verify_missing_case_returns_structured_failure(tmp_path: Path) -> None:
    """An empty case does not silently succeed."""
    result = runner.invoke(app, ["verify", "C001", "--evidence-root", str(tmp_path)])
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "no evidence found"
