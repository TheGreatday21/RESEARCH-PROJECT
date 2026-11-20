"""Tests for Typer commands and on-disk verification failures."""

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.app import app
from common.canonical import canonical_json_bytes, sha256_bytes
from phase1_acquire.custody import build_entry
from phase1_acquire.manifest import build_manifest
from phase1_acquire.signing import generate_keypair, sign_manifest
from phase1_acquire.store import LocalStore

EVIDENCE_ID = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
ACQUISITION_ID = "ee650768-83d9-4f04-a7f0-1b4d81be176e"
runner = CliRunner()


def _create_evidence(root: Path, keys: Path) -> tuple[LocalStore, Path]:
    private_path, public_path = generate_keypair(keys)
    store = LocalStore(root, "C001")
    access_bytes = (
        b'127.0.0.1 - - [11/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 2 "-" "ua"\n'
    )
    access_hash = sha256_bytes(access_bytes)
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
        acquirer={"tool": "lapa", "version": "0.1.0"},
        target={"hostname": "target", "cloud": {}},
        timing={"started_utc": "2026-11-11T00:00:00Z"},
        artifacts=[
            {
                "logical_name": "access.log",
                "source_path": "/var/log/nginx/access.log",
                "size_at_open": len(access_bytes),
                "sha256_source": access_hash,
                "sha256_destination": access_hash,
                "sha256_full": access_hash,
                "stored_size": len(access_bytes),
                "stored_as": "artifacts/0000-access.log",
                "changed_during_read": False,
                "verified": True,
            }
        ],
        context_artifacts=[],
        footprint={"commands": [], "files_created": []},
        custody_ref=str(custody["entry_hash"]),
    )
    unsigned["collection_errors"] = []
    signed = sign_manifest(unsigned, private_path)
    store.put(EVIDENCE_ID, "artifacts/0000-access.log", access_bytes)
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


@pytest.mark.parametrize("command", ["detect", "evaluate", "report"])
def test_phase4_commands_require_a_case_id(command: str) -> None:
    """Phase 4 commands are real commands and reject a missing CASE_ID."""
    assert runner.invoke(app, [command]).exit_code == 2


def test_analyze_command_requires_case_id() -> None:
    """The analyze command is a real Phase 3 command and requires a CASE_ID argument."""
    result = runner.invoke(app, ["analyze"])
    # Typer exits 2 when required arguments are missing.
    assert result.exit_code == 2


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
    assert "run lapa keygen first" in result.output


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


DEMO = Path(__file__).resolve().parent / "fixtures" / "phase2-demo"
DEMO_ID = "d13a92df-dbbf-48dc-9784-59758a4c3456"
LABELS = Path(__file__).resolve().parents[2] / "lab" / "out" / "labels.jsonl"
needs_demo = pytest.mark.skipif(
    not (DEMO / "derived").is_dir() or not LABELS.is_file(),
    reason="recorded Phase 2 demo package is not present",
)


def _demo_args(*extra: str) -> list[str]:
    return [
        "C002",
        "--evidence-id",
        DEMO_ID,
        "--derived-root",
        str(DEMO / "derived"),
        "--evidence-root",
        str(DEMO / "evidence"),
        "--public-key",
        str(DEMO / "ed25519.pub"),
        *extra,
    ]


@needs_demo
def test_detect_evaluate_and_report_on_the_recorded_demo(tmp_path: Path) -> None:
    """Run every Phase 3 and 4 command against the signed live-lab package."""
    analyze = runner.invoke(app, ["analyze", *_demo_args("--analysis-root", str(tmp_path / "a"))])
    assert analyze.exit_code == 0, analyze.output

    detect = runner.invoke(app, ["detect", *_demo_args("--analysis-root", str(tmp_path / "a"))])
    assert detect.exit_code == 0, detect.output
    summary = json.loads(detect.output)["results"][0]
    assert summary["by_class"] == {
        "brute_force": 8,
        "low_slow": 5,
        "path_scan": 6,
        "traversal": 3,
    } | {"sqli_like": 3}
    assert (tmp_path / "a" / "C002" / DEMO_ID / "detections.json").is_file()

    evaluate = runner.invoke(
        app,
        ["evaluate", *_demo_args("--labels", str(LABELS), "--bench-root", str(tmp_path / "b"))],
    )
    assert evaluate.exit_code == 0, evaluate.output
    result = json.loads(evaluate.output)["results"][0]
    assert result["labelled_rows"] == 72
    assert result["labels_without_joined_row"] == 2
    assert result["rows_without_trace_id_flagged"] == 2

    report = runner.invoke(
        app,
        ["report", *_demo_args("--labels", str(LABELS), "--reports-root", str(tmp_path / "r"))],
    )
    assert report.exit_code == 0, report.output
    text = (tmp_path / "r" / "C002" / DEMO_ID / "report.md").read_text(encoding="utf-8")
    assert "## Findings" in text and "## Limitations" in text
    assert "## Trust boundaries and limitations" in text
    report_json = json.loads(
        (tmp_path / "r" / "C002" / DEMO_ID / "report.json").read_text(encoding="utf-8")
    )
    assert report_json["trust_boundaries"]["provenance"]["custody_entry_count"] == 1
    assert report_json["trust_boundaries"]["evaluation_labels"]["file"] == "labels.jsonl"


@needs_demo
def test_phase4_commands_refuse_tampered_derived_data(tmp_path: Path) -> None:
    """A flipped byte in the derived parse report blocks detection and reporting."""
    import shutil

    derived = tmp_path / "derived"
    shutil.copytree(DEMO / "derived", derived)
    report_file = derived / "C002" / DEMO_ID / "parse_report.json"
    report_file.chmod(0o600)
    data = bytearray(report_file.read_bytes())
    data[0] ^= 1
    report_file.write_bytes(bytes(data))
    for command in ("detect", "report"):
        args = _demo_args("--derived-root", str(derived))
        result = runner.invoke(
            app,
            [command, *args, "--analysis-root", str(tmp_path / "a")]
            if command == "detect"
            else [command, *args, "--reports-root", str(tmp_path / "r")],
        )
        assert result.exit_code == 1
    assert not (tmp_path / "a").exists()
    assert not (tmp_path / "r").exists()
