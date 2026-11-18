"""Run Ansible acquisition and assemble signed evidence through a store."""

from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import uuid4

from elijah import __version__
from elijah.canonical import canonical_json_bytes, hash_file, sha256_bytes
from elijah.config import validate_case_id
from elijah.prov.custody import build_entry
from elijah.prov.manifest import build_manifest
from elijah.prov.signing import sign_manifest
from elijah.store.base import EvidenceStore


class AcquisitionError(RuntimeError):
    """Report an acquisition failure without deleting partial evidence."""


@dataclass(frozen=True)
class FetchedArtifact:
    """Pair a manifest artifact with its optional staged file."""

    metadata: dict[str, Any]
    local_path: Path | None


@dataclass(frozen=True)
class CapturedContext:
    """Pair a manifest context artifact with its exact stored bytes."""

    metadata: dict[str, Any]
    content: bytes


@dataclass(frozen=True)
class SignedAcquisition:
    """Hold a signed manifest and its referenced custody entry."""

    manifest: dict[str, Any]
    custody_entry: dict[str, Any]


@dataclass(frozen=True)
class AcquisitionResult:
    """Summarize stored evidence and every unverified source artifact."""

    evidence_id: str
    manifest: Mapping[str, Any]
    unverified_artifacts: tuple[str, ...]
    collection_errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """Return whether every collected artifact transferred and verified."""
        return not self.unverified_artifacts and not self.collection_errors


def _read_json_object(path: Path) -> dict[str, Any]:
    """Read one staging JSON object with a labelled validation error."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcquisitionError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise AcquisitionError(f"expected a JSON object in {path}")
    return value


def _run_ansible(inventory: Path, case_id: str, staging_dir: Path) -> None:
    """Run the packaged playbook with pipelining and explicit staging paths."""
    inventory = inventory.resolve()
    if not inventory.is_file():
        raise AcquisitionError(f"inventory does not exist: {inventory}")
    staging_dir = staging_dir.resolve()
    staging_dir.mkdir(parents=True, exist_ok=True)
    if any(staging_dir.iterdir()):
        raise AcquisitionError(f"staging directory must be empty: {staging_dir}")

    ansible_dir = Path(__file__).resolve().parent / "ansible"
    playbook = ansible_dir / "acquire.yml"
    executable = shutil.which("ansible-playbook")
    if executable is None:
        sibling = Path(sys.executable).with_name("ansible-playbook")
        executable = str(sibling) if sibling.is_file() else None
    if executable is None:
        raise AcquisitionError("ansible-playbook is not installed or not on PATH")
    extra_vars = canonical_json_bytes(
        {"elijah_case_id": case_id, "elijah_staging_dir": str(staging_dir)}
    ).decode("utf-8")
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(ansible_dir / "ansible.cfg")
    environment["ANSIBLE_PIPELINING"] = "True"
    command = [
        executable,
        "-i",
        str(inventory),
        str(playbook),
        "--extra-vars",
        extra_vars,
    ]
    completed = subprocess.run(
        command,
        cwd=ansible_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        output = (completed.stdout + "\n" + completed.stderr).strip()
        raise AcquisitionError(
            f"ansible-playbook failed with exit {completed.returncode}:\n{output}"
        )


def verify_fetched_artifacts(
    collector: Mapping[str, Any],
    staging_dir: Path,
) -> list[FetchedArtifact]:
    """Compare each source prefix with its fetched copy and retain full hashes."""
    source_artifacts = collector.get("artifacts", [])
    if not isinstance(source_artifacts, list):
        raise AcquisitionError("collector artifacts must be a list")
    results: list[FetchedArtifact] = []
    for index, source in enumerate(source_artifacts):
        if not isinstance(source, dict):
            raise AcquisitionError(f"collector artifact {index} is not an object")
        record = dict(source)
        source_path = str(source.get("source_path", f"artifact-{index}"))
        basename = Path(source_path).name or f"artifact-{index}"
        record["stored_as"] = f"artifacts/{index:04d}-{basename}"
        record["verified"] = False
        if "collection_error" in source:
            record["verification_error"] = "collection failed on the target"
            results.append(FetchedArtifact(record, None))
            continue

        local_path = staging_dir / "artifacts" / f"{index:04d}" / basename
        size_at_open = source.get("size_at_open")
        if not isinstance(size_at_open, int) or size_at_open < 0:
            record["verification_error"] = "collector size_at_open is invalid"
            results.append(FetchedArtifact(record, None))
            continue
        try:
            prefix = hash_file(str(local_path), size_at_open)
            full = hash_file(str(local_path))
        except OSError as error:
            record["sha256_destination"] = ""
            record["sha256_full"] = ""
            record["stored_size"] = 0
            record["verification_error"] = f"fetched artifact is unavailable: {error}"
            results.append(FetchedArtifact(record, None))
            continue

        record["sha256_destination"] = prefix.sha256
        record["sha256_full"] = full.sha256
        record["stored_size"] = full.bytes_read
        source_prefix_complete = source.get("prefix_bytes_read", size_at_open) == size_at_open
        verified = (
            source_prefix_complete
            and prefix.bytes_read == size_at_open
            and prefix.sha256 == source.get("sha256_source")
        )
        record["verified"] = verified
        if not verified:
            record["verification_error"] = "source and destination prefix hashes differ"
        results.append(FetchedArtifact(record, local_path))
    return results


def prepare_context_artifacts(collector: Mapping[str, Any]) -> list[CapturedContext]:
    """Convert collector text records into deterministic stored context bytes."""
    source_context = collector.get("context_artifacts", [])
    if not isinstance(source_context, list):
        raise AcquisitionError("collector context_artifacts must be a list")
    results: list[CapturedContext] = []
    for index, source in enumerate(source_context):
        if not isinstance(source, dict):
            raise AcquisitionError(f"collector context artifact {index} is not an object")
        record = {key: value for key, value in source.items() if key != "content"}
        logical_name = str(source.get("logical_name", f"context-{index}"))
        safe_name = "".join(
            character if character.isalnum() or character in "._-" else "_"
            for character in logical_name
        )
        content = str(source.get("content", "")).encode("utf-8")
        stored_hash = sha256_bytes(content)
        record.update(
            {
                "stored_as": f"context/{index:04d}-{safe_name}.txt",
                "sha256_destination": stored_hash,
                "sha256_full": stored_hash,
                "stored_size": len(content),
                "size_at_open": len(content),
                "verified": stored_hash == source.get("sha256_source"),
            }
        )
        results.append(CapturedContext(record, content))
    return results


def _parse_utc(value: str) -> datetime:
    """Parse an ISO timestamp and require an explicit UTC-compatible offset."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AcquisitionError(f"timestamp lacks a UTC offset: {value}")
    return parsed.astimezone(UTC)


def _format_utc(value: datetime) -> str:
    """Format a midpoint timestamp as UTC ISO 8601."""
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timing(collector: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Estimate target/control offset using both probe interval midpoints."""
    started = _parse_utc(str(metadata["control_started_utc"]))
    probe_finished = _parse_utc(str(metadata["control_probe_finished_utc"]))
    target_before = _parse_utc(str(collector["target_time_before"]["utc"]))
    target_after = _parse_utc(str(collector["target_time_after"]["utc"]))
    control_midpoint = started + (probe_finished - started) / 2
    target_midpoint = target_before + (target_after - target_before) / 2
    return {
        "started_utc": metadata["control_started_utc"],
        "finished_utc": metadata["control_finished_utc"],
        "target_clock_before": collector["target_time_before"],
        "target_clock_after": collector["target_time_after"],
        "control_clock_at_probe": _format_utc(control_midpoint),
        "estimated_offset_seconds": (target_midpoint - control_midpoint).total_seconds(),
    }


def _git_commit() -> str:
    """Return the repository commit when available, otherwise unknown."""
    repository_root = Path(__file__).resolve().parents[3]
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "unknown"
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _ansible_version() -> str:
    """Read the installed Ansible Core package version."""
    try:
        return version("ansible-core")
    except PackageNotFoundError:
        return "unknown"


def assemble_signed_acquisition(
    *,
    case_id: str,
    collector: Mapping[str, Any],
    run_metadata: Mapping[str, Any],
    artifacts: Sequence[FetchedArtifact],
    context_artifacts: Sequence[CapturedContext],
    private_key_path: Path,
    evidence_id: str | None = None,
    acquisition_id: str | None = None,
) -> SignedAcquisition:
    """Build signed provenance and its hash-chained acquisition entry."""
    evidence_id = evidence_id or str(uuid4())
    acquisition_id = acquisition_id or str(uuid4())
    operator = getpass.getuser()
    collection_errors = collector.get("collection_errors", [])
    custody_entry = build_entry(
        seq=1,
        actor=operator,
        action="acquire",
        evidence_id=evidence_id,
        details={
            "case_id": case_id,
            "acquisition_id": acquisition_id,
            "artifact_count": len(artifacts),
            "context_artifact_count": len(context_artifacts),
        },
    )
    ssh_user = str(run_metadata.get("ssh_user", "forensic-acq"))
    preflight = run_metadata.get("preflight_commands", [])
    collector_footprint = collector.get("footprint", {})
    unsigned = build_manifest(
        case_id=case_id,
        evidence_id=evidence_id,
        acquisition_id=acquisition_id,
        acquirer={
            "tool": "elijah",
            "version": __version__,
            "git_commit": _git_commit(),
            "ansible_version": _ansible_version(),
            "operator": operator,
            "control_hostname": socket.gethostname(),
        },
        target={
            "hostname": collector.get("hostname", ""),
            "address": run_metadata.get("target_address", ""),
            "os_release": collector.get("os_release", {}),
            "kernel": collector.get("kernel", ""),
            "ssh_user": ssh_user,
            "cloud": {"provider": "", "instance_id": "", "region": "", "account_id": ""},
        },
        timing=_timing(collector, run_metadata),
        artifacts=[artifact.metadata for artifact in artifacts],
        context_artifacts=[context.metadata for context in context_artifacts],
        footprint={
            "files_created": run_metadata.get("files_created", []),
            "commands": list(preflight) + list(collector_footprint.get("commands", [])),
            "ssh_user": ssh_user,
        },
        custody_ref=str(custody_entry["entry_hash"]),
    )
    if isinstance(collection_errors, list):
        unsigned["collection_errors"] = collection_errors
    return SignedAcquisition(sign_manifest(unsigned, private_key_path), custody_entry)


def acquire_evidence(
    *,
    store: EvidenceStore,
    inventory: Path,
    case_id: str,
    staging_dir: Path,
    private_key_path: Path,
) -> AcquisitionResult:
    """Acquire, verify, sign, and store one evidence set without cloud access."""
    validate_case_id(case_id)
    _run_ansible(inventory, case_id, staging_dir)
    collector = _read_json_object(staging_dir / "collector.json")
    run_metadata = _read_json_object(staging_dir / "run_metadata.json")
    artifacts = verify_fetched_artifacts(collector, staging_dir)
    context = prepare_context_artifacts(collector)
    signed = assemble_signed_acquisition(
        case_id=case_id,
        collector=collector,
        run_metadata=run_metadata,
        artifacts=artifacts,
        context_artifacts=context,
        private_key_path=private_key_path,
    )
    evidence_id = str(signed.manifest["evidence_id"])

    for artifact in artifacts:
        if artifact.local_path is None:
            continue
        stored_as = str(artifact.metadata["stored_as"])
        with artifact.local_path.open("rb") as stream:
            store.put(
                evidence_id,
                stored_as,
                stream,
                {"sha256": str(artifact.metadata["sha256_full"])},
            )
    for context_artifact in context:
        store.put(
            evidence_id,
            str(context_artifact.metadata["stored_as"]),
            context_artifact.content,
            {"sha256": str(context_artifact.metadata["sha256_full"])},
        )
    store.put(
        evidence_id,
        "custody.jsonl",
        canonical_json_bytes(signed.custody_entry) + b"\n",
    )
    store.put(evidence_id, "manifest.json", canonical_json_bytes(signed.manifest))

    unverified = tuple(
        str(artifact.metadata.get("source_path", artifact.metadata["stored_as"]))
        for artifact in artifacts
        if artifact.metadata.get("verified") is not True
    )
    errors = collector.get("collection_errors", [])
    return AcquisitionResult(
        evidence_id=evidence_id,
        manifest=signed.manifest,
        unverified_artifacts=unverified,
        collection_errors=tuple(str(error) for error in errors) if isinstance(errors, list) else (),
    )
