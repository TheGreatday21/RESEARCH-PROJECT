"""Structured verification of stored bytes, signatures, and custody history."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from common.canonical import hash_stream
from phase1_acquire.custody import CustodyFormatError, chain_errors, parse_custody_bytes
from phase1_acquire.manifest import structure_errors
from phase1_acquire.signing import verify_manifest_signature
from phase1_acquire.store import EvidenceStore


@dataclass(frozen=True)
class CheckResult:
    """Name one independent verification check and its outcome."""

    name: str
    passed: bool
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable check result."""
        return {"name": self.name, "passed": self.passed, "message": self.message}


@dataclass(frozen=True)
class VerificationResult:
    """Aggregate all checks without hiding individual failures."""

    evidence_id: str
    checks: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        """Return true only when every executed check passed."""
        return bool(self.checks) and all(check.passed for check in self.checks)

    @property
    def failed_checks(self) -> tuple[str, ...]:
        """Return the exact names of failed checks."""
        return tuple(check.name for check in self.checks if not check.passed)

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable verification report."""
        return {
            "evidence_id": self.evidence_id,
            "ok": self.ok,
            "failed_checks": list(self.failed_checks),
            "checks": [check.to_dict() for check in self.checks],
        }


def _load_json_object(data: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _verify_artifact(artifact: Mapping[str, Any], data: bytes) -> list[CheckResult]:
    stored_as = str(artifact.get("stored_as", "<unknown>"))
    checks: list[CheckResult] = []
    size_at_open = artifact.get("size_at_open")
    if not isinstance(size_at_open, int) or size_at_open < 0:
        return [
            CheckResult(
                name=f"artifact_schema:{stored_as}",
                passed=False,
                message="size_at_open must be a non-negative integer",
            )
        ]

    prefix = hash_stream(BytesIO(data), size_at_open)
    expected_source = artifact.get("sha256_source")
    expected_destination = artifact.get("sha256_destination")
    prefix_passed = (
        prefix.bytes_read == size_at_open
        and prefix.sha256 == expected_source
        and prefix.sha256 == expected_destination
        and artifact.get("verified") is True
    )
    checks.append(
        CheckResult(
            name=f"artifact_prefix:{stored_as}",
            passed=prefix_passed,
            message=(
                "source and destination prefix hashes match"
                if prefix_passed
                else "source/destination prefix mismatch, short read, or verified is false"
            ),
        )
    )

    full = hash_stream(BytesIO(data))
    full_passed = (
        full.sha256 == artifact.get("sha256_full")
        and full.bytes_read == artifact.get("stored_size")
    )
    checks.append(
        CheckResult(
            name=f"artifact_full:{stored_as}",
            passed=full_passed,
            message=(
                "complete stored artifact hash matches"
                if full_passed
                else "complete stored artifact hash or size mismatch"
            ),
        )
    )
    return checks


def verify_evidence(
    store: EvidenceStore,
    evidence_id: str,
    public_key_path: Path,
) -> VerificationResult:
    """Verify one evidence ID and name every failed integrity check."""
    checks: list[CheckResult] = []
    try:
        manifest_bytes = store.get(evidence_id, "manifest.json")
    except (FileNotFoundError, KeyError) as error:
        checks.append(CheckResult("manifest_present", False, str(error)))
        return VerificationResult(evidence_id, tuple(checks))
    checks.append(CheckResult("manifest_present", True, "manifest.json is present"))

    try:
        manifest = _load_json_object(manifest_bytes, "manifest.json")
    except ValueError as error:
        checks.append(CheckResult("manifest_json", False, str(error)))
        return VerificationResult(evidence_id, tuple(checks))
    checks.append(CheckResult("manifest_json", True, "manifest is a UTF-8 JSON object"))

    manifest_structure_errors = structure_errors(manifest)
    checks.append(
        CheckResult(
            "manifest_schema",
            not manifest_structure_errors,
            "; ".join(manifest_structure_errors) or "required manifest fields are present",
        )
    )

    try:
        verify_manifest_signature(manifest, public_key_path)
    except (InvalidSignature, ValueError, OSError) as error:
        checks.append(CheckResult("manifest_signature", False, str(error) or "invalid signature"))
    else:
        checks.append(CheckResult("manifest_signature", True, "Ed25519 signature is valid"))

    custody_entries: Sequence[Mapping[str, Any]] = []
    try:
        custody_bytes = store.get(evidence_id, "custody.jsonl")
    except (FileNotFoundError, KeyError) as error:
        checks.append(CheckResult("custody_present", False, str(error)))
        custody_bytes = None
    if custody_bytes is not None:
        checks.append(CheckResult("custody_present", True, "custody.jsonl is present"))
        try:
            custody_entries = parse_custody_bytes(custody_bytes)
        except CustodyFormatError as error:
            checks.append(CheckResult("custody_json", False, str(error)))
        else:
            checks.append(CheckResult("custody_json", True, "every custody line is valid JSON"))
            custody_chain_errors = chain_errors(custody_entries)
            checks.append(
                CheckResult(
                    "custody_chain",
                    not custody_chain_errors,
                    "; ".join(custody_chain_errors) or "custody hash chain is valid",
                )
            )
            reference_passed = any(
                entry.get("entry_hash") == manifest.get("custody_ref")
                and entry.get("evidence_id") == manifest.get("evidence_id")
                and entry.get("action") == "acquire"
                for entry in custody_entries
            )
            checks.append(
                CheckResult(
                    "custody_reference",
                    reference_passed,
                    (
                        "manifest references its acquisition entry"
                        if reference_passed
                        else "manifest custody_ref does not reference a matching acquire entry"
                    ),
                )
            )

    stored_objects: list[Any] = []
    for field in ("artifacts", "context_artifacts"):
        objects = manifest.get(field)
        if isinstance(objects, list):
            stored_objects.extend(objects)
    for artifact in stored_objects:
        if not isinstance(artifact, dict):
            continue
        stored_as = artifact.get("stored_as")
        if not isinstance(stored_as, str):
            continue
        try:
            data = store.get(evidence_id, stored_as)
        except (FileNotFoundError, KeyError, ValueError) as error:
            checks.append(CheckResult(f"artifact_present:{stored_as}", False, str(error)))
        else:
            checks.append(
                CheckResult(f"artifact_present:{stored_as}", True, "stored artifact is present")
            )
            checks.extend(_verify_artifact(artifact, data))
    return VerificationResult(evidence_id, tuple(checks))
