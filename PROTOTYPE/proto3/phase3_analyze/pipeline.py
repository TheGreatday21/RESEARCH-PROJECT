"""Shared loading and verification steps for every analysis command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phase1_acquire.store import EvidenceStore
from phase1_acquire.verify import verify_evidence
from phase2_parse.dataset import verify_derived_dataset


class AnalysisError(RuntimeError):
    """Report an input that analysis must not read, such as unverified derived data."""


def require_verified_derived(
    store: EvidenceStore,
    evidence_id: str,
    derived_directory: Path,
    public_key_path: Path,
) -> None:
    """Raise AnalysisError unless the derived dataset verifies against its evidence."""
    result = verify_derived_dataset(store, evidence_id, derived_directory, public_key_path)
    if not result.ok:
        raise AnalysisError(
            f"derived verification failed for {evidence_id}: {', '.join(result.failed_checks)}"
        )


def require_verified_evidence(
    store: EvidenceStore,
    evidence_id: str,
    public_key_path: Path,
) -> None:
    """Raise AnalysisError unless the stored evidence package verifies."""
    result = verify_evidence(store, evidence_id, public_key_path)
    if not result.ok:
        raise AnalysisError(
            f"evidence verification failed for {evidence_id}: {', '.join(result.failed_checks)}"
        )


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnalysisError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise AnalysisError(f"{label} must be a JSON object")
    return value


def load_inputs(
    store: EvidenceStore,
    evidence_id: str,
    derived_directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the evidence manifest and the derived parse report as JSON objects."""
    try:
        manifest = _json_object(store.get(evidence_id, "manifest.json"), "manifest.json")
        report = _json_object(
            (derived_directory / "parse_report.json").read_bytes(), "parse_report.json"
        )
    except (OSError, KeyError) as error:
        raise AnalysisError(f"cannot load analysis inputs for {evidence_id}: {error}") from error
    return manifest, report
