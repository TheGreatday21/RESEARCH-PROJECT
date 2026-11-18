"""Construction and structural checks for signed acquisition manifests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = 1
REQUIRED_FIELDS = (
    "schema_version",
    "case_id",
    "evidence_id",
    "acquisition_id",
    "acquirer",
    "target",
    "timing",
    "artifacts",
    "context_artifacts",
    "footprint",
    "custody_ref",
    "signature",
)


def build_manifest(
    *,
    case_id: str,
    acquirer: Mapping[str, Any],
    target: Mapping[str, Any],
    timing: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    context_artifacts: Sequence[Mapping[str, Any]],
    footprint: Mapping[str, Any],
    custody_ref: str,
    evidence_id: str | None = None,
    acquisition_id: str | None = None,
) -> dict[str, Any]:
    """Build an unsigned manifest with fresh UUIDv4 identifiers by default."""
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "evidence_id": evidence_id or str(uuid4()),
        "acquisition_id": acquisition_id or str(uuid4()),
        "acquirer": dict(acquirer),
        "target": dict(target),
        "timing": dict(timing),
        "artifacts": [dict(artifact) for artifact in artifacts],
        "context_artifacts": [dict(artifact) for artifact in context_artifacts],
        "footprint": dict(footprint),
        "custody_ref": custody_ref,
    }


def structure_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return structural errors needed before provenance checks can run."""
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            errors.append(f"missing manifest field: {field}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"unsupported schema_version: {manifest.get('schema_version')!r}")
    for field in ("artifacts", "context_artifacts"):
        value = manifest.get(field)
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            errors.append(f"{field} must be a list of objects")
    for field in ("case_id", "evidence_id", "acquisition_id", "custody_ref"):
        if field in manifest and not isinstance(manifest[field], str):
            errors.append(f"{field} must be a string")
    return errors
