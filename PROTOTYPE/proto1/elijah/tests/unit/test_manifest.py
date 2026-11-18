"""Tests for Phase 1 manifest construction and structural validation."""

from uuid import UUID

from elijah.prov.manifest import build_manifest, structure_errors


def _manifest() -> dict[str, object]:
    return build_manifest(
        case_id="C001",
        acquirer={"tool": "elijah", "version": "0.1.0"},
        target={"hostname": "target", "cloud": {}},
        timing={"started_utc": "2026-11-11T00:00:00Z"},
        artifacts=[],
        context_artifacts=[],
        footprint={"commands": [], "files_created": []},
        custody_ref="a" * 64,
    )


def test_manifest_uses_uuid4_identifiers() -> None:
    """Evidence and acquisition IDs are independent UUIDv4 values."""
    manifest = _manifest()
    evidence_id = UUID(str(manifest["evidence_id"]))
    acquisition_id = UUID(str(manifest["acquisition_id"]))
    assert evidence_id.version == 4
    assert acquisition_id.version == 4
    assert evidence_id != acquisition_id
    assert manifest["schema_version"] == 1


def test_structure_errors_name_missing_fields() -> None:
    """Structural verification reports each absent required field."""
    manifest = _manifest()
    del manifest["case_id"]
    del manifest["artifacts"]
    errors = structure_errors(manifest)
    assert "missing manifest field: case_id" in errors
    assert "missing manifest field: artifacts" in errors
