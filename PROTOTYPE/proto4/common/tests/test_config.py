"""Tests for control-host configuration validation."""

from pathlib import Path

import pytest

from common.config import Settings, validate_case_id


def test_case_id_accepts_specification_format() -> None:
    """A three-digit case ID is accepted unchanged."""
    assert validate_case_id("C001") == "C001"


@pytest.mark.parametrize("case_id", ["C1", "C0001", "c001", "D001", "C01A"])
def test_case_id_rejects_other_formats(case_id: str) -> None:
    """Malformed or ambiguous case IDs fail before paths are created."""
    with pytest.raises(ValueError, match="case ID"):
        validate_case_id(case_id)


def test_default_key_paths(tmp_path: Path) -> None:
    """Signing key paths remain below the configured key directory."""
    settings = Settings(key_directory=tmp_path)
    assert settings.private_key_path == tmp_path / "ed25519.pem"
    assert settings.public_key_path == tmp_path / "ed25519.pub"
