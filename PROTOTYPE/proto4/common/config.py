"""Validated configuration defaults for the control host."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CASE_ID_PATTERN = re.compile(r"^C[0-9]{3}$")


@dataclass(frozen=True)
class Settings:
    """Resolve Phase 1 paths without reading process-global state."""

    evidence_root: Path = Path("evidence")
    key_directory: Path = Path.home() / ".lapa" / "keys"

    @property
    def private_key_path(self) -> Path:
        """Return the default Ed25519 private-key path."""
        return self.key_directory / "ed25519.pem"

    @property
    def public_key_path(self) -> Path:
        """Return the default Ed25519 public-key path."""
        return self.key_directory / "ed25519.pub"


def validate_case_id(case_id: str) -> str:
    """Return a valid three-digit case identifier or raise ValueError."""
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ValueError("case ID must match C followed by exactly three digits, for example C001")
    return case_id
