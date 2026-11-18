"""Storage boundary shared by local and future S3-compatible stores."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from io import BytesIO
from typing import BinaryIO


class EvidenceStore(ABC):
    """Store and retrieve immutable evidence objects by relative path."""

    @abstractmethod
    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        """Create an object without overwriting existing evidence."""

    def open_read(self, evidence_id: str, relative_path: str) -> BinaryIO:
        """Open read-only bytes; stores without streaming support use memory."""
        return BytesIO(self.get(evidence_id, relative_path))

    @abstractmethod
    def get(self, evidence_id: str, relative_path: str) -> bytes:
        """Return the complete object as bytes."""

    @abstractmethod
    def list(self, evidence_id: str) -> list[str]:
        """Return sorted relative object paths for one evidence ID."""

    @abstractmethod
    def exists(self, evidence_id: str, relative_path: str) -> bool:
        """Return whether an object exists."""
