"""Filesystem evidence storage with create-only writes and read-only files."""

from __future__ import annotations

import builtins
import shutil
from abc import ABC, abstractmethod
from collections.abc import Mapping
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from uuid import UUID

from common.config import validate_case_id

READ_ONLY_MODE = 0o444


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


class LocalStore(EvidenceStore):
    """Store evidence below evidence/<case_id>/<evidence_id>/ on local disk."""

    def __init__(self, root: Path, case_id: str) -> None:
        """Bind one store instance to a validated case directory."""
        self.root = root
        self.case_id = validate_case_id(case_id)
        self.case_directory = root / case_id

    @staticmethod
    def _validate_evidence_id(evidence_id: str) -> None:
        """Require the canonical UUIDv4 evidence identifiers used by manifests."""
        try:
            parsed = UUID(evidence_id)
        except ValueError as error:
            raise ValueError(f"invalid evidence ID: {evidence_id!r}") from error
        if parsed.version != 4 or str(parsed) != evidence_id.lower():
            raise ValueError(f"evidence ID must be a canonical UUIDv4: {evidence_id!r}")

    @staticmethod
    def _relative_parts(relative_path: str) -> tuple[str, ...]:
        """Validate a portable relative object path and reject traversal."""
        if not relative_path or "\x00" in relative_path or "\\" in relative_path:
            raise ValueError(f"invalid evidence relative path: {relative_path!r}")
        pure_path = PurePosixPath(relative_path)
        if pure_path.is_absolute() or not pure_path.parts or any(
            part in ("", ".", "..") for part in pure_path.parts
        ):
            raise ValueError(
                f"evidence path must be relative and traversal-free: {relative_path!r}"
            )
        return pure_path.parts

    def _evidence_directory(self, evidence_id: str) -> Path:
        """Return the directory for a validated evidence ID."""
        self._validate_evidence_id(evidence_id)
        return self.case_directory / evidence_id

    def _object_path(self, evidence_id: str, relative_path: str) -> Path:
        """Resolve an object path while containing it within its evidence directory."""
        evidence_directory = self._evidence_directory(evidence_id)
        parts = self._relative_parts(relative_path)
        candidate = evidence_directory.joinpath(*parts)
        try:
            candidate.resolve(strict=False).relative_to(evidence_directory.resolve(strict=False))
        except ValueError as error:
            raise ValueError(
                f"evidence path escapes its evidence directory: {relative_path!r}"
            ) from error
        return candidate

    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        """Create one read-only object and never overwrite existing evidence."""
        del metadata
        target = self._object_path(evidence_id, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as output:
                if isinstance(bytes_or_stream, bytes):
                    output.write(bytes_or_stream)
                else:
                    shutil.copyfileobj(bytes_or_stream, output, length=1024 * 1024)
        except Exception:
            if target.exists() and target.is_file():
                target.chmod(READ_ONLY_MODE)
            raise
        target.chmod(READ_ONLY_MODE)

    def open_read(self, evidence_id: str, relative_path: str) -> BinaryIO:
        """Open one evidence object read-only without loading it into memory."""
        target = self._object_path(evidence_id, relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"evidence object not found: {relative_path}")
        return target.open("rb")

    def get(self, evidence_id: str, relative_path: str) -> bytes:
        """Read one complete evidence object."""
        target = self._object_path(evidence_id, relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"evidence object not found: {relative_path}")
        return target.read_bytes()

    def list(self, evidence_id: str) -> list[str]:
        """List all regular evidence objects in deterministic path order."""
        evidence_directory = self._evidence_directory(evidence_id)
        if not evidence_directory.is_dir():
            return []
        return sorted(
            path.relative_to(evidence_directory).as_posix()
            for path in evidence_directory.rglob("*")
            if path.is_file()
        )

    def exists(self, evidence_id: str, relative_path: str) -> bool:
        """Return whether a regular evidence object exists."""
        return self._object_path(evidence_id, relative_path).is_file()

    def list_evidence_ids(self) -> builtins.list[str]:
        """Discover canonical evidence IDs below this store's case directory."""
        if not self.case_directory.is_dir():
            return []
        evidence_ids: builtins.list[str] = []
        for path in self.case_directory.iterdir():
            if not path.is_dir():
                continue
            try:
                self._validate_evidence_id(path.name)
            except ValueError:
                continue
            evidence_ids.append(path.name)
        return sorted(evidence_ids)
