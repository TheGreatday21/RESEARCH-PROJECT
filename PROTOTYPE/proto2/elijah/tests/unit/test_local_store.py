"""Tests for local evidence path safety and read-only create-only writes."""

import stat
from io import BytesIO
from pathlib import Path

import pytest

from elijah.store.local import LocalStore

EVIDENCE_ID = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
OTHER_EVIDENCE_ID = "ee650768-83d9-4f04-a7f0-1b4d81be176e"


def test_put_get_list_and_read_only_mode(tmp_path: Path) -> None:
    """Local objects use the required layout, sorted paths, and mode 0444."""
    store = LocalStore(tmp_path, "C001")
    store.put(EVIDENCE_ID, "artifacts/access.log", b"one\n")
    store.put(EVIDENCE_ID, "manifest.json", BytesIO(b"{}"))
    assert store.get(EVIDENCE_ID, "artifacts/access.log") == b"one\n"
    assert store.list(EVIDENCE_ID) == ["artifacts/access.log", "manifest.json"]
    assert store.exists(EVIDENCE_ID, "manifest.json")
    path = tmp_path / "C001" / EVIDENCE_ID / "artifacts" / "access.log"
    assert stat.S_IMODE(path.stat().st_mode) == 0o444


def test_put_refuses_to_overwrite_evidence(tmp_path: Path) -> None:
    """An existing object remains byte-for-byte unchanged after a put attempt."""
    store = LocalStore(tmp_path, "C001")
    store.put(EVIDENCE_ID, "artifacts/access.log", b"original")
    with pytest.raises(FileExistsError):
        store.put(EVIDENCE_ID, "artifacts/access.log", b"replacement")
    assert store.get(EVIDENCE_ID, "artifacts/access.log") == b"original"


@pytest.mark.parametrize("path", ["../outside", "/absolute", "a/../../b", "a\\..\\b", ""])
def test_put_rejects_unsafe_relative_paths(tmp_path: Path, path: str) -> None:
    """Traversal, absolute paths, and platform-confusing separators are rejected."""
    store = LocalStore(tmp_path, "C001")
    with pytest.raises(ValueError):
        store.put(EVIDENCE_ID, path, b"evidence")


def test_invalid_evidence_ids_are_rejected(tmp_path: Path) -> None:
    """Evidence IDs cannot inject path components or non-v4 identifiers."""
    store = LocalStore(tmp_path, "C001")
    with pytest.raises(ValueError, match="evidence ID"):
        store.put("../escape", "manifest.json", b"{}")
    with pytest.raises(ValueError, match="evidence ID"):
        store.get("not-a-uuid", "manifest.json")


def test_case_scoped_evidence_discovery(tmp_path: Path) -> None:
    """Only canonical UUIDv4 directories in the selected case are discovered."""
    store = LocalStore(tmp_path, "C001")
    store.put(OTHER_EVIDENCE_ID, "manifest.json", b"{}")
    store.put(EVIDENCE_ID, "manifest.json", b"{}")
    (tmp_path / "C001" / "scratch").mkdir()
    (tmp_path / "C002").mkdir()
    assert store.list_evidence_ids() == sorted([EVIDENCE_ID, OTHER_EVIDENCE_ID])
