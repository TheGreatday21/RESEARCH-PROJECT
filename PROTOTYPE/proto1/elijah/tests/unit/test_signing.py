"""Tests for Ed25519 key handling and manifest signatures."""

import stat
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from elijah.prov.signing import (
    generate_keypair,
    sign_manifest,
    unsigned_manifest_bytes,
    verify_manifest_signature,
)


def test_keygen_sign_and_verify(tmp_path: Path) -> None:
    """A newly generated key signs canonical bytes and enforces private mode."""
    private_path, public_path = generate_keypair(tmp_path)
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    manifest = {"case_id": "C001", "nested": {"b": 2, "a": 1}}
    signed = sign_manifest(manifest, private_path)
    assert signed["signature"]["algorithm"] == "ed25519"
    verify_manifest_signature(signed, public_path)
    assert unsigned_manifest_bytes(signed) == b'{"case_id":"C001","nested":{"a":1,"b":2}}'


def test_signature_detects_manifest_tampering(tmp_path: Path) -> None:
    """Changing any unsigned manifest field invalidates the signature."""
    private_path, public_path = generate_keypair(tmp_path)
    signed = sign_manifest({"case_id": "C001"}, private_path)
    signed["case_id"] = "C002"
    with pytest.raises(InvalidSignature):
        verify_manifest_signature(signed, public_path)


def test_keygen_never_overwrites_existing_private_key(tmp_path: Path) -> None:
    """Repeated key generation leaves the original private key untouched."""
    private_path, _ = generate_keypair(tmp_path)
    original = private_path.read_bytes()
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path)
    assert private_path.read_bytes() == original
