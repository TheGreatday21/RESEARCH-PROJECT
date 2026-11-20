"""Ed25519 key generation and canonical-manifest signatures."""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common.canonical import canonical_json_bytes, sha256_bytes


def unsigned_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Return canonical bytes for a manifest with its signature field removed."""
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return canonical_json_bytes(unsigned)


def key_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    """Derive a stable key ID from the raw public key."""
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_bytes(raw_public)


def generate_keypair(key_directory: Path) -> tuple[Path, Path]:
    """Create a new Ed25519 key pair without replacing existing keys."""
    key_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = key_directory / "ed25519.pem"
    public_path = key_directory / "ed25519.pub"

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as private_stream:
        private_stream.write(private_bytes)
    with public_path.open("xb") as public_stream:
        public_stream.write(public_bytes)
    public_path.chmod(0o644)
    return private_path, public_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from an unencrypted PEM file."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"private key is not Ed25519: {path}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"public key is not Ed25519: {path}")
    return key


def sign_manifest(manifest: Mapping[str, Any], private_key_path: Path) -> dict[str, Any]:
    """Return a manifest containing its deterministic Ed25519 signature."""
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(unsigned_manifest_bytes(manifest))
    signed = dict(manifest)
    signed["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id_for_public_key(private_key.public_key()),
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_manifest_signature(manifest: Mapping[str, Any], public_key_path: Path) -> None:
    """Raise ValueError or InvalidSignature when a manifest signature is invalid."""
    signature_block = manifest.get("signature")
    if not isinstance(signature_block, dict):
        raise ValueError("manifest signature block is missing")
    if signature_block.get("algorithm") != "ed25519":
        raise ValueError("manifest signature algorithm is not ed25519")

    public_key = load_public_key(public_key_path)
    if signature_block.get("key_id") != key_id_for_public_key(public_key):
        raise ValueError("manifest signature key ID does not match the verification key")
    try:
        signature = base64.b64decode(signature_block.get("value", ""), validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("manifest signature is not valid base64") from error
    public_key.verify(signature, unsigned_manifest_bytes(manifest))
