"""Typer command-line interface for Phase 1 acquisition and verification."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated, Any

import typer

from elijah.acquire.orchestrator import AcquisitionError, acquire_evidence
from elijah.canonical import canonical_json_bytes
from elijah.config import Settings, validate_case_id
from elijah.prov.signing import generate_keypair
from elijah.prov.verify import verify_evidence
from elijah.store.local import LocalStore

app = typer.Typer(
    name="elijah",
    help="Acquire nginx evidence with signed provenance and verify local evidence.",
    no_args_is_help=True,
)


def _echo_json(value: Any) -> None:
    """Print one deterministic JSON document."""
    typer.echo(canonical_json_bytes(value).decode("utf-8"))


def _key_paths(
    private_key: Path | None,
    public_key: Path | None,
) -> tuple[Path, Path]:
    """Resolve explicit key paths or the user's Phase 1 defaults."""
    settings = Settings()
    return (
        private_key or settings.private_key_path,
        public_key or settings.public_key_path,
    )


@app.command("keygen")
def keygen_command(
    key_directory: Annotated[
        Path | None,
        typer.Option("--key-directory", file_okay=False, dir_okay=True),
    ] = None,
) -> None:
    """Create a new Ed25519 key pair without replacing existing keys."""
    directory = key_directory or Settings().key_directory
    try:
        private_path, public_path = generate_keypair(directory)
    except (OSError, ValueError) as error:
        typer.echo(f"key generation failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    _echo_json({"private_key": str(private_path), "public_key": str(public_path)})


@app.command("acquire")
def acquire_command(
    inventory: Annotated[
        Path,
        typer.Option("--inventory", exists=True, file_okay=True, dir_okay=False),
    ],
    case_id: Annotated[str, typer.Option("--case-id")],
    store: Annotated[str, typer.Option("--store")] = "local",
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    staging_dir: Annotated[Path | None, typer.Option("--staging-dir")] = None,
    private_key: Annotated[Path | None, typer.Option("--private-key")] = None,
) -> None:
    """Acquire target logs and store signed evidence through the local store."""
    if store != "local":
        raise typer.BadParameter("Phase 1 supports only --store local")
    try:
        validate_case_id(case_id)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    private_path, _ = _key_paths(private_key, None)
    if not private_path.is_file():
        typer.echo(f"signing key not found: {private_path}; run elijah keygen first", err=True)
        raise typer.Exit(code=2)
    staging = staging_dir or Path(tempfile.mkdtemp(prefix=f"elijah-{case_id}-"))
    local_store = LocalStore(evidence_root, case_id)
    try:
        result = acquire_evidence(
            store=local_store,
            inventory=inventory,
            case_id=case_id,
            staging_dir=staging,
            private_key_path=private_path,
        )
    except (AcquisitionError, OSError, ValueError) as error:
        typer.echo(f"acquisition failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    _echo_json(
        {
            "case_id": case_id,
            "evidence_id": result.evidence_id,
            "ok": result.ok,
            "unverified_artifacts": list(result.unverified_artifacts),
            "collection_errors": list(result.collection_errors),
            "staging_dir": str(staging),
            "store": "local",
        }
    )
    if not result.ok:
        raise typer.Exit(code=2)


@app.command("verify")
def verify_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
) -> None:
    """Verify every acquisition in a case, or one explicitly selected ID."""
    _, public_path = _key_paths(None, public_key)
    try:
        store = LocalStore(evidence_root, case_id)
        evidence_ids = [evidence_id] if evidence_id else store.list_evidence_ids()
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    if not evidence_ids:
        _echo_json({"case_id": case_id, "ok": False, "error": "no evidence found", "results": []})
        raise typer.Exit(code=1)
    try:
        results = [verify_evidence(store, item, public_path) for item in evidence_ids]
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    ok = all(result.ok for result in results)
    _echo_json(
        {
            "case_id": case_id,
            "ok": ok,
            "results": [result.to_dict() for result in results],
        }
    )
    if not ok:
        raise typer.Exit(code=1)


@app.command("show")
def show_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
) -> None:
    """Show canonical manifests for acquisitions in a case."""
    try:
        store = LocalStore(evidence_root, case_id)
        evidence_ids = [evidence_id] if evidence_id else store.list_evidence_ids()
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    manifests: list[dict[str, Any]] = []
    for item in evidence_ids:
        try:
            manifest = json.loads(store.get(item, "manifest.json").decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            typer.echo(f"cannot read manifest for {item}: {error}", err=True)
            raise typer.Exit(code=1) from error
        if not isinstance(manifest, dict):
            typer.echo(f"manifest for {item} is not an object", err=True)
            raise typer.Exit(code=1)
        manifests.append(manifest)
    _echo_json({"case_id": case_id, "evidence": manifests})


def _not_implemented() -> None:
    """Print the common later-phase command response."""
    typer.echo("not implemented in this phase")


@app.command("parse")
def parse_command() -> None:
    """Reserve nginx parsing for Phase 3."""
    _not_implemented()


@app.command("analyze")
def analyze_command() -> None:
    """Reserve consistency and attack analysis for later phases."""
    _not_implemented()


@app.command("report")
def report_command() -> None:
    """Reserve report generation for a later phase."""
    _not_implemented()


if __name__ == "__main__":
    app()
