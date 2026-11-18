"""Typer command-line interface for Project Elijah acquisition, verification, and analysis."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import duckdb
import typer

from elijah.acquire.orchestrator import AcquisitionError, acquire_evidence
from elijah.analysis.consistency import run_consistency_checks
from elijah.analysis.dataset import (
    DerivedError,
    create_derived_dataset,
    verify_derived_dataset,
)
from elijah.analysis.detectors import DetectorConfig, run_detectors
from elijah.analysis.evaluate import LabelError, evaluate_detections, load_labels
from elijah.analysis.features import extract_request_features, summarize_clients
from elijah.analysis.isolation_forest import run_isolation_forest
from elijah.analysis.pipeline import (
    AnalysisError,
    load_inputs,
    require_verified_derived,
    require_verified_evidence,
)
from elijah.analysis.report import build_report, render_markdown
from elijah.analysis.sql import run_query
from elijah.analysis.timeline import build_timeline
from elijah.canonical import canonical_json_bytes
from elijah.config import Settings, validate_case_id
from elijah.prov.signing import generate_keypair
from elijah.prov.verify import verify_evidence
from elijah.store.local import LocalStore

app = typer.Typer(
    name="elijah",
    help="Acquire, verify, parse, and query nginx evidence with signed provenance.",
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


def _validate_evidence_id(evidence_id: str) -> str:
    """Require a canonical UUIDv4 before using an ID in a derived-data path."""
    try:
        parsed = UUID(evidence_id)
    except ValueError as error:
        raise ValueError(f"invalid evidence ID: {evidence_id!r}") from error
    if parsed.version != 4 or str(parsed) != evidence_id.lower():
        raise ValueError(f"evidence ID must be a canonical UUIDv4: {evidence_id!r}")
    return evidence_id.lower()


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
        raise typer.BadParameter("Use only --store local")
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
        evidence_ids = (
            [_validate_evidence_id(evidence_id)] if evidence_id else store.list_evidence_ids()
        )
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
        evidence_ids = (
            [_validate_evidence_id(evidence_id)] if evidence_id else store.list_evidence_ids()
        )
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


@app.command("parse")
def parse_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    out: Annotated[Path, typer.Option("--out", file_okay=False)] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    private_key: Annotated[Path | None, typer.Option("--private-key")] = None,
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
    allow_unverified: Annotated[bool, typer.Option("--allow-unverified")] = False,
) -> None:
    """Verify stored evidence, then create signed streaming Parquet derivatives."""
    private_path, public_path = _key_paths(private_key, public_key)
    try:
        store = LocalStore(evidence_root, case_id)
        evidence_ids = (
            [_validate_evidence_id(evidence_id)] if evidence_id else store.list_evidence_ids()
        )
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    if not evidence_ids:
        _echo_json({"case_id": case_id, "ok": False, "error": "no evidence found", "results": []})
        raise typer.Exit(code=1)
    if not private_path.is_file():
        typer.echo(f"signing key not found: {private_path}; run elijah keygen first", err=True)
        raise typer.Exit(code=2)

    results: list[dict[str, Any]] = []
    for item in evidence_ids:
        try:
            result = create_derived_dataset(
                store,
                case_id,
                str(item),
                out,
                private_path,
                public_path,
                allow_unverified=allow_unverified,
            )
        except (DerivedError, OSError, ValueError, EOFError) as error:
            typer.echo(f"parse failed for {item}: {error}", err=True)
            raise typer.Exit(code=1) from error
        if result.warning is not None:
            typer.echo(f"warning: {result.warning}", err=True)
        results.append(
            {
                "derived_id": result.derived_id,
                "evidence_id": str(item),
                "evidence_verified": result.evidence_verified,
                "output_directory": str(result.output_directory),
                "content_hash": result.manifest["content_hash"],
            }
        )
    _echo_json({"case_id": case_id, "ok": True, "results": results})


@app.command("verify-derived")
def verify_derived_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
) -> None:
    """Verify derived signatures, file hashes, row content, and evidence linkage."""
    _, public_path = _key_paths(None, public_key)
    try:
        store = LocalStore(evidence_root, case_id)
        derived_store = LocalStore(derived_root, case_id)
        evidence_ids = (
            [_validate_evidence_id(evidence_id)]
            if evidence_id
            else derived_store.list_evidence_ids()
        )
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if not evidence_ids:
        _echo_json({"case_id": case_id, "ok": False, "error": "no derived data", "results": []})
        raise typer.Exit(code=1)
    results = [
        verify_derived_dataset(store, str(item), derived_root / case_id / str(item), public_path)
        for item in evidence_ids
    ]
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


@app.command("sql")
def sql_command(
    case_id: str,
    evidence_id: str,
    query: str,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
) -> None:
    """Execute a DuckDB query with access and error views for one derivation."""
    try:
        validate_case_id(case_id)
        validated_id = _validate_evidence_id(evidence_id)
        result = run_query(derived_root / case_id / validated_id, query)
    except (OSError, ValueError, duckdb.Error) as error:
        typer.echo(f"SQL query failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    _echo_json(result.to_dict())


@app.command("analyze")
def analyze_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    analysis_root: Annotated[Path, typer.Option("--analysis-root")] = Path("analysis"),
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
    gap_threshold: Annotated[float, typer.Option("--gap-threshold")] = 60.0,
) -> None:
    """Run consistency checks and timeline reconstruction on derived evidence.

    Verifies derived signatures before reading Parquet data.  Writes
    consistency_report.json and timeline_report.json under
    analysis/<case_id>/<evidence_id>/.  Exits 1 if any consistency check failed.
    """
    _, public_path = _key_paths(None, public_key)
    try:
        validate_case_id(case_id)
        evidence_store = LocalStore(evidence_root, case_id)
        derived_store = LocalStore(derived_root, case_id)
        evidence_ids = (
            [_validate_evidence_id(evidence_id)]
            if evidence_id
            else derived_store.list_evidence_ids()
        )
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    if not evidence_ids:
        _echo_json({
            "case_id": case_id,
            "ok": False,
            "error": "no derived data found",
            "results": [],
        })
        raise typer.Exit(code=1)

    overall_ok = True
    results: list[dict[str, Any]] = []

    for item in evidence_ids:
        derived_dir = derived_root / case_id / item
        analysis_dir = analysis_root / case_id / item

        # --- verify derived dataset before reading ---
        derived_result = verify_derived_dataset(
            evidence_store, item, derived_dir, public_path
        )
        if not derived_result.ok:
            typer.echo(
                f"derived verification failed for {item}: "
                f"{', '.join(derived_result.failed_checks)}",
                err=True,
            )
            raise typer.Exit(code=1)

        # --- load manifest and parse_report ---
        try:
            manifest_bytes = evidence_store.get(item, "manifest.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("evidence manifest must be a JSON object")
            parse_report_bytes = (derived_dir / "parse_report.json").read_bytes()
            parse_report = json.loads(parse_report_bytes.decode("utf-8"))
            if not isinstance(parse_report, dict):
                raise ValueError("parse_report.json must be a JSON object")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            typer.echo(f"cannot load data for {item}: {error}", err=True)
            raise typer.Exit(code=1) from error

        timing_block: dict[str, Any] = {}
        timing_raw = manifest.get("timing")
        if isinstance(timing_raw, dict):
            timing_block = timing_raw

        # --- run consistency checks ---
        consistency = run_consistency_checks(
            evidence_id=item,
            timing_block=timing_block,
            parse_report=parse_report,
            derived_directory=derived_dir,
        )

        # --- build timeline ---
        try:
            timeline = build_timeline(derived_dir, gap_threshold_seconds=gap_threshold)
        except (FileNotFoundError, ValueError, duckdb.Error) as error:
            typer.echo(f"timeline reconstruction failed for {item}: {error}", err=True)
            raise typer.Exit(code=1) from error

        # --- write output ---
        analysis_dir.mkdir(parents=True, exist_ok=True)
        created_utc = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")

        consistency_report: dict[str, Any] = {
            "schema_version": 1,
            "case_id": case_id,
            "evidence_id": item,
            "created_utc": created_utc,
            **consistency.to_dict(),
        }
        consistency_path = analysis_dir / "consistency_report.json"
        consistency_path.write_bytes(canonical_json_bytes(consistency_report))

        timeline_report: dict[str, Any] = {
            "schema_version": 1,
            "case_id": case_id,
            "evidence_id": item,
            "created_utc": created_utc,
            "gap_threshold_seconds": gap_threshold,
            "total_events": timeline.to_dict()["total_events"],
            "unparsed_count": timeline.unparsed_count,
            "gaps": timeline.to_dict()["gaps"],
        }
        timeline_path = analysis_dir / "timeline_report.json"
        timeline_path.write_bytes(canonical_json_bytes(timeline_report))

        item_ok = consistency.ok
        overall_ok = overall_ok and item_ok
        results.append({
            "evidence_id": item,
            "ok": item_ok,
            "has_failures": consistency.has_failures,
            "consistency_report": str(consistency_path),
            "timeline_report": str(timeline_path),
            "total_events": timeline.to_dict()["total_events"],
            "unparsed_count": timeline.unparsed_count,
            "gaps": len(timeline.gaps),
            "checks": [c.to_dict() for c in consistency.checks],
        })

    _echo_json({"case_id": case_id, "ok": overall_ok, "results": results})
    if not overall_ok:
        raise typer.Exit(code=1)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _derived_ids(
    case_id: str,
    evidence_id: str | None,
    derived_root: Path,
    evidence_root: Path,
) -> tuple[LocalStore, list[str]]:
    """Resolve the evidence store and the derived datasets an analysis command will read."""
    try:
        validate_case_id(case_id)
        store = LocalStore(evidence_root, case_id)
        ids = (
            [_validate_evidence_id(evidence_id)]
            if evidence_id
            else LocalStore(derived_root, case_id).list_evidence_ids()
        )
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if not ids:
        _echo_json({"case_id": case_id, "ok": False, "error": "no derived data found"})
        raise typer.Exit(code=1)
    return store, [str(item) for item in ids]


def _fail(message: str, error: Exception) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(code=1)


@app.command("detect")
def detect_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    analysis_root: Annotated[Path, typer.Option("--analysis-root")] = Path("analysis"),
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
) -> None:
    """Run the rule-based attack detectors on verified derived access data.

    Writes analysis/<case>/<evidence>/detections.json with every detection and the
    row reference needed to find its original bytes.
    """
    _, public_path = _key_paths(None, public_key)
    store, ids = _derived_ids(case_id, evidence_id, derived_root, evidence_root)
    config = DetectorConfig()
    results: list[dict[str, Any]] = []
    for item in ids:
        derived_dir = derived_root / case_id / item
        try:
            require_verified_derived(store, item, derived_dir, public_path)
            features = extract_request_features(derived_dir)
        except (AnalysisError, OSError, ValueError, duckdb.Error) as error:
            raise _fail(f"detection failed for {item}: {error}", error) from error
        detections = run_detectors(features, config)
        iforest = run_isolation_forest(features)
        document = {
            "schema_version": 1,
            "case_id": case_id,
            "evidence_id": item,
            "created_utc": _utc_now(),
            "detector_config": config.to_dict(),
            "scored_requests": len(features),
            "clients": [client.to_dict() for client in summarize_clients(features)],
            "total_detections": len(detections),
            "detections": [detection.to_dict() for detection in detections],
            "isolation_forest": iforest.to_dict(),
        }
        output = analysis_root / case_id / item / "detections.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json_bytes(document))
        by_class: dict[str, int] = {}
        for detection in detections:
            by_class[detection.attack_class] = by_class.get(detection.attack_class, 0) + 1
        results.append(
            {
                "evidence_id": item,
                "scored_requests": len(features),
                "total_detections": len(detections),
                "by_class": dict(sorted(by_class.items())),
                "isolation_forest_anomalies": iforest.anomaly_count,
                "isolation_forest_max_score": round(iforest.score_max, 4),
                "detections_file": str(output),
            }
        )
    _echo_json({"case_id": case_id, "ok": True, "results": results})


@app.command("evaluate")
def evaluate_command(
    case_id: str,
    labels: Annotated[Path, typer.Option("--labels", exists=True, dir_okay=False)],
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    bench_root: Annotated[Path, typer.Option("--bench-root")] = Path("bench"),
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
) -> None:
    """Score detector output against synthetic lab ground-truth labels.

    Writes bench/<case>/<evidence>/evaluation.json. Labels are lab ground truth, not
    signed evidence; results describe detector behaviour on synthetic traffic only.
    """
    _, public_path = _key_paths(None, public_key)
    store, ids = _derived_ids(case_id, evidence_id, derived_root, evidence_root)
    try:
        label_map = load_labels(labels)
    except (OSError, LabelError) as error:
        raise _fail(f"cannot load labels: {error}", error) from error
    results: list[dict[str, Any]] = []
    for item in ids:
        derived_dir = derived_root / case_id / item
        try:
            require_verified_derived(store, item, derived_dir, public_path)
            features = extract_request_features(derived_dir)
        except (AnalysisError, OSError, ValueError, duckdb.Error) as error:
            raise _fail(f"evaluation failed for {item}: {error}", error) from error
        report = evaluate_detections(features, run_detectors(features), label_map).report
        document = {
            "schema_version": 1,
            "case_id": case_id,
            "evidence_id": item,
            "created_utc": _utc_now(),
            "labels_file": str(labels),
            **report,
        }
        output = bench_root / case_id / item / "evaluation.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json_bytes(document))
        results.append({"evidence_id": item, "evaluation_file": str(output), **report})
    _echo_json({"case_id": case_id, "ok": True, "results": results})


@app.command("report")
def report_command(
    case_id: str,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
    derived_root: Annotated[Path, typer.Option("--derived-root")] = Path("derived"),
    evidence_root: Annotated[Path, typer.Option("--evidence-root")] = Path("evidence"),
    reports_root: Annotated[Path, typer.Option("--reports-root")] = Path("reports"),
    labels: Annotated[Path | None, typer.Option("--labels", exists=True, dir_okay=False)] = None,
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
    gap_threshold: Annotated[float, typer.Option("--gap-threshold")] = 60.0,
) -> None:
    """Generate a Markdown and JSON forensic report from freshly verified evidence.

    Re-verifies the evidence package and derived dataset, then re-runs consistency
    checks, timeline, and detectors rather than trusting earlier output files.
    Writes reports/<case>/<evidence>/report.md and report.json.
    """
    _, public_path = _key_paths(None, public_key)
    store, ids = _derived_ids(case_id, evidence_id, derived_root, evidence_root)
    try:
        label_map = load_labels(labels) if labels is not None else None
    except (OSError, LabelError) as error:
        raise _fail(f"cannot load labels: {error}", error) from error
    config = DetectorConfig()
    results: list[dict[str, Any]] = []
    for item in ids:
        derived_dir = derived_root / case_id / item
        try:
            require_verified_evidence(store, item, public_path)
            require_verified_derived(store, item, derived_dir, public_path)
            manifest, parse_report = load_inputs(store, item, derived_dir)
            timing = manifest.get("timing")
            consistency = run_consistency_checks(
                evidence_id=item,
                timing_block=timing if isinstance(timing, dict) else {},
                parse_report=parse_report,
                derived_directory=derived_dir,
            )
            timeline = build_timeline(derived_dir, gap_threshold_seconds=gap_threshold)
            features = extract_request_features(derived_dir)
        except (AnalysisError, OSError, ValueError, duckdb.Error) as error:
            raise _fail(f"report failed for {item}: {error}", error) from error
        detections = run_detectors(features, config)
        iforest = run_isolation_forest(features)
        evaluation = (
            evaluate_detections(features, detections, label_map).report
            if label_map is not None
            else None
        )
        document = build_report(
            case_id=case_id,
            evidence_id=item,
            generated_utc=_utc_now(),
            manifest=manifest,
            parse_report=parse_report,
            consistency=consistency,
            timeline=timeline,
            clients=summarize_clients(features),
            detections=detections,
            detector_config=config,
            evaluation=evaluation,
            isolation_forest=iforest.to_dict(max_anomalies=10),
        )
        directory = reports_root / case_id / item
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "report.json").write_bytes(canonical_json_bytes(document))
        (directory / "report.md").write_text(render_markdown(document), encoding="utf-8")
        results.append(
            {
                "evidence_id": item,
                "report_markdown": str(directory / "report.md"),
                "report_json": str(directory / "report.json"),
                "total_detections": document["total_detections"],
                "isolation_forest_anomalies": iforest.anomaly_count,
                "consistency_ok": consistency.ok,
            }
        )
    _echo_json({"case_id": case_id, "ok": True, "results": results})


if __name__ == "__main__":
    app()
