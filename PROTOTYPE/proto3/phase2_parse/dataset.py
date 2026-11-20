"""Create and verify signed, streaming Parquet derivatives of stored evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pyarrow as pa
import pyarrow.parquet as pq
from cryptography.exceptions import InvalidSignature

from common import __version__
from common.canonical import canonical_json_bytes, hash_file, sha256_bytes
from common.config import validate_case_id
from phase1_acquire.signing import sign_manifest, verify_manifest_signature
from phase1_acquire.store import EvidenceStore, LocalStore
from phase1_acquire.verify import CheckResult, VerificationResult, verify_evidence
from phase2_parse.parse_nginx import (
    ParsedArtifact,
    access_format_for_evidence,
    extra_access_columns,
    parse_evidence_logs,
    parse_report,
)

DEFAULT_ROW_GROUP_SIZE = 1000
_PROVENANCE_SCHEMA = (
    pa.field("case_id", pa.string()),
    pa.field("evidence_id", pa.string()),
    pa.field("artifact_path", pa.string()),
    pa.field("artifact_sha256_full", pa.string()),
    pa.field("stream", pa.string()),
    pa.field("line_no", pa.int64()),
    pa.field("byte_offset", pa.int64()),
    pa.field("byte_length", pa.int64()),
    pa.field("raw_bytes", pa.binary()),
    pa.field("raw_line", pa.string()),
    pa.field("parse_ok", pa.bool_()),
    pa.field("parse_error", pa.string()),
    pa.field("beyond_prefix", pa.bool_()),
    pa.field("crlf", pa.bool_()),
    pa.field("incomplete_final_line", pa.bool_()),
)
_ACCESS_TYPES = {
    "ts_original": pa.string(),
    "ts_utc": pa.string(),
    "msec": pa.float64(),
    "remote_addr": pa.string(),
    "remote_user": pa.string(),
    "method": pa.string(),
    "uri_raw": pa.string(),
    "path": pa.string(),
    "path_decoded": pa.string(),
    "query_raw": pa.string(),
    "query_decoded": pa.string(),
    "protocol": pa.string(),
    "status": pa.int64(),
    "body_bytes_sent": pa.int64(),
    "referer": pa.string(),
    "user_agent": pa.string(),
    "request_time": pa.float64(),
    "request_id": pa.string(),
    "connection": pa.string(),
    "trace_id": pa.string(),
}
_ERROR_TYPES = {
    "ts_original": pa.string(),
    "ts_utc": pa.string(),
    "ts_tz_source": pa.string(),
    "level": pa.string(),
    "pid": pa.int64(),
    "tid": pa.int64(),
    "cid": pa.int64(),
    "message": pa.string(),
    "client": pa.string(),
    "server": pa.string(),
    "request": pa.string(),
    "upstream": pa.string(),
    "host": pa.string(),
}


class DerivedError(RuntimeError):
    """Report a derived-dataset creation or verification failure."""


@dataclass(frozen=True)
class DerivedResult:
    """Describe one newly created derived dataset."""

    derived_id: str
    output_directory: Path
    evidence_verified: bool
    warning: str | None
    manifest: Mapping[str, Any]


class ContentHasher:
    """Hash canonical rows in table/artifact/offset order without accumulating them."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._last_keys: dict[str, tuple[str, int, int]] = {}

    def update(self, table: str, row: Mapping[str, Any]) -> None:
        key = (str(row["artifact_path"]), int(row["byte_offset"]), int(row["line_no"]))
        previous = self._last_keys.get(table)
        if previous is not None and key < previous:
            raise DerivedError(f"rows are not canonically ordered in {table}")
        self._last_keys[table] = key
        normalized = {
            field: {"$bytes": base64.b64encode(value).decode("ascii")}
            if isinstance(value, bytes)
            else value
            for field, value in row.items()
        }
        self._digest.update(canonical_json_bytes({"table": table, "row": normalized}))
        self._digest.update(b"\n")

    @property
    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _schema(kind: str, extra_access_columns: Sequence[str]) -> pa.Schema:
    fields = list(_PROVENANCE_SCHEMA)
    types = _ACCESS_TYPES if kind == "access" else _ERROR_TYPES
    fields.extend(pa.field(name, field_type) for name, field_type in types.items())
    if kind == "access":
        fields.extend(pa.field(name, pa.string()) for name in extra_access_columns)
    return pa.schema(fields)


def _write_parquet(
    path: Path,
    kind: str,
    artifacts: Sequence[ParsedArtifact],
    schema: pa.Schema,
    row_group_size: int,
    content_hasher: ContentHasher,
) -> int:
    writer = pq.ParquetWriter(path, schema)
    count = 0
    batch: list[dict[str, Any]] = []

    def flush() -> None:
        if not batch:
            return
        table = pa.Table.from_pylist(batch, schema=schema)
        writer.write_table(table, row_group_size=row_group_size)
        batch.clear()

    try:
        for artifact in artifacts:
            for row in artifact.rows:
                materialized = {name: row.get(name) for name in schema.names}
                content_hasher.update(kind, materialized)
                batch.append(materialized)
                count += 1
                if len(batch) >= row_group_size:
                    flush()
            flush()
    finally:
        writer.close()
    return count


def _created_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def create_derived_dataset(
    store: EvidenceStore,
    case_id: str,
    evidence_id: str,
    out_root: Path,
    private_key_path: Path,
    public_key_path: Path,
    *,
    allow_unverified: bool = False,
    row_group_size: int = DEFAULT_ROW_GROUP_SIZE,
) -> DerivedResult:
    """Verify evidence first, then create a new signed derived dataset."""
    validate_case_id(case_id)
    if row_group_size <= 0:
        raise ValueError("row_group_size must be positive")
    output_directory = out_root / case_id / evidence_id
    if isinstance(store, LocalStore) and (
        output_directory.resolve().is_relative_to(store.root.resolve())
        or output_directory.parent.resolve().is_relative_to(store.root.resolve())
    ):
        raise DerivedError("derived output must be outside the evidence store")
    verification = verify_evidence(store, evidence_id, public_key_path)
    warning = _verification_warning(verification, allow_unverified, "evidence")

    manifest_bytes = store.get(evidence_id, "manifest.json")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise DerivedError("evidence manifest must be a JSON object")
    if manifest.get("case_id") != case_id or manifest.get("evidence_id") != evidence_id:
        raise DerivedError("evidence manifest identifiers differ from the requested acquisition")
    if output_directory.exists():
        raise FileExistsError(f"derived output already exists: {output_directory}")

    with tempfile.TemporaryDirectory(prefix="lapa-working-") as working_root:
        working = LocalStore(Path(working_root), case_id)
        working.put(evidence_id, "manifest.json", manifest_bytes)
        paths = {"custody.jsonl"}
        for field in ("artifacts", "context_artifacts"):
            artifacts = manifest.get(field)
            if isinstance(artifacts, list):
                paths.update(
                    item["stored_as"]
                    for item in artifacts
                    if isinstance(item, dict) and isinstance(item.get("stored_as"), str)
                )
        for path in sorted(paths - {"manifest.json"}):
            try:
                source = store.open_read(evidence_id, path)
            except FileNotFoundError:
                continue  # The working-copy verifier reports the missing path.
            with source:
                working.put(evidence_id, path, source)
        copy_verification = verify_evidence(working, evidence_id, public_key_path)
        copy_warning = _verification_warning(copy_verification, allow_unverified, "working copy")
        warnings = [message for message in (warning, copy_warning) if message is not None]

        output_directory.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".lapa-parse-", dir=output_directory.parent
        ) as temporary:
            staged = Path(temporary) / "dataset"
            staged.mkdir()
            signed = _write_dataset(
                working,
                manifest,
                manifest_bytes,
                staged,
                private_key_path,
                row_group_size,
                "; ".join(warnings) or None,
            )
            staged.rename(output_directory)
    return DerivedResult(
        derived_id=str(signed["derived_id"]),
        output_directory=output_directory,
        evidence_verified=not warnings,
        warning="; ".join(warnings) or None,
        manifest=signed,
    )


def _verification_warning(
    result: VerificationResult, allow_unverified: bool, label: str
) -> str | None:
    if result.ok:
        return None
    failures = ", ".join(
        f"{check.name} ({check.message})" for check in result.checks if not check.passed
    )
    if not allow_unverified:
        raise DerivedError(f"{label} verification failed: {failures}")
    return f"{label} verification failed; continuing as requested: {failures}"


def _write_dataset(
    store: EvidenceStore,
    evidence_manifest: dict[str, Any],
    evidence_manifest_bytes: bytes,
    output_directory: Path,
    private_key_path: Path,
    row_group_size: int,
    warning: str | None,
) -> dict[str, Any]:
    case_id = evidence_manifest["case_id"]
    evidence_id = evidence_manifest["evidence_id"]
    access_format = access_format_for_evidence(store, evidence_id, evidence_manifest)
    parsed = parse_evidence_logs(store, evidence_id, evidence_manifest)
    extras = sorted(extra_access_columns(access_format).values())
    content_hasher = ContentHasher()
    access = [artifact for artifact in parsed if artifact.report["kind"] == "access"]
    error = [artifact for artifact in parsed if artifact.report["kind"] == "error"]
    access_rows = _write_parquet(
        output_directory / "access.parquet",
        "access",
        access,
        _schema("access", extras),
        row_group_size,
        content_hasher,
    )
    error_rows = _write_parquet(
        output_directory / "error.parquet",
        "error",
        error,
        _schema("error", ()),
        row_group_size,
        content_hasher,
    )
    report = parse_report(parsed)
    report["evidence_verified"] = warning is None
    if warning is not None:
        report["warning"] = warning
    report_bytes = canonical_json_bytes(report)
    with (output_directory / "parse_report.json").open("xb") as stream:
        stream.write(report_bytes)

    files = {
        "access.parquet": {
            "sha256": hash_file(str(output_directory / "access.parquet")).sha256,
            "rows": access_rows,
        },
        "error.parquet": {
            "sha256": hash_file(str(output_directory / "error.parquet")).sha256,
            "rows": error_rows,
        },
        "parse_report.json": {
            "sha256": sha256_bytes(report_bytes),
            "rows": None,
        },
    }

    unsigned = {
        "schema_version": 1,
        "derived_id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_manifest_sha256": sha256_bytes(evidence_manifest_bytes),
        "parser": {
            "name": "lapa",
            "version": __version__,
            "parameters": {
                "row_group_size": row_group_size,
                "access_format_sources": sorted(
                    {artifact.report.get("format_source", "") for artifact in access}
                ),
                "content_row_order": "table,artifact_path,byte_offset,line_no",
            },
        },
        "evidence_verified": warning is None,
        "created_utc": _created_utc(),
        "files": files,
        "content_hash": content_hasher.hexdigest,
    }
    signed = sign_manifest(unsigned, private_key_path)
    with (output_directory / "derived_manifest.json").open("xb") as stream:
        stream.write(canonical_json_bytes(signed))
    return signed


def _hashed_parquet_rows(path: Path, table: str, hasher: ContentHasher) -> int:
    count = 0
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches():
        for row in batch.to_pylist():
            hasher.update(table, row)
            count += 1
    return count


def _file_field(files: Any, name: str, field: str) -> Any:
    """Read one optional file-metadata field without trusting manifest value types."""
    if not isinstance(files, dict):
        return None
    metadata = files.get(name)
    return metadata.get(field) if isinstance(metadata, dict) else None


def verify_derived_dataset(
    store: EvidenceStore,
    evidence_id: str,
    derived_directory: Path,
    public_key_path: Path,
) -> VerificationResult:
    """Check derived signatures, file bytes, content rows, and evidence linkage."""
    checks: list[CheckResult] = []
    manifest_path = derived_directory / "derived_manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("derived manifest is not an object")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return VerificationResult(
            evidence_id,
            (CheckResult("derived_manifest_present", False, str(error)),),
        )
    checks.append(CheckResult("derived_manifest_present", True, "derived manifest is valid JSON"))
    required = {
        "schema_version",
        "derived_id",
        "case_id",
        "evidence_id",
        "evidence_manifest_sha256",
        "parser",
        "evidence_verified",
        "created_utc",
        "files",
        "content_hash",
        "signature",
    }
    missing = sorted(required - set(manifest))
    checks.append(
        CheckResult(
            "derived_manifest_schema",
            not missing,
            "required fields are present" if not missing else f"missing fields: {missing}",
        )
    )
    try:
        verify_manifest_signature(manifest, public_key_path)
    except (InvalidSignature, ValueError, OSError) as error:
        checks.append(CheckResult("derived_manifest_signature", False, str(error)))
    else:
        checks.append(CheckResult("derived_manifest_signature", True, "Ed25519 signature is valid"))

    evidence_id_matches = manifest.get("evidence_id") == evidence_id
    checks.append(
        CheckResult(
            "derived_evidence_id",
            evidence_id_matches,
            (
                "derived evidence ID matches"
                if evidence_id_matches
                else "derived evidence ID differs from the requested evidence"
            ),
        )
    )

    files = manifest.get("files", {})
    for name in ("access.parquet", "error.parquet", "parse_report.json"):
        path = derived_directory / name
        try:
            actual = hash_file(str(path)).sha256
        except OSError as error:
            checks.append(CheckResult(f"derived_file:{name}", False, str(error)))
            continue
        expected = _file_field(files, name, "sha256")
        passed = actual == expected
        checks.append(
            CheckResult(
                f"derived_file:{name}",
                passed,
                "file hash matches" if passed else "derived file hash differs",
            )
        )

    try:
        evidence_hash = sha256_bytes(store.get(evidence_id, "manifest.json"))
    except (OSError, KeyError, ValueError) as error:
        checks.append(CheckResult("evidence_manifest_hash", False, str(error)))
    else:
        passed = evidence_hash == manifest.get("evidence_manifest_sha256")
        checks.append(
            CheckResult(
                "evidence_manifest_hash",
                passed,
                "evidence manifest hash matches" if passed else "evidence manifest link differs",
            )
        )

    hasher = ContentHasher()
    try:
        access_rows = _hashed_parquet_rows(derived_directory / "access.parquet", "access", hasher)
        error_rows = _hashed_parquet_rows(derived_directory / "error.parquet", "error", hasher)
    except (OSError, ValueError, DerivedError, pa.ArrowInvalid) as error:
        checks.append(CheckResult("derived_content_hash", False, str(error)))
    else:
        passed = hasher.hexdigest == manifest.get("content_hash")
        checks.append(
            CheckResult(
                "derived_content_hash",
                passed,
                "canonical row hash matches" if passed else "canonical row hash differs",
            )
        )
        for name, row_count in (("access.parquet", access_rows), ("error.parquet", error_rows)):
            expected = _file_field(files, name, "rows")
            row_check = row_count == expected
            checks.append(
                CheckResult(
                    f"derived_rows:{name}",
                    row_check,
                    "row count matches" if row_check else "row count differs",
                )
            )
    return VerificationResult(evidence_id, tuple(checks))
