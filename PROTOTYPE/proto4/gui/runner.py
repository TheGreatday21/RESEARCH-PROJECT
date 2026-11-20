"""Subprocess runner, command builders, SQL guard, and JSON result formatters
(no tkinter imports)."""

from __future__ import annotations

import json
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

_SELECT_OR_WITH = re.compile(r"^\s*(?:SELECT|WITH)\b", re.IGNORECASE)

FRIENDLY_CONSISTENCY_LABELS: dict[str, str] = {
    "clock_skew": "Clock difference between server and analyst machine",
    "byte_coverage": "Every byte of the raw log files is accounted for in parsed rows",
    "unparsed_ratio": "Share of log lines that could not be parsed (warns above 5%)",
    "line_continuity:access": "Access log line numbers are continuous (1..N) with no gaps",
    "line_continuity:error": "Error log line numbers are continuous (1..N) with no gaps",
    "timestamp_monotonicity:access": (
        "Access log timestamps move forward in time without jumps back"
    ),
    "timestamp_monotonicity:error": "Error log timestamps move forward in time without jumps back",
}


@dataclass(frozen=True)
class RunOutcome:
    """Summarize one completed or cancelled CLI subprocess invocation."""

    step_name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    parsed_json: dict[str, Any] | None
    cancelled: bool = False
    cleanup_path: Path | None = None

    @property
    def last_stderr_line(self) -> str:
        """Return the last non-empty stderr line, or a fallback message."""
        lines = [line.strip() for line in self.stderr.splitlines() if line.strip()]
        if lines:
            return lines[-1]
        if self.parsed_json and isinstance(self.parsed_json.get("error"), str):
            return str(self.parsed_json["error"])
        return f"Command exited with status {self.returncode}"


## creating a function that locates the lapa CLI executable or falls back to python -m cli.app
def resolve_lapa_command(
    project_root: Path | None = None,
    override: list[str] | None = None,
) -> list[str]:
    if override:
        return list(override)
    sibling = Path(sys.executable).with_name("lapa")
    if sibling.is_file():
        return [str(sibling)]
    if project_root is not None:
        venv_lapa = project_root / ".venv" / "bin" / "lapa"
        if venv_lapa.is_file():
            return [str(venv_lapa)]
    found = shutil.which("lapa")
    if found:
        return [found]
    return [sys.executable, "-m", "cli.app"]


## creating a function that shortens .pem paths in logged commands so private key paths stay compact
def format_command_for_log(command: list[str]) -> str:
    formatted: list[str] = []
    shorten_next = False
    for token in command:
        if shorten_next:
            p = Path(token)
            formatted.append(shlex.quote(f".../{p.name}" if len(p.parts) > 2 else token))
            shorten_next = False
            continue
        if token in ("-i", "--private-key"):
            formatted.append(token)
            shorten_next = True
            continue
        if token.endswith(".pem") and "/" in token:
            formatted.append(shlex.quote(f".../{Path(token).name}"))
            continue
        formatted.append(shlex.quote(token))
    return " ".join(formatted)


## creating a function that lists valid UUIDv4 evidence directories under evidence/<case_id>/
def list_case_evidence_ids(working_folder: Path, case_id: str) -> list[str]:
    cleaned_case = case_id.strip()
    if not cleaned_case:
        return []
    case_dir = working_folder / "evidence" / cleaned_case
    if not case_dir.is_dir():
        return []
    found: list[str] = []
    try:
        entries = list(case_dir.iterdir())
    except OSError:
        return []
    for item in entries:
        if not item.is_dir():
            continue
        try:
            parsed = UUID(item.name)
        except ValueError:
            continue
        if parsed.version == 4 and str(parsed) == item.name.lower():
            found.append(item.name)
    return sorted(found)


## creating a function that parses JSON printed to stdout even when a command exits non-zero
def parse_json_stdout(stdout: str) -> dict[str, Any] | None:
    stripped = stdout.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    # Fallback: try the last line that looks like a JSON object
    for line in reversed(stripped.splitlines()):
        candidate = line.strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue
    return None


## creating a function that validates a read-only demo SQL query and wraps it in LIMIT 1001
def validate_and_wrap_sql(query: str, limit: int = 1001) -> str:
    trimmed = query.strip()
    if trimmed.endswith(";"):
        trimmed = trimmed[:-1].strip()
    if not trimmed:
        raise ValueError("SQL query must not be empty.")
    if ";" in trimmed:
        raise ValueError("Only a single SELECT or WITH statement is allowed.")
    if not _SELECT_OR_WITH.match(trimmed):
        raise ValueError("Query must start with SELECT or WITH.")
    return f"SELECT * FROM ({trimmed}) AS _lapa_gui_q LIMIT {limit}"


## creating a function that formats DuckDB cell values and masks binary blobs as <bytes>
def format_cell_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        if "$bytes_base64" in value or "$bytes" in value:
            return "<bytes>"
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


## creating a function that groups Phase 1 Verify checks into Manifest, Custody, Completeness,
## and per-File rows
def group_verify_checks(result_entry: dict[str, Any]) -> list[dict[str, Any]]:
    checks = result_entry.get("checks", [])
    if not isinstance(checks, list):
        return []

    manifest_names = {"manifest_present", "manifest_json", "manifest_schema", "manifest_signature"}
    custody_names = {"custody_present", "custody_json", "custody_chain", "custody_reference"}
    completeness_names = {"acquisition_complete"}

    manifest_checks: list[dict[str, Any]] = []
    custody_checks: list[dict[str, Any]] = []
    completeness_checks: list[dict[str, Any]] = []
    file_groups: dict[str, list[dict[str, Any]]] = {}
    other_checks: list[dict[str, Any]] = []

    for item in checks:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        if name in manifest_names:
            manifest_checks.append(item)
        elif name in custody_names:
            custody_checks.append(item)
        elif name in completeness_names:
            completeness_checks.append(item)
        elif ":" in name and name.split(":", 1)[0] in (
            "artifact_present",
            "artifact_schema",
            "artifact_prefix",
            "artifact_full",
        ):
            _, file_path = name.split(":", 1)
            file_groups.setdefault(file_path, []).append(item)
        else:
            other_checks.append(item)

    rows: list[dict[str, Any]] = []

    if manifest_checks:
        all_ok = all(bool(c.get("passed")) for c in manifest_checks)
        failed_msgs = [
            f"{c.get('name')}: {c.get('message')}" for c in manifest_checks if not c.get("passed")
        ]
        rows.append(
            {
                "group": "Manifest",
                "target": "manifest.json",
                "passed": all_ok,
                "label": (
                    "The signed record exists, is readable, is complete and has a valid signature"
                ),
                "detail": "; ".join(failed_msgs)
                if failed_msgs
                else "All 4 manifest & Ed25519 signature checks passed",
            }
        )

    if custody_checks:
        all_ok = all(bool(c.get("passed")) for c in custody_checks)
        failed_msgs = [
            f"{c.get('name')}: {c.get('message')}" for c in custody_checks if not c.get("passed")
        ]
        rows.append(
            {
                "group": "Custody",
                "target": "custody.jsonl",
                "passed": all_ok,
                "label": (
                    "The acquisition record is present, hash-chained and linked to the manifest"
                ),
                "detail": "; ".join(failed_msgs)
                if failed_msgs
                else "All 4 acquisition record hash-chain & reference checks passed",
            }
        )

    if completeness_checks:
        all_ok = all(bool(c.get("passed")) for c in completeness_checks)
        messages = [str(c.get("message", "")) for c in completeness_checks if c.get("message")]
        rows.append(
            {
                "group": "Completeness",
                "target": "acquisition_complete",
                "passed": all_ok,
                "label": (
                    "Acquisition captured at least one access log with no collection errors"
                ),
                "detail": "; ".join(messages)
                if messages
                else ("Acquisition completeness check passed" if all_ok else "Incomplete"),
            }
        )

    for file_path in sorted(file_groups):
        items = file_groups[file_path]
        all_ok = all(bool(c.get("passed")) for c in items)
        failed_msgs = [f"{c.get('name')}: {c.get('message')}" for c in items if not c.get("passed")]
        rows.append(
            {
                "group": "Files",
                "target": file_path,
                "passed": all_ok,
                "label": (
                    f"{file_path} — present and matches its recorded source-prefix and full hashes"
                ),
                "detail": "; ".join(failed_msgs)
                if failed_msgs
                else "Present; prefix & full SHA-256 hashes verified",
            }
        )

    for item in other_checks:
        rows.append(
            {
                "group": "Other",
                "target": str(item.get("name", "")),
                "passed": bool(item.get("passed")),
                "label": str(item.get("name", "")),
                "detail": str(item.get("message", "")),
            }
        )

    return rows


## creating a function that formats Phase 2 verify-derived checks with plain-English labels
def format_verify_derived_checks(result_entry: dict[str, Any]) -> list[dict[str, Any]]:
    checks = result_entry.get("checks", [])
    if not isinstance(checks, list):
        return []
    labels = {
        "derived_manifest_present": "Derived manifest file exists and is valid JSON",
        "derived_manifest_schema": "Derived manifest contains all required provenance fields",
        "derived_manifest_signature": "Derived manifest Ed25519 signature is valid",
        "derived_evidence_id": "Derived dataset matches the selected Evidence ID",
        "derived_file:access.parquet": (
            "access.parquet SHA-256 hash matches the signed derived manifest"
        ),
        "derived_file:error.parquet": (
            "error.parquet SHA-256 hash matches the signed derived manifest"
        ),
        "derived_file:parse_report.json": (
            "parse_report.json SHA-256 hash matches the signed derived manifest"
        ),
        "evidence_manifest_hash": "Parent evidence manifest SHA-256 link matches stored evidence",
        "derived_content_hash": "Canonical row-by-row content hash matches across all Parquet rows",
        "derived_rows:access.parquet": (
            "access.parquet row count matches the signed derived manifest"
        ),
        "derived_rows:error.parquet": "error.parquet row count matches the signed derived manifest",
    }
    formatted: list[dict[str, Any]] = []
    for item in checks:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        formatted.append(
            {
                "name": name,
                "label": labels.get(name, name),
                "passed": bool(item.get("passed")),
                "message": str(item.get("message", "")),
            }
        )
    return formatted


## creating a function that returns a friendly plain-English name for a Phase 3 consistency check
def friendly_consistency_label(check_name: str) -> str:
    return FRIENDLY_CONSISTENCY_LABELS.get(check_name, check_name)


## creating a function that formats lapa preflight JSON checks into display rows with hints
def format_preflight_checks(data: dict[str, Any]) -> list[dict[str, Any]]:
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return []
    labels = {
        "ssh_connect": "SSH connectivity",
        "non_root_user": "Non-root SSH account",
        "adm_group": "adm group membership",
        "log_directory_readable": "Log directory readable",
        "access_logs_readable": "access.log* readable",
        "error_logs_readable": "error.log* readable",
        "python3_version": "Python 3.8+ present",
        "nginx_present": "nginx binary present",
    }
    rows: list[dict[str, Any]] = []
    for item in checks:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        rows.append(
            {
                "name": name,
                "label": labels.get(name, name),
                "passed": bool(item.get("passed")),
                "message": str(item.get("message", "")),
                "hint": str(item.get("hint", "")),
            }
        )
    return rows


## creating a function that extracts structured summary, per-file, and dual-source cloud display
## data from a manifest
def extract_manifest_display(manifest: dict[str, Any]) -> dict[str, Any]:
    target = manifest.get("target", {}) if isinstance(manifest.get("target"), dict) else {}
    acquirer = manifest.get("acquirer", {}) if isinstance(manifest.get("acquirer"), dict) else {}
    timing = manifest.get("timing", {}) if isinstance(manifest.get("timing"), dict) else {}
    tz = manifest.get("timezone", {}) if isinstance(manifest.get("timezone"), dict) else {}
    sig = manifest.get("signature", {}) if isinstance(manifest.get("signature"), dict) else {}
    footprint = manifest.get("footprint", {}) if isinstance(manifest.get("footprint"), dict) else {}
    artifacts = manifest.get("artifacts", []) if isinstance(manifest.get("artifacts"), list) else []
    ctx = (
        manifest.get("context_artifacts", [])
        if isinstance(manifest.get("context_artifacts"), list)
        else []
    )
    commands = footprint.get("commands", []) if isinstance(footprint.get("commands"), list) else []
    errors = (
        manifest.get("collection_errors", [])
        if isinstance(manifest.get("collection_errors"), list)
        else []
    )
    collector_info = (
        acquirer.get("collector", {}) if isinstance(acquirer.get("collector"), dict) else {}
    )
    if "match" in collector_info:
        collector_status = (
            "✓ Matched local collector.py"
            if collector_info.get("match") is True
            else "✗ Mismatch with local collector.py"
        )
    else:
        collector_status = "Not recorded (legacy manifest)"

    signing_key_id = str(sig.get("key_id", ""))
    footprint_command_count = len(commands)

    summary_rows: list[tuple[str, str]] = [
        ("Case ID / Evidence ID", f"{manifest.get('case_id')}  /  {manifest.get('evidence_id')}"),
        (
            "Target Host & Address",
            f"{target.get('hostname', 'n/a')} ({target.get('address', 'n/a')})",
        ),
        (
            "SSH User & Kernel",
            f"{target.get('ssh_user', 'n/a')}  |  {target.get('kernel', 'n/a')}",
        ),
        (
            "Target Timezone",
            (
                f"{tz.get('iana_name') or tz.get('abbreviation') or 'UTC'} "
                f"({tz.get('utc_offset', '')})"
            ),
        ),
        (
            "Acquisition Window (UTC)",
            f"{timing.get('started_utc', 'n/a')}  →  {timing.get('finished_utc', 'n/a')}",
        ),
        (
            "Estimated Clock Offset",
            (
                f"{timing.get('estimated_offset_seconds', 'n/a')} s (± "
                f"{timing.get('estimated_offset_uncertainty_seconds', 'n/a')} s)"
            ),
        ),
        (
            "Collected Files",
            f"{len(artifacts)} log artifact(s), {len(ctx)} server context record(s)",
        ),
        (
            "Footprint Commands Recorded",
            f"{footprint_command_count} target command(s) / request(s)",
        ),
        ("Collector Self-Hash", collector_status),
        ("Collection Errors", str(len(errors))),
        (
            "Acquirer",
            f"{acquirer.get('tool', 'lapa')} v{acquirer.get('version', '')} "
            f"by {acquirer.get('operator', '')}",
        ),
        ("Signing Key ID", signing_key_id or "n/a"),
    ]

    file_rows: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        file_rows.append(
            {
                "file": str(item.get("stored_as") or item.get("logical_name") or ""),
                "logical_name": str(item.get("logical_name") or ""),
                "size_at_open": item.get("size_at_open"),
                "grew_during_read": bool(item.get("grew_during_read")),
                "changed_during_read": bool(item.get("changed_during_read")),
                "verified": bool(item.get("verified")),
            }
        )

    cloud = target.get("cloud", {}) if isinstance(target.get("cloud"), dict) else {}
    target_cloud = (
        cloud.get("reported_by_target", {})
        if isinstance(cloud.get("reported_by_target"), dict)
        else {
            "provider": cloud.get("provider", ""),
            "instance_id": cloud.get("instance_id", ""),
            "region": cloud.get("region", ""),
            "account_id": cloud.get("account_id", ""),
            "availability_zone": "",
            "source": "manifest",
            "error": "",
        }
    )
    aws_cloud = (
        cloud.get("reported_by_aws_api", {})
        if isinstance(cloud.get("reported_by_aws_api"), dict)
        else {}
    )
    cross_check = (
        cloud.get("cross_check", {})
        if isinstance(cloud.get("cross_check"), dict)
        else {"status": "not_checked", "details": ["No cloud cross-check recorded in manifest."]}
    )
    cross_status = str(cross_check.get("status") or "not_checked")
    cross_details = (
        [str(d) for d in cross_check.get("details", [])]
        if isinstance(cross_check.get("details"), list)
        else []
    )

    aws_ip_candidates = (
        str(aws_cloud.get("public_ip") or ""),
        str(aws_cloud.get("private_ip") or ""),
    )
    aws_ips = ", ".join(ip for ip in aws_ip_candidates if ip)
    cloud_rows: list[tuple[str, str, str]] = [
        (
            "Source",
            str(target_cloud.get("source") or "not reported"),
            str(aws_cloud.get("source") or "not queried"),
        ),
        (
            "Instance ID",
            str(target_cloud.get("instance_id") or "—"),
            str(aws_cloud.get("instance_id") or "—"),
        ),
        (
            "Region",
            str(target_cloud.get("region") or "—"),
            str(aws_cloud.get("region") or "—"),
        ),
        (
            "Availability Zone",
            str(target_cloud.get("availability_zone") or "—"),
            str(aws_cloud.get("availability_zone") or "—"),
        ),
        (
            "Account ID",
            str(target_cloud.get("account_id") or "—"),
            str(aws_cloud.get("account_id") or "—"),
        ),
        (
            "IP / SSH Address",
            str(target.get("address") or "—"),
            aws_ips or "—",
        ),
        (
            "AWS Caller / Status",
            str(target_cloud.get("error") or ("ok" if target_cloud.get("instance_id") else "—")),
            str(
                aws_cloud.get("caller_arn")
                or aws_cloud.get("error")
                or aws_cloud.get("status")
                or "—"
            ),
        ),
    ]

    return {
        "summary_rows": summary_rows,
        "file_rows": file_rows,
        "grew_note": (
            "Note: 'Grew during read' is normal on a live server because nginx keeps "
            "appending new log lines while the file is read."
        ),
        "signing_key_id": signing_key_id,
        "footprint_command_count": footprint_command_count,
        "cloud_comparison": {
            "status": cross_status,
            "details": cross_details,
            "rows": cloud_rows,
        },
    }


## creating a function that classifies lapa acquire output into chip state, banner style, and text
def format_acquire_outcome(outcome: RunOutcome) -> dict[str, Any]:
    data = outcome.parsed_json
    if "signing key not found" in outcome.stderr.lower():
        return {
            "ok": False,
            "missing_key": True,
            "chip_state": "fail",
            "banner_kind": "fail",
            "banner_text": (
                "Signing key (evidence) not found. Click "
                "'Create signing keys' in the top bar first."
            ),
            "evidence_id": None,
        }
    if outcome.cancelled:
        return {
            "ok": False,
            "missing_key": False,
            "chip_state": "cancelled",
            "banner_kind": "fail",
            "banner_text": "Acquisition was cancelled.",
            "evidence_id": None,
        }
    if data and isinstance(data.get("evidence_id"), str):
        eid = str(data["evidence_id"])
        unverified = data.get("unverified_artifacts", [])
        errors = data.get("collection_errors", [])
        unverified_list = [str(x) for x in unverified] if isinstance(unverified, list) else []
        errors_list = [str(x) for x in errors] if isinstance(errors, list) else []
        cross = (
            data.get("cloud_cross_check", {})
            if isinstance(data.get("cloud_cross_check"), dict)
            else {}
        )
        cross_status = str(cross.get("status") or "not_checked")
        cross_details = (
            [str(d) for d in cross.get("details", [])]
            if isinstance(cross.get("details"), list)
            else []
        )

        if outcome.returncode == 2 or not bool(data.get("ok")):
            parts: list[str] = []
            if unverified_list:
                parts.append("Unverified artifacts: " + ", ".join(unverified_list))
            if errors_list:
                parts.append("Collection errors: " + "; ".join(errors_list))
            detail = " | ".join(parts) or outcome.last_stderr_line
            return {
                "ok": False,
                "missing_key": False,
                "chip_state": "warn",
                "banner_kind": "warn",
                "banner_text": (
                    f"▲ Acquisition saved {eid} with warnings (exit {outcome.returncode}): {detail}"
                ),
                "evidence_id": eid,
            }

        if cross_status == "mismatch":
            detail = "; ".join(cross_details) or "Target and AWS API cloud identities disagree."
            return {
                "ok": True,
                "missing_key": False,
                "chip_state": "warn",
                "banner_kind": "warn",
                "banner_text": (
                    f"▲ Acquired and signed {eid}, but cloud identity cross-check reported "
                    f"a mismatch: {detail}"
                ),
                "evidence_id": eid,
            }

        return {
            "ok": True,
            "missing_key": False,
            "chip_state": "pass",
            "banner_kind": "pass",
            "banner_text": f"✓ Acquired and signed evidence package {eid}.",
            "evidence_id": eid,
        }

    return {
        "ok": False,
        "missing_key": False,
        "chip_state": "fail",
        "banner_kind": "fail",
        "banner_text": f"✗ {outcome.last_stderr_line}",
        "evidence_id": None,
    }


class CommandRunner:
    """Run CLI subprocesses in a background daemon thread and stream events to a queue."""

    def __init__(self, event_queue: queue.Queue[tuple[str, Any]]) -> None:
        self.event_queue = event_queue
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._cancelled = False
        self._running = False

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    ## creating a function that starts a subprocess in a background thread and streams stdout/stderr
    def start(
        self,
        step_name: str,
        command: list[str],
        cwd: Path,
        *,
        cleanup_path: Path | None = None,
        on_complete: Callable[[RunOutcome], None] | None = None,
    ) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError("A command is already running.")
            self._running = True
            self._cancelled = False

        worker = threading.Thread(
            target=self._worker,
            args=(step_name, list(command), cwd, cleanup_path, on_complete),
            daemon=True,
        )
        worker.start()

    ## creating a function that terminates the running subprocess and kills it after 3 seconds if
    ## needed
    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            proc = self._process
        if proc is None:
            return
        threading.Thread(target=self._terminate_process, args=(proc,), daemon=True).start()

    @staticmethod
    def _terminate_process(proc: subprocess.Popen[str]) -> None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
        except OSError:
            pass

    def _worker(
        self,
        step_name: str,
        command: list[str],
        cwd: Path,
        cleanup_path: Path | None,
        on_complete: Callable[[RunOutcome], None] | None,
    ) -> None:
        self.event_queue.put(("cmd", f"$ {format_command_for_log(command)}  (cwd: {cwd})"))
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        returncode = -1

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            with self._lock:
                self._process = proc
                if self._cancelled:
                    self._terminate_process(proc)

            def read_stream(stream: Any, kind: str, bucket: list[str]) -> None:
                if stream is None:
                    return
                for line in iter(stream.readline, ""):
                    bucket.append(line)
                    stripped = line.rstrip("\r\n")
                    if stripped:
                        self.event_queue.put((kind, stripped))
                stream.close()

            t_out = threading.Thread(
                target=read_stream, args=(proc.stdout, "stdout", stdout_chunks), daemon=True
            )
            t_err = threading.Thread(
                target=read_stream, args=(proc.stderr, "stderr", stderr_chunks), daemon=True
            )
            t_out.start()
            t_err.start()
            returncode = proc.wait()
            t_out.join()
            t_err.join()
        except Exception as error:
            stderr_chunks.append(f"{error}\n")
            self.event_queue.put(("stderr", str(error)))
            returncode = 1
        finally:
            if cleanup_path is not None:
                cleanup_path.unlink(missing_ok=True)
            with self._lock:
                cancelled = self._cancelled
                self._process = None
                self._running = False

        stdout_text = "".join(stdout_chunks)
        stderr_text = "".join(stderr_chunks)
        parsed = parse_json_stdout(stdout_text)
        outcome = RunOutcome(
            step_name=step_name,
            command=command,
            returncode=returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            parsed_json=parsed,
            cancelled=cancelled,
            cleanup_path=cleanup_path,
        )
        self.event_queue.put(("done", (outcome, on_complete)))
