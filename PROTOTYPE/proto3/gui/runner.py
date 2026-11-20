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


## creating a function that groups Phase 1 Verify checks into Manifest, Custody, and per-File rows
def group_verify_checks(result_entry: dict[str, Any]) -> list[dict[str, Any]]:
    checks = result_entry.get("checks", [])
    if not isinstance(checks, list):
        return []

    manifest_names = {"manifest_present", "manifest_json", "manifest_schema", "manifest_signature"}
    custody_names = {"custody_present", "custody_json", "custody_chain", "custody_reference"}

    manifest_checks: list[dict[str, Any]] = []
    custody_checks: list[dict[str, Any]] = []
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
                    "The log of who handled the evidence is "
                    "present, unbroken and linked to the manifest"
                ),
                "detail": "; ".join(failed_msgs)
                if failed_msgs
                else "All 4 custody hash-chain & reference checks passed",
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
