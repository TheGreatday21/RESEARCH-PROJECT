"""Stream stored nginx logs into lossless, row-level provenance records."""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, BinaryIO, cast
from urllib.parse import unquote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from phase1_acquire.store import EvidenceStore
from phase2_parse.formats import AccessFormat, derive_access_format, fallback_access_format

CHUNK_SIZE = 1024 * 1024
_ERROR_LINE = re.compile(
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>[A-Za-z]+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+"
    r"(?:\*(?P<cid>\d+)\s+)?(?P<message>.*)"
)
_OFFSET = re.compile(r"^(?P<sign>[+-])(?P<hours>\d{2})(?P<minutes>\d{2})$")
_ACCESS_COLUMNS = (
    "ts_original",
    "ts_utc",
    "msec",
    "remote_addr",
    "remote_user",
    "method",
    "uri_raw",
    "path",
    "path_decoded",
    "query_raw",
    "query_decoded",
    "protocol",
    "status",
    "body_bytes_sent",
    "referer",
    "user_agent",
    "request_time",
    "request_id",
    "connection",
    "trace_id",
)
_ERROR_COLUMNS = (
    "ts_original",
    "ts_utc",
    "ts_tz_source",
    "level",
    "pid",
    "tid",
    "cid",
    "message",
    "client",
    "server",
    "request",
    "upstream",
    "host",
)
_ACCESS_VARIABLES = {
    "time_local",
    "msec",
    "remote_addr",
    "remote_user",
    "request",
    "status",
    "body_bytes_sent",
    "http_referer",
    "http_user_agent",
    "request_time",
    "request_id",
    "connection",
    "http_x_lapa_trace",
}
_PROVENANCE_COLUMNS = {
    "case_id",
    "evidence_id",
    "artifact_path",
    "artifact_sha256_full",
    "stream",
    "line_no",
    "byte_offset",
    "byte_length",
    "raw_bytes",
    "raw_line",
    "parse_ok",
    "parse_error",
    "beyond_prefix",
    "crlf",
    "incomplete_final_line",
}
_DETAIL_KEYS = ("client", "server", "request", "upstream", "host")


@dataclass(frozen=True)
class ParsedArtifact:
    """Expose one streaming row iterator and its report, completed after consumption."""

    rows: Iterator[dict[str, Any]]
    report: dict[str, Any]


def _physical_lines(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Split only on LF and retain each line terminator in its returned bytes."""
    pending = bytearray()
    for chunk in chunks:
        parts = chunk.split(b"\n")
        if len(parts) == 1:
            pending.extend(chunk)
            continue
        pending.extend(parts[0])
        yield bytes(pending) + b"\n"
        pending.clear()
        for part in parts[1:-1]:
            yield part + b"\n"
        pending.extend(parts[-1])
    if pending:
        yield bytes(pending)


def _line_body(raw: bytes) -> bytes:
    body = raw[:-1] if raw.endswith(b"\n") else raw
    return body[:-1] if body.endswith(b"\r") else body


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _number(value: str | None, conversion: type[int] | type[float]) -> int | float | None:
    if value is None or value in ("", "-"):
        return None
    try:
        number = conversion(value)
        if isinstance(number, int):
            return number if -(2**63) <= number < 2**63 else None
        return number if math.isfinite(number) else None
    except ValueError:
        return None


def _access_values(values: Mapping[str, str]) -> tuple[dict[str, Any], str | None]:
    row: dict[str, Any] = {column: None for column in _ACCESS_COLUMNS}
    row.update(
        {
            "ts_original": values.get("time_local"),
            "msec": _number(values.get("msec"), float),
            "remote_addr": values.get("remote_addr"),
            "remote_user": (
                None if values.get("remote_user") in (None, "-") else values.get("remote_user")
            ),
            "status": _number(values.get("status"), int),
            "body_bytes_sent": _number(values.get("body_bytes_sent"), int),
            "referer": values.get("http_referer"),
            "user_agent": values.get("http_user_agent"),
            "request_time": _number(values.get("request_time"), float),
            "request_id": values.get("request_id"),
            "connection": values.get("connection"),
            "trace_id": values.get("http_x_lapa_trace"),
        }
    )
    parse_error: str | None = None
    msec = row["msec"]
    if isinstance(msec, float):
        try:
            row["ts_utc"] = _iso_utc(datetime.fromtimestamp(msec, UTC))
        except (ValueError, OverflowError, OSError):
            parse_error = "invalid access epoch timestamp"
    elif row["ts_original"]:
        try:
            parsed = datetime.strptime(str(row["ts_original"]), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            parse_error = "invalid access timestamp"
        else:
            row["ts_utc"] = _iso_utc(parsed)

    request = values.get("request")
    if request is not None:
        parts = request.split(" ")
        if len(parts) == 3 and all(parts):
            method, uri, protocol = parts
        elif (
            len(parts) > 3
            and parts[0].isalpha()
            and parts[-1].startswith("HTTP/")
            and request[len(parts[0]) + 1 : -(len(parts[-1]) + 1)].strip()
        ):
            method = parts[0]
            protocol = parts[-1]
            uri = request[len(method) + 1 : -(len(protocol) + 1)]
        else:
            method = uri = protocol = ""
        if not (method and uri and protocol):
            parse_error = "malformed request line"
        else:
            path, separator, query = uri.partition("?")
            row.update(
                {
                    "method": method,
                    "uri_raw": uri,
                    "path": path,
                    "path_decoded": unquote(path, errors="replace"),
                    "query_raw": query if separator else None,
                    "query_decoded": unquote(query, errors="replace") if separator else None,
                    "protocol": protocol,
                }
            )
    return row, parse_error


def extra_access_columns(access_format: AccessFormat) -> dict[str, str]:
    """Keep unknown variables without letting their names replace provenance or parsed fields."""
    extras = sorted(set(access_format.variables) - _ACCESS_VARIABLES)
    reserved = _PROVENANCE_COLUMNS | set(_ACCESS_COLUMNS)
    used = reserved | set(extras)
    columns = {}
    for variable in extras:
        column = variable
        if column in reserved:
            column = f"nginx_{column}"
            while column in used:
                column = f"nginx_{column}"
            used.add(column)
        columns[variable] = column
    return columns


def _target_timezone(block: Mapping[str, Any]) -> tuple[tzinfo, str]:
    iana_name = block.get("iana_name")
    if isinstance(iana_name, str) and iana_name:
        try:
            return ZoneInfo(iana_name), "context"
        except (ZoneInfoNotFoundError, ValueError):
            pass
    offset = block.get("utc_offset")
    if isinstance(offset, str):
        match = _OFFSET.fullmatch(offset)
        if match:
            seconds = int(match.group("hours")) * 3600 + int(match.group("minutes")) * 60
            if match.group("sign") == "-":
                seconds = -seconds
            if abs(seconds) < 86400 and int(match.group("minutes")) < 60:
                return timezone(timedelta(seconds=seconds)), "context"
    return UTC, "assumed_utc"


def _error_details(message: str) -> tuple[str, dict[str, str | None]]:
    positions = [(message.find(f", {key}: "), key) for key in _DETAIL_KEYS]
    present = [(position, key) for position, key in positions if position >= 0]
    first = min((position for position, _ in present), default=len(message))
    core = message[:first]
    details: dict[str, str | None] = {key: None for key in _DETAIL_KEYS}
    for position, key in present:
        start = position + len(f", {key}: ")
        later = [other for other, _ in present if other >= start]
        end = min(later, default=len(message))
        value = message[start:end]
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        details[key] = value
    return core, details


def _error_values(
    line: str,
    target_tz: tzinfo,
    tz_source: str,
) -> tuple[dict[str, Any], str | None]:
    row: dict[str, Any] = {column: None for column in _ERROR_COLUMNS}
    row["ts_tz_source"] = tz_source
    match = _ERROR_LINE.fullmatch(line)
    if match is None:
        return row, "error line does not match the nginx error format"
    row.update(
        {
            "ts_original": match.group("ts"),
            "level": match.group("level"),
            "pid": _number(match.group("pid"), int),
            "tid": _number(match.group("tid"), int),
            "cid": _number(match.group("cid"), int),
        }
    )
    core, details = _error_details(match.group("message"))
    row["message"] = core
    row.update(details)
    try:
        parsed = datetime.strptime(str(row["ts_original"]), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return row, "invalid error timestamp"
    row["ts_utc"] = _iso_utc(parsed.replace(tzinfo=target_tz))
    return row, None


def nginx_config_text(
    store: EvidenceStore,
    evidence_id: str,
    manifest: Mapping[str, Any],
) -> str | None:
    """Read captured nginx configuration as text, if present."""
    context = manifest.get("context_artifacts", [])
    if not isinstance(context, list):
        return None
    for artifact in context:
        if not isinstance(artifact, dict) or artifact.get("logical_name") != "nginx_config":
            continue
        stored_as = artifact.get("stored_as")
        if isinstance(stored_as, str):
            return store.get(evidence_id, stored_as).decode("utf-8", errors="replace")
    return None


def access_format_for_evidence(
    store: EvidenceStore,
    evidence_id: str,
    manifest: Mapping[str, Any],
) -> AccessFormat:
    """Derive the captured format or explicitly select the documented fallback."""
    config = nginx_config_text(store, evidence_id, manifest)
    if config is not None:
        try:
            return derive_access_format(config)
        except ValueError:
            pass
    return fallback_access_format()


def discover_logs(manifest: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """Discover access and error artifacts in deterministic stored-path order."""
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    discovered: list[tuple[str, Mapping[str, Any]]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        name = Path(str(artifact.get("source_path", artifact.get("stored_as", "")))).name
        for kind in ("access", "error"):
            if name == f"{kind}.log" or name.startswith(f"{kind}.log."):
                discovered.append((kind, artifact))
                break
    return sorted(discovered, key=lambda item: str(item[1].get("stored_as", "")))


def parse_artifact(
    store: EvidenceStore,
    evidence_id: str,
    kind: str,
    artifact: Mapping[str, Any],
    access_format: AccessFormat,
    timezone_block: Mapping[str, Any],
    *,
    case_id: str | None = None,
) -> ParsedArtifact:
    """Parse one complete stored stream and finish with an exact byte-coverage report."""
    stored_as = str(artifact["stored_as"])
    decompressed = stored_as.endswith(".gz")
    stream_name = "decompressed" if decompressed else "stored"
    target_tz, tz_source = _target_timezone(timezone_block)
    extras = extra_access_columns(access_format)
    prefix_size = artifact.get("size_at_open")
    prefix_mappable = isinstance(prefix_size, int) and (
        not decompressed or prefix_size == artifact.get("stored_size")
    )
    report: dict[str, Any] = {
        "artifact_path": stored_as,
        "kind": kind,
        "stream": stream_name,
        "source_prefix_mappable": prefix_mappable,
        "source_prefix_verified_at_acquisition": artifact.get("verified"),
        "total_bytes": 0,
        "total_lines": 0,
        "parsed_lines": 0,
        "unparsed_lines": 0,
        "row_bytes": 0,
        "stream_sha256": "",
        "byte_coverage": False,
        "complete": False,
    }
    if kind == "access":
        report["format_source"] = access_format.source
    else:
        report["ts_tz_source"] = tz_source

    def rows() -> Iterator[dict[str, Any]]:
        digest = hashlib.sha256()
        stream_digest = hashlib.sha256()
        stream_size = 0

        def chunks(stream: BinaryIO) -> Iterator[bytes]:
            nonlocal stream_size
            while chunk := stream.read(CHUNK_SIZE):
                stream_digest.update(chunk)
                stream_size += len(chunk)
                yield chunk

        offset = 0
        line_no = 0
        with (
            store.open_read(evidence_id, stored_as) as source,
            (
                gzip.GzipFile(fileobj=source, mode="rb") if decompressed else nullcontext(source)
            ) as stream,
        ):
            for raw in _physical_lines(chunks(cast(BinaryIO, stream))):
                line_no += 1
                body = _line_body(raw)
                raw_line = body.decode("utf-8", errors="backslashreplace")
                row: dict[str, Any] = {
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "artifact_path": stored_as,
                    "artifact_sha256_full": artifact.get("sha256_full"),
                    "stream": stream_name,
                    "line_no": line_no,
                    "byte_offset": offset,
                    "byte_length": len(raw),
                    "raw_bytes": raw,
                    "raw_line": raw_line,
                    "parse_ok": False,
                    "parse_error": None,
                    "beyond_prefix": (
                        None
                        if not prefix_mappable
                        else not decompressed and offset + len(raw) > int(artifact["size_at_open"])
                    ),
                    "crlf": raw.endswith(b"\r\n"),
                    "incomplete_final_line": not raw.endswith(b"\n"),
                }
                try:
                    text = body.decode("utf-8")
                except UnicodeDecodeError as error:
                    row["parse_error"] = f"invalid UTF-8: {error}"
                else:
                    if kind == "access":
                        values = access_format.parse(text)
                        if values is None:
                            row["parse_error"] = "access line does not match the derived format"
                        else:
                            parsed, parse_error = _access_values(values)
                            row.update(parsed)
                            row.update({column: values[name] for name, column in extras.items()})
                            row["parse_error"] = parse_error
                    else:
                        parsed, parse_error = _error_values(text, target_tz, tz_source)
                        row.update(parsed)
                        row["parse_error"] = parse_error
                row["parse_ok"] = row["parse_error"] is None
                digest.update(raw)
                offset += len(raw)
                report["total_lines"] = line_no
                report["row_bytes"] = offset
                report["parsed_lines"] += int(row["parse_ok"])
                report["unparsed_lines"] += int(not row["parse_ok"])
                yield row
        report["total_bytes"] = stream_size
        report["stream_sha256"] = stream_digest.hexdigest()
        report["byte_coverage"] = (
            offset == stream_size and digest.digest() == stream_digest.digest()
        )
        report["complete"] = True
        if not report["byte_coverage"]:
            raise ValueError(f"byte coverage failed for {stored_as}")

    return ParsedArtifact(rows(), report)


def parse_evidence_logs(
    store: EvidenceStore,
    evidence_id: str,
    manifest: Mapping[str, Any],
) -> list[ParsedArtifact]:
    """Prepare streaming parsers for every discovered access and error artifact."""
    access_format = access_format_for_evidence(store, evidence_id, manifest)
    timezone_block = manifest.get("timezone", {})
    if not isinstance(timezone_block, dict):
        timezone_block = {}
    return [
        parse_artifact(
            store,
            evidence_id,
            kind,
            artifact,
            access_format,
            timezone_block,
            case_id=manifest.get("case_id"),
        )
        for kind, artifact in discover_logs(manifest)
    ]


def parse_report(artifacts: list[ParsedArtifact]) -> dict[str, Any]:
    """Summarize consumed artifact streams and fail if any stream was not exhausted."""
    if any(not artifact.report["complete"] for artifact in artifacts):
        raise ValueError("all artifact rows must be consumed before writing the parse report")
    reports = [artifact.report for artifact in artifacts]
    return {
        "artifacts": reports,
        "total_bytes": sum(report["total_bytes"] for report in reports),
        "total_lines": sum(report["total_lines"] for report in reports),
        "parsed_lines": sum(report["parsed_lines"] for report in reports),
        "unparsed_lines": sum(report["unparsed_lines"] for report in reports),
        "byte_coverage": all(report["byte_coverage"] for report in reports),
        "assumed_utc_artifacts": [
            report["artifact_path"]
            for report in reports
            if report.get("ts_tz_source") == "assumed_utc"
        ],
    }


def load_manifest(store: EvidenceStore, evidence_id: str) -> dict[str, Any]:
    """Load one stored evidence manifest for parser orchestration."""
    value = json.loads(store.get(evidence_id, "manifest.json").decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evidence manifest must be a JSON object")
    return value
