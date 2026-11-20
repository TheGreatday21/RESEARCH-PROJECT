"""Lossless streaming parser tests, including hostile physical-line edge cases."""

import gzip
import hashlib
from collections.abc import Mapping
from typing import Any, BinaryIO

from common.canonical import sha256_bytes
from phase1_acquire.store import EvidenceStore
from phase2_parse.formats import AccessFormat, derive_access_format, fallback_access_format
from phase2_parse.parse_nginx import parse_artifact, parse_report

EVIDENCE_ID = "3ea4c29b-1c31-4f4d-9482-58df13506bc5"
LAB_FORMAT = (
    "log_format lapa '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
    "                  '$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" '\n"
    "                  'msec=$msec request_time=$request_time request_id=$request_id '\n"
    "                  'connection=$connection trace_id=$http_x_lapa_trace "
    "flavour=$http_flavour';\n"
    "access_log /var/log/nginx/access.log lapa;\n"
)


class MemoryStore(EvidenceStore):
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put(
        self,
        evidence_id: str,
        relative_path: str,
        bytes_or_stream: bytes | BinaryIO,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        self.objects[(evidence_id, relative_path)] = (
            bytes_or_stream if isinstance(bytes_or_stream, bytes) else bytes_or_stream.read()
        )

    def get(self, evidence_id: str, relative_path: str) -> bytes:
        try:
            return self.objects[(evidence_id, relative_path)]
        except KeyError as error:
            raise FileNotFoundError(relative_path) from error

    def list(self, evidence_id: str) -> list[str]:
        return sorted(path for item, path in self.objects if item == evidence_id)

    def exists(self, evidence_id: str, relative_path: str) -> bool:
        return (evidence_id, relative_path) in self.objects


def _artifact(path: str, data: bytes, size_at_open: int | None = None) -> dict[str, object]:
    return {
        "source_path": f"/var/log/nginx/{path}",
        "stored_as": f"artifacts/{path}",
        "size_at_open": len(data) if size_at_open is None else size_at_open,
        "sha256_full": sha256_bytes(data),
    }


def _parse_bytes(
    data: bytes,
    *,
    kind: str = "access",
    name: str | None = None,
    size_at_open: int | None = None,
    timezone_block: dict[str, object] | None = None,
    access_format: AccessFormat | None = None,
    expected_stream: bytes | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    name = name or f"{kind}.log"
    store = MemoryStore()
    artifact = _artifact(name, data, size_at_open)
    store.put(EVIDENCE_ID, str(artifact["stored_as"]), data)
    parsed = parse_artifact(
        store,
        EVIDENCE_ID,
        kind,
        artifact,
        access_format or fallback_access_format(),
        timezone_block or {},
    )
    rows = list(parsed.rows)
    report = parse_report([parsed])
    expected = data if expected_stream is None else expected_stream
    assert report["byte_coverage"] is True
    assert b"".join(row["raw_bytes"] for row in rows) == expected
    assert hashlib.sha256(b"".join(row["raw_bytes"] for row in rows)).hexdigest() == report[
        "artifacts"
    ][0]["stream_sha256"]
    return rows, parsed.report


def test_custom_format_parses_fields_and_retains_unknown_variables() -> None:
    access_format = derive_access_format(LAB_FORMAT)
    assert access_format.source == "nginx_config:lapa"
    line = (
        b'127.0.0.1 - - [11/Nov/2026:12:00:00 +0300] '
        b'"GET /a%20b?q=x%20y HTTP/1.1" 200 123 "-" "agent" '
        b"msec=- request_time=0.123 request_id=req-1 connection=5 "
        b"trace_id=trace-1 flavour=vanilla"
    )
    rows, report = _parse_bytes(line + b"\n", access_format=access_format)
    row = rows[0]
    assert row["parse_ok"] is True
    assert row["ts_utc"] == "2026-11-11T09:00:00.000000Z"
    assert row["method"] == "GET"
    assert row["path"] == "/a%20b"
    assert row["path_decoded"] == "/a b"
    assert row["query_decoded"] == "q=x y"
    assert row["trace_id"] == "trace-1"
    assert row["http_flavour"] == "vanilla"
    assert report["format_source"] == "nginx_config:lapa"


def test_malformed_binary_crlf_and_incomplete_lines_are_never_dropped() -> None:
    content = b"\nmalformed\r\n\xffbinary\nlast-no-newline"
    rows, report = _parse_bytes(content)
    assert len(rows) == 4
    assert [row["raw_line"] for row in rows] == [
        "",
        "malformed",
        "\\xffbinary",
        "last-no-newline",
    ]
    assert rows[1]["crlf"] is True
    assert rows[-1]["incomplete_final_line"] is True
    assert all(not row["parse_ok"] for row in rows)
    assert report["total_lines"] == 4
    assert report["unparsed_lines"] == 4
    assert report["total_bytes"] == len(content)


def test_empty_gzip_and_ten_megabyte_single_line_have_exact_coverage() -> None:
    empty_rows, empty_report = _parse_bytes(b"")
    assert empty_rows == []
    assert empty_report["total_bytes"] == 0

    decompressed = b"first\nsecond\n"
    compressed = gzip.compress(decompressed, mtime=0)
    gzip_rows, gzip_report = _parse_bytes(
        compressed,
        name="access.log.2.gz",
        expected_stream=decompressed,
    )
    assert len(gzip_rows) == 2
    assert gzip_report["stream"] == "decompressed"
    assert b"".join(row["raw_bytes"] for row in gzip_rows) == decompressed
    assert gzip_report["total_bytes"] == len(decompressed)

    long_line = b"x" * (10 * 1024 * 1024)
    long_rows, long_report = _parse_bytes(long_line)
    assert len(long_rows) == 1
    assert long_rows[0]["byte_length"] == len(long_line)
    assert long_report["total_bytes"] == len(long_line)


def test_rows_crossing_and_after_verified_prefix_are_flagged() -> None:
    original = b"bad\n"
    grown = original + b"more\n"
    rows, _ = _parse_bytes(grown, size_at_open=len(original))
    assert rows[0]["beyond_prefix"] is False
    assert rows[1]["beyond_prefix"] is True


def test_error_timestamp_uses_target_timezone_and_explicit_utc_fallback() -> None:
    line = (
        b'2026/11/11 12:00:00 [error] 12#34: *56 upstream failed, '
        b'client: 127.0.0.1, server: example.test, request: "GET / HTTP/1.1", '
        b'upstream: "http://127.0.0.1:8081/", host: "example.test"\n'
    )
    rows, report = _parse_bytes(
        line,
        kind="error",
        timezone_block={"iana_name": "Africa/Nairobi"},
    )
    assert rows[0]["parse_ok"] is True
    assert rows[0]["ts_utc"] == "2026-11-11T09:00:00.000000Z"
    assert rows[0]["ts_tz_source"] == "context"
    assert rows[0]["cid"] == 56
    assert rows[0]["client"] == "127.0.0.1"
    assert rows[0]["request"] == "GET / HTTP/1.1"
    assert report["ts_tz_source"] == "context"

    fallback_rows, fallback_report = _parse_bytes(line, kind="error")
    assert fallback_rows[0]["ts_utc"] == "2026-11-11T12:00:00.000000Z"
    assert fallback_rows[0]["ts_tz_source"] == "assumed_utc"
    assert fallback_report["ts_tz_source"] == "assumed_utc"


def test_malformed_request_retains_raw_line_and_null_method() -> None:
    line = (
        b'127.0.0.1 - - [11/Nov/2026:12:00:00 +0000] "BROKEN" 400 0 "-" "-" '
        b"msec=- request_time=- request_id=- connection=- trace_id=- flavour=-\n"
    )
    access_format = derive_access_format(LAB_FORMAT)
    store = MemoryStore()
    artifact = _artifact("access.log", line)
    store.put(EVIDENCE_ID, str(artifact["stored_as"]), line)
    parsed = parse_artifact(store, EVIDENCE_ID, "access", artifact, access_format, {})
    row = list(parsed.rows)[0]
    assert row["method"] is None
    assert row["parse_ok"] is False
    assert row["parse_error"] == "malformed request line"
    assert row["raw_line"].startswith("127.0.0.1")
