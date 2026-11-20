"""Unit tests for timeline reconstruction."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from phase3_analyze.timeline import GapEvent, TimelineEvent, TimelineResult, build_timeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACCESS_SCHEMA = pa.schema(
    [
        pa.field("ts_utc", pa.string()),
        pa.field("artifact_path", pa.string()),
        pa.field("line_no", pa.int64()),
        pa.field("byte_offset", pa.int64()),
        pa.field("method", pa.string()),
        pa.field("status", pa.int64()),
        pa.field("path", pa.string()),
        pa.field("request_time", pa.float64()),
        pa.field("raw_line", pa.string()),
        pa.field("parse_ok", pa.bool_()),
    ]
)

_ERROR_SCHEMA = pa.schema(
    [
        pa.field("ts_utc", pa.string()),
        pa.field("artifact_path", pa.string()),
        pa.field("line_no", pa.int64()),
        pa.field("byte_offset", pa.int64()),
        pa.field("level", pa.string()),
        pa.field("message", pa.string()),
        pa.field("raw_line", pa.string()),
        pa.field("parse_ok", pa.bool_()),
    ]
)


def _write_access(path: Path, rows: list[dict[str, Any]]) -> None:
    table = pa.Table.from_pylist(rows, schema=_ACCESS_SCHEMA)
    pq.write_table(table, path)


def _write_error(path: Path, rows: list[dict[str, Any]]) -> None:
    table = pa.Table.from_pylist(rows, schema=_ERROR_SCHEMA)
    pq.write_table(table, path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_build_timeline_merges_access_and_error() -> None:
    """Access and error events are merged and sorted by ts_utc."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(
            d / "access.parquet",
            [
                {
                    "ts_utc": "2026-11-12T10:00:01Z",
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 1,
                    "byte_offset": 0,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "...",
                    "parse_ok": True,
                },
                {
                    "ts_utc": "2026-11-12T10:00:03Z",
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 2,
                    "byte_offset": 100,
                    "method": "GET",
                    "status": 404,
                    "path": "/missing",
                    "request_time": 0.02,
                    "raw_line": "...",
                    "parse_ok": True,
                },
            ],
        )
        _write_error(
            d / "error.parquet",
            [
                {
                    "ts_utc": "2026-11-12T10:00:02Z",
                    "artifact_path": "artifacts/0001-error.log",
                    "line_no": 1,
                    "byte_offset": 0,
                    "level": "error",
                    "message": "upstream failed",
                    "raw_line": "...",
                    "parse_ok": True,
                },
            ],
        )
        result = build_timeline(d, gap_threshold_seconds=10.0)

    assert isinstance(result, TimelineResult)
    assert result.unparsed_count == 0
    assert len(result.events) == 3

    timestamps = [e.ts_utc for e in result.events]
    assert timestamps == sorted(timestamps), "events are not sorted by ts_utc"

    sources = [e.source for e in result.events]
    assert sources == ["access", "error", "access"]


def test_build_timeline_skips_null_timestamps() -> None:
    """Rows with NULL ts_utc are excluded from events and counted as unparsed."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(
            d / "access.parquet",
            [
                {
                    "ts_utc": "2026-11-12T10:00:01Z",
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 1,
                    "byte_offset": 0,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "parsed",
                    "parse_ok": True,
                },
                {
                    "ts_utc": None,
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 2,
                    "byte_offset": 100,
                    "method": None,
                    "status": None,
                    "path": None,
                    "request_time": None,
                    "raw_line": "JUNK",
                    "parse_ok": False,
                },
            ],
        )
        _write_error(d / "error.parquet", [])

        result = build_timeline(d, gap_threshold_seconds=10.0)

    assert len(result.events) == 1
    assert result.unparsed_count == 1
    assert result.events[0].raw_line == "parsed"


def test_build_timeline_detects_gaps() -> None:
    """GapEvent objects are created when consecutive events are far apart."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(
            d / "access.parquet",
            [
                {
                    "ts_utc": "2026-11-12T10:00:00Z",
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 1,
                    "byte_offset": 0,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "...",
                    "parse_ok": True,
                },
                {
                    "ts_utc": "2026-11-12T10:05:01Z",  # > 60 s later
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 2,
                    "byte_offset": 100,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "...",
                    "parse_ok": True,
                },
            ],
        )
        _write_error(d / "error.parquet", [])

        result = build_timeline(d, gap_threshold_seconds=60.0)

    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert isinstance(gap, GapEvent)
    assert gap.gap_seconds == pytest.approx(301.0)
    assert gap.after_source == "access"
    assert gap.before_source == "access"


def test_build_timeline_no_gap_below_threshold() -> None:
    """Events closer than the threshold produce no GapEvent."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(
            d / "access.parquet",
            [
                {
                    "ts_utc": "2026-11-12T10:00:00Z",
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 1,
                    "byte_offset": 0,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "...",
                    "parse_ok": True,
                },
                {
                    "ts_utc": "2026-11-12T10:00:30Z",  # 30 s — below 60 s threshold
                    "artifact_path": "artifacts/0000-access.log",
                    "line_no": 2,
                    "byte_offset": 100,
                    "method": "GET",
                    "status": 200,
                    "path": "/",
                    "request_time": 0.01,
                    "raw_line": "...",
                    "parse_ok": True,
                },
            ],
        )
        _write_error(d / "error.parquet", [])

        result = build_timeline(d, gap_threshold_seconds=60.0)

    assert len(result.gaps) == 0


def test_build_timeline_missing_parquet_raises() -> None:
    """FileNotFoundError is raised when a required Parquet file is absent."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # Only write access; omit error.
        _write_access(d / "access.parquet", [])
        with pytest.raises(FileNotFoundError, match="error.parquet"):
            build_timeline(d)


def test_build_timeline_empty_tables() -> None:
    """Empty tables produce a TimelineResult with zero events."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(d / "access.parquet", [])
        _write_error(d / "error.parquet", [])
        result = build_timeline(d)

    assert len(result.events) == 0
    assert result.unparsed_count == 0
    assert len(result.gaps) == 0


def test_timeline_event_to_dict_roundtrip() -> None:
    """TimelineEvent.to_dict produces JSON-serialisable output."""
    event = TimelineEvent(
        ts_utc="2026-11-12T10:00:00Z",
        source="access",
        artifact_path="artifacts/0000-access.log",
        line_no=1,
        byte_offset=0,
        method="GET",
        status=200,
        path="/",
        request_time=0.01,
        level=None,
        message=None,
        raw_line="line",
        parse_ok=True,
    )
    d = event.to_dict()
    assert json.dumps(d)  # must not raise
    assert d["source"] == "access"
    assert d["level"] is None


def test_timeline_result_to_dict_structure() -> None:
    """TimelineResult.to_dict has the expected top-level keys."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_access(d / "access.parquet", [])
        _write_error(d / "error.parquet", [])
        result = build_timeline(d)

    report = result.to_dict()
    assert "total_events" in report
    assert "unparsed_count" in report
    assert "gaps" in report
    assert "events" in report
