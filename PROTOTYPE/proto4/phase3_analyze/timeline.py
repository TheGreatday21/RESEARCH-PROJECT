"""Merge access and error logs into a chronological forensic timeline."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb


@dataclass(frozen=True)
class TimelineEvent:
    """One merged, timestamped event from either the access or error log stream."""

    ts_utc: str
    source: str  # "access" or "error"
    artifact_path: str
    line_no: int
    byte_offset: int
    # Access-specific (None for error events)
    method: str | None
    status: int | None
    path: str | None
    request_time: float | None
    # Error-specific (None for access events)
    level: str | None
    message: str | None
    # Shared
    raw_line: str
    parse_ok: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts_utc": self.ts_utc,
            "source": self.source,
            "artifact_path": self.artifact_path,
            "line_no": self.line_no,
            "byte_offset": self.byte_offset,
            "method": self.method,
            "status": self.status,
            "path": self.path,
            "request_time": self.request_time,
            "level": self.level,
            "message": self.message,
            "raw_line": self.raw_line,
            "parse_ok": self.parse_ok,
        }


@dataclass(frozen=True)
class GapEvent:
    """A silence interval between two consecutive timestamped events."""

    after_ts_utc: str
    before_ts_utc: str
    gap_seconds: float
    after_source: str
    before_source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "after_ts_utc": self.after_ts_utc,
            "before_ts_utc": self.before_ts_utc,
            "gap_seconds": self.gap_seconds,
            "after_source": self.after_source,
            "before_source": self.before_source,
        }


@dataclass(frozen=True)
class TimelineResult:
    """Full timeline with event list, unparsed-row count, and gap summary."""

    events: tuple[TimelineEvent, ...]
    unparsed_count: int
    gaps: tuple[GapEvent, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": len(self.events),
            "unparsed_count": self.unparsed_count,
            "gaps": [g.to_dict() for g in self.gaps],
            "events": [e.to_dict() for e in self.events],
        }


# ---------------------------------------------------------------------------
# DuckDB-backed construction
# ---------------------------------------------------------------------------

_ACCESS_SQL = """\
SELECT
    ts_utc,
    'access'       AS source,
    artifact_path,
    line_no,
    byte_offset,
    method,
    status,
    path,
    request_time,
    NULL::VARCHAR  AS level,
    NULL::VARCHAR  AS message,
    raw_line,
    parse_ok
FROM read_parquet({path!r})
WHERE ts_utc IS NOT NULL"""

_ERROR_SQL = """\
SELECT
    ts_utc,
    'error'        AS source,
    artifact_path,
    line_no,
    byte_offset,
    NULL::VARCHAR  AS method,
    NULL::INTEGER  AS status,
    NULL::VARCHAR  AS path,
    NULL::DOUBLE   AS request_time,
    level,
    message,
    raw_line,
    parse_ok
FROM read_parquet({path!r})
WHERE ts_utc IS NOT NULL"""

_UNPARSED_SQL = """\
SELECT count(*) AS n FROM (
    SELECT ts_utc FROM read_parquet({access!r}) WHERE ts_utc IS NULL
    UNION ALL
    SELECT ts_utc FROM read_parquet({error!r}) WHERE ts_utc IS NULL
)"""


def build_timeline(
    derived_directory: Path,
    *,
    gap_threshold_seconds: float = 60.0,
) -> TimelineResult:
    """Merge access and error Parquet tables into one sorted timeline.

    Rows whose ``ts_utc`` is NULL (timestamp could not be parsed) are skipped
    and their count is reported in ``unparsed_count``.  Events are sorted by
    ``ts_utc`` then ``source`` then ``artifact_path`` then ``line_no`` so the
    result is deterministic across repeated runs.
    """
    access_path = str((derived_directory / "access.parquet").resolve())
    error_path = str((derived_directory / "error.parquet").resolve())

    for label, p in (("access.parquet", access_path), ("error.parquet", error_path)):
        if not Path(p).is_file():
            raise FileNotFoundError(f"derived table not found: {label} in {derived_directory}")

    con = duckdb.connect(":memory:")
    try:
        unparsed_count = int(
            con.execute(
                _UNPARSED_SQL.format(access=access_path, error=error_path)
            ).fetchone()[0]  # type: ignore[index]
        )

        merged_sql = (
            "SELECT * FROM ("
            + _ACCESS_SQL.format(path=access_path)
            + " UNION ALL "
            + _ERROR_SQL.format(path=error_path)
            + ") ORDER BY ts_utc, source, artifact_path, line_no"
        )
        rows = con.execute(merged_sql).fetchall()
    finally:
        con.close()

    events: list[TimelineEvent] = []
    for row in rows:
        (
            ts_utc, source, artifact_path, line_no, byte_offset,
            method, status, path, request_time,
            level, message, raw_line, parse_ok,
        ) = row
        events.append(
            TimelineEvent(
                ts_utc=str(ts_utc),
                source=str(source),
                artifact_path=str(artifact_path),
                line_no=int(line_no),
                byte_offset=int(byte_offset),
                method=str(method) if method is not None else None,
                status=int(status) if status is not None else None,
                path=str(path) if path is not None else None,
                request_time=float(request_time) if request_time is not None else None,
                level=str(level) if level is not None else None,
                message=str(message) if message is not None else None,
                raw_line=str(raw_line),
                parse_ok=bool(parse_ok),
            )
        )

    gaps = _find_gaps(events, gap_threshold_seconds)
    return TimelineResult(
        events=tuple(events),
        unparsed_count=unparsed_count,
        gaps=tuple(gaps),
    )


def _find_gaps(events: list[TimelineEvent], threshold: float) -> list[GapEvent]:
    """Return consecutive pairs of events whose time gap exceeds the threshold."""
    gaps: list[GapEvent] = []
    for prev, curr in zip(events, events[1:], strict=False):
        try:
            t0 = _dt.datetime.fromisoformat(prev.ts_utc.replace("Z", "+00:00"))
            t1 = _dt.datetime.fromisoformat(curr.ts_utc.replace("Z", "+00:00"))
            gap = (t1 - t0).total_seconds()
        except ValueError:
            continue
        if gap >= threshold:
            gaps.append(
                GapEvent(
                    after_ts_utc=prev.ts_utc,
                    before_ts_utc=curr.ts_utc,
                    gap_seconds=gap,
                    after_source=prev.source,
                    before_source=curr.source,
                )
            )
    return gaps
