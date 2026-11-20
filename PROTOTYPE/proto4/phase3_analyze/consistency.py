"""Log consistency checks over verified evidence and derived datasets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

# ---------------------------------------------------------------------------
# Check result types
# ---------------------------------------------------------------------------

PASS = "pass"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class ConsistencyCheck:
    """Named, graded outcome for one consistency check."""

    name: str
    status: str  # "pass", "warn", or "fail"
    message: str
    detail: dict[str, Any] | None = None

    @property
    def passed(self) -> bool:
        return self.status == PASS

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "passed": self.passed,
            "message": self.message,
        }
        if self.detail:
            result["detail"] = self.detail
        return result


@dataclass(frozen=True)
class ConsistencyResult:
    """Aggregate all consistency checks for one evidence/derived pair."""

    evidence_id: str
    checks: tuple[ConsistencyCheck, ...]

    @property
    def ok(self) -> bool:
        """True when every check passed (no warns or fails)."""
        return all(c.status == PASS for c in self.checks)

    @property
    def has_failures(self) -> bool:
        return any(c.status == FAIL for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "ok": self.ok,
            "has_failures": self.has_failures,
            "checks": [c.to_dict() for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

# Clock-skew thresholds (seconds)
_SKEW_WARN = 5.0
_SKEW_FAIL = 30.0


def check_clock_skew(timing_block: dict[str, Any]) -> ConsistencyCheck:
    """Grade the estimated target/control clock offset from the manifest timing block.

    Uses ``estimated_offset_seconds`` and ``estimated_offset_uncertainty_seconds``
    written by the orchestrator.  An absolute offset below the warn threshold is a
    pass; between warn and fail is a warn; above is a fail.
    """
    name = "clock_skew"
    offset = timing_block.get("estimated_offset_seconds")
    uncertainty = timing_block.get("estimated_offset_uncertainty_seconds")
    if not isinstance(offset, (int, float)) or not isinstance(uncertainty, (int, float)):
        return ConsistencyCheck(
            name=name,
            status=WARN,
            message="timing block is missing estimated_offset_seconds or uncertainty",
        )
    abs_offset = abs(float(offset))
    detail: dict[str, Any] = {
        "estimated_offset_seconds": offset,
        "estimated_offset_uncertainty_seconds": uncertainty,
    }
    if abs_offset >= _SKEW_FAIL:
        return ConsistencyCheck(
            name=name,
            status=FAIL,
            message=(
                f"clock offset {abs_offset:.1f} s exceeds the {_SKEW_FAIL:.0f} s failure threshold"
            ),
            detail=detail,
        )
    if abs_offset >= _SKEW_WARN:
        return ConsistencyCheck(
            name=name,
            status=WARN,
            message=(
                f"clock offset {abs_offset:.1f} s exceeds the {_SKEW_WARN:.0f} s warning threshold"
            ),
            detail=detail,
        )
    return ConsistencyCheck(
        name=name,
        status=PASS,
        message=f"clock offset {abs_offset:.1f} s is within acceptable range",
        detail=detail,
    )


def check_line_continuity(parquet_path: Path, table: str) -> ConsistencyCheck:
    """Verify that line_no is gapless 1..N within each artifact_path partition.

    A gap in line numbers indicates possible truncation or missing content in the
    stored artifact.
    """
    name = f"line_continuity:{table}"
    if not parquet_path.is_file():
        return ConsistencyCheck(name=name, status=FAIL, message=f"file not found: {parquet_path}")
    con = duckdb.connect(":memory:")
    try:
        # Find the first gap: where line_no != previous line_no + 1 within the same artifact.
        gap_sql = f"""
        WITH ordered AS (
            SELECT artifact_path, line_no,
                   lag(line_no) OVER (PARTITION BY artifact_path ORDER BY line_no) AS prev_line_no
            FROM read_parquet({str(parquet_path.resolve())!r})
        )
        SELECT artifact_path, prev_line_no, line_no
        FROM ordered
        WHERE prev_line_no IS NOT NULL
          AND line_no != prev_line_no + 1
        ORDER BY artifact_path, line_no
        LIMIT 1
        """
        rows = con.execute(gap_sql).fetchall()
    finally:
        con.close()

    if rows:
        artifact_path, prev_no, curr_no = rows[0]
        return ConsistencyCheck(
            name=name,
            status=FAIL,
            message=(
                f"line number gap in {artifact_path}: "
                f"expected {prev_no + 1} but found {curr_no}"
            ),
            detail={"artifact_path": artifact_path, "prev_line_no": prev_no, "line_no": curr_no},
        )
    return ConsistencyCheck(
        name=name,
        status=PASS,
        message=f"all line numbers in {table} are gapless 1..N within each artifact",
    )


def check_timestamp_monotonicity(parquet_path: Path, table: str) -> ConsistencyCheck:
    """Check that parsed timestamps are non-decreasing within each log file.

    A retrograde jump (later timestamp followed by an earlier one within the same
    artifact) may indicate log rotation interleaving, tampering, or a misbehaving
    clock — all worth flagging for investigator review.
    """
    name = f"timestamp_monotonicity:{table}"
    if not parquet_path.is_file():
        return ConsistencyCheck(name=name, status=FAIL, message=f"file not found: {parquet_path}")
    con = duckdb.connect(":memory:")
    try:
        jump_sql = f"""
        WITH ordered AS (
            SELECT artifact_path, ts_utc, line_no,
                   lag(ts_utc) OVER (PARTITION BY artifact_path ORDER BY line_no) AS prev_ts
            FROM read_parquet({str(parquet_path.resolve())!r})
            WHERE ts_utc IS NOT NULL AND parse_ok
        )
        SELECT artifact_path, prev_ts, ts_utc, line_no
        FROM ordered
        WHERE prev_ts IS NOT NULL AND ts_utc < prev_ts
        ORDER BY artifact_path, line_no
        LIMIT 1
        """
        rows = con.execute(jump_sql).fetchall()
    finally:
        con.close()

    if rows:
        artifact_path, prev_ts, curr_ts, line_no = rows[0]
        return ConsistencyCheck(
            name=name,
            status=WARN,
            message=(
                f"retrograde timestamp in {artifact_path} at line {line_no}: "
                f"{curr_ts!r} follows {prev_ts!r}"
            ),
            detail={
                "artifact_path": artifact_path,
                "line_no": line_no,
                "prev_ts_utc": prev_ts,
                "curr_ts_utc": curr_ts,
            },
        )
    return ConsistencyCheck(
        name=name,
        status=PASS,
        message=f"all parsed timestamps in {table} are non-decreasing within each artifact",
    )


def check_byte_coverage(parse_report: dict[str, Any]) -> ConsistencyCheck:
    """Promote the parse report's byte_coverage boolean into a named check."""
    name = "byte_coverage"
    covered = parse_report.get("byte_coverage")
    total = parse_report.get("total_bytes", 0)
    parsed = parse_report.get("parsed_lines", 0)
    unparsed = parse_report.get("unparsed_lines", 0)
    detail: dict[str, Any] = {
        "total_bytes": total,
        "parsed_lines": parsed,
        "unparsed_lines": unparsed,
    }
    if covered is True:
        return ConsistencyCheck(
            name=name,
            status=PASS,
            message=f"all {total} bytes are accounted for across {parsed + unparsed} rows",
            detail=detail,
        )
    if covered is False:
        return ConsistencyCheck(
            name=name,
            status=FAIL,
            message="byte coverage check failed: not all stream bytes appear in row offsets",
            detail=detail,
        )
    return ConsistencyCheck(
        name=name,
        status=WARN,
        message="byte_coverage is absent from the parse report",
        detail=detail,
    )


def check_unparsed_ratio(
    parse_report: dict[str, Any], *, warn_pct: float = 5.0
) -> ConsistencyCheck:
    """Warn when the fraction of unparsed lines exceeds warn_pct (default 5%)."""
    name = "unparsed_ratio"
    parsed = parse_report.get("parsed_lines", 0)
    unparsed = parse_report.get("unparsed_lines", 0)
    total = parsed + unparsed
    if total == 0:
        return ConsistencyCheck(name=name, status=PASS, message="no log lines to check")
    pct = 100.0 * unparsed / total
    detail: dict[str, Any] = {
        "parsed_lines": parsed,
        "unparsed_lines": unparsed,
        "unparsed_pct": round(pct, 2),
    }
    if pct > warn_pct:
        return ConsistencyCheck(
            name=name,
            status=WARN,
            message=f"{unparsed} of {total} lines ({pct:.1f}%) could not be parsed",
            detail=detail,
        )
    return ConsistencyCheck(
        name=name,
        status=PASS,
        message=f"{unparsed} of {total} lines ({pct:.1f}%) unparsed — within tolerance",
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Aggregated runner
# ---------------------------------------------------------------------------

def run_consistency_checks(
    evidence_id: str,
    timing_block: dict[str, Any],
    parse_report: dict[str, Any],
    derived_directory: Path,
) -> ConsistencyResult:
    """Run the full Phase 3 consistency check suite.

    Args:
        evidence_id: UUID of the evidence package being analysed.
        timing_block: The ``timing`` object from the evidence manifest.
        parse_report: Parsed parse_report.json from the derived dataset.
        derived_directory: Directory containing access.parquet and error.parquet.
    """
    checks: list[ConsistencyCheck] = [
        check_clock_skew(timing_block),
        check_byte_coverage(parse_report),
        check_unparsed_ratio(parse_report),
        check_line_continuity(derived_directory / "access.parquet", "access"),
        check_line_continuity(derived_directory / "error.parquet", "error"),
        check_timestamp_monotonicity(derived_directory / "access.parquet", "access"),
        check_timestamp_monotonicity(derived_directory / "error.parquet", "error"),
    ]
    return ConsistencyResult(evidence_id=evidence_id, checks=tuple(checks))
