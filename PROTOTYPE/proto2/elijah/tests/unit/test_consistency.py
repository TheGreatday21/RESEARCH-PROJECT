"""Unit tests for log consistency checks."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from elijah.analysis.consistency import (
    FAIL,
    PASS,
    WARN,
    ConsistencyResult,
    check_byte_coverage,
    check_clock_skew,
    check_line_continuity,
    check_timestamp_monotonicity,
    check_unparsed_ratio,
    run_consistency_checks,
)

# ---------------------------------------------------------------------------
# Minimal Parquet helpers
# ---------------------------------------------------------------------------

_LOG_SCHEMA = pa.schema(
    [
        pa.field("artifact_path", pa.string()),
        pa.field("line_no", pa.int64()),
        pa.field("ts_utc", pa.string()),
        pa.field("parse_ok", pa.bool_()),
    ]
)


def _row(line_no: int, ts_utc: str | None, parse_ok: bool, path: str = "a.log") -> dict[str, Any]:
    return {"artifact_path": path, "line_no": line_no, "ts_utc": ts_utc, "parse_ok": parse_ok}


def _write_parquet(path: Path, rows: list[dict[str, Any]]) -> None:
    table = pa.Table.from_pylist(rows, schema=_LOG_SCHEMA)
    pq.write_table(table, path)


# ---------------------------------------------------------------------------
# check_clock_skew
# ---------------------------------------------------------------------------


def test_clock_skew_pass() -> None:
    check = check_clock_skew(
        {"estimated_offset_seconds": 1.5, "estimated_offset_uncertainty_seconds": 0.2}
    )
    assert check.status == PASS
    assert check.passed


def test_clock_skew_warn() -> None:
    check = check_clock_skew(
        {"estimated_offset_seconds": 10.0, "estimated_offset_uncertainty_seconds": 0.5}
    )
    assert check.status == WARN
    assert not check.passed


def test_clock_skew_fail() -> None:
    check = check_clock_skew(
        {"estimated_offset_seconds": -45.0, "estimated_offset_uncertainty_seconds": 1.0}
    )
    assert check.status == FAIL
    assert not check.passed


def test_clock_skew_missing_fields() -> None:
    check = check_clock_skew({})
    assert check.status == WARN
    assert "missing" in check.message


def test_clock_skew_detail_present() -> None:
    check = check_clock_skew(
        {"estimated_offset_seconds": 2.0, "estimated_offset_uncertainty_seconds": 0.1}
    )
    assert check.detail is not None
    assert "estimated_offset_seconds" in check.detail


# ---------------------------------------------------------------------------
# check_byte_coverage
# ---------------------------------------------------------------------------


def test_byte_coverage_pass() -> None:
    report = {"byte_coverage": True, "total_bytes": 1000, "parsed_lines": 10, "unparsed_lines": 0}
    check = check_byte_coverage(report)
    assert check.status == PASS


def test_byte_coverage_fail() -> None:
    report = {"byte_coverage": False, "total_bytes": 1000, "parsed_lines": 9, "unparsed_lines": 1}
    check = check_byte_coverage(report)
    assert check.status == FAIL


def test_byte_coverage_absent() -> None:
    check = check_byte_coverage({})
    assert check.status == WARN
    assert "absent" in check.message


# ---------------------------------------------------------------------------
# check_unparsed_ratio
# ---------------------------------------------------------------------------


def test_unparsed_ratio_pass() -> None:
    check = check_unparsed_ratio({"parsed_lines": 99, "unparsed_lines": 1})
    assert check.status == PASS


def test_unparsed_ratio_warn() -> None:
    check = check_unparsed_ratio({"parsed_lines": 90, "unparsed_lines": 10})
    assert check.status == WARN


def test_unparsed_ratio_no_lines() -> None:
    check = check_unparsed_ratio({"parsed_lines": 0, "unparsed_lines": 0})
    assert check.status == PASS


# ---------------------------------------------------------------------------
# check_line_continuity
# ---------------------------------------------------------------------------


def test_line_continuity_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, None, False, "a.log"),
                _row(2, None, False, "a.log"),
                _row(3, None, False, "a.log"),
            ],
        )
        check = check_line_continuity(p, "access")
    assert check.status == PASS


def test_line_continuity_gap() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, None, False, "a.log"),
                _row(3, None, False, "a.log"),  # gap
            ],
        )
        check = check_line_continuity(p, "access")
    assert check.status == FAIL
    assert "gap" in check.message.lower()


def test_line_continuity_missing_file() -> None:
    check = check_line_continuity(Path("/no/such/file.parquet"), "access")
    assert check.status == FAIL
    assert "not found" in check.message


def test_line_continuity_independent_partitions() -> None:
    """Each artifact_path is checked independently; a new file starts at 1."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, None, False, "a.log"),
                _row(2, None, False, "a.log"),
                _row(1, None, False, "b.log"),
                _row(2, None, False, "b.log"),
            ],
        )
        check = check_line_continuity(p, "access")
    assert check.status == PASS


# ---------------------------------------------------------------------------
# check_timestamp_monotonicity
# ---------------------------------------------------------------------------


def test_timestamp_monotonicity_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, "2026-11-12T10:00:00Z", True, "a.log"),
                _row(2, "2026-11-12T10:00:01Z", True, "a.log"),
                _row(3, "2026-11-12T10:00:01Z", True, "a.log"),
            ],
        )
        check = check_timestamp_monotonicity(p, "access")
    assert check.status == PASS


def test_timestamp_monotonicity_retrograde() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, "2026-11-12T10:00:05Z", True, "a.log"),
                _row(2, "2026-11-12T10:00:01Z", True, "a.log"),  # retrograde
            ],
        )
        check = check_timestamp_monotonicity(p, "access")
    assert check.status == WARN
    assert "retrograde" in check.message


def test_timestamp_monotonicity_missing_file() -> None:
    check = check_timestamp_monotonicity(Path("/no/such/file.parquet"), "access")
    assert check.status == FAIL


def test_timestamp_monotonicity_ignores_unparsed() -> None:
    """Rows with parse_ok=False are excluded from monotonicity checks."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "access.parquet"
        _write_parquet(
            p,
            [
                _row(1, "2026-11-12T10:00:05Z", True, "a.log"),
                _row(2, "2026-11-12T10:00:01Z", False, "a.log"),  # skipped
                _row(3, "2026-11-12T10:00:06Z", True, "a.log"),
            ],
        )
        check = check_timestamp_monotonicity(p, "access")
    assert check.status == PASS


# ---------------------------------------------------------------------------
# run_consistency_checks (integration of all checks)
# ---------------------------------------------------------------------------


def test_run_consistency_checks_all_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        good_rows = [
            _row(1, "2026-11-12T10:00:00Z", True, "a.log"),
            _row(2, "2026-11-12T10:00:01Z", True, "a.log"),
        ]
        _write_parquet(d / "access.parquet", good_rows)
        _write_parquet(d / "error.parquet", good_rows)
        timing = {"estimated_offset_seconds": 0.5, "estimated_offset_uncertainty_seconds": 0.1}
        parse_report = {
            "byte_coverage": True,
            "total_bytes": 500,
            "parsed_lines": 10,
            "unparsed_lines": 0,
        }
        result = run_consistency_checks("test-id", timing, parse_report, d)

    assert isinstance(result, ConsistencyResult)
    assert result.ok
    assert not result.has_failures
    names = [c.name for c in result.checks]
    assert "clock_skew" in names
    assert "byte_coverage" in names
    assert "line_continuity:access" in names
    assert "line_continuity:error" in names
    assert "timestamp_monotonicity:access" in names
    assert "timestamp_monotonicity:error" in names


def test_run_consistency_checks_reports_failure() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # Line gap → failure
        gap_rows = [
            _row(1, "2026-11-12T10:00:00Z", True, "a.log"),
            _row(3, "2026-11-12T10:00:01Z", True, "a.log"),
        ]
        _write_parquet(d / "access.parquet", gap_rows)
        _write_parquet(d / "error.parquet", [])
        timing = {"estimated_offset_seconds": 0.0, "estimated_offset_uncertainty_seconds": 0.0}
        parse_report = {
            "byte_coverage": True,
            "total_bytes": 100,
            "parsed_lines": 2,
            "unparsed_lines": 0,
        }
        result = run_consistency_checks("test-id", timing, parse_report, d)

    assert result.has_failures
    failed = [c.name for c in result.checks if c.status == FAIL]
    assert "line_continuity:access" in failed


def test_consistency_result_to_dict() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_parquet(d / "access.parquet", [])
        _write_parquet(d / "error.parquet", [])
        result = run_consistency_checks(
            "eid",
            {"estimated_offset_seconds": 1.0, "estimated_offset_uncertainty_seconds": 0.1},
            {"byte_coverage": True, "total_bytes": 0, "parsed_lines": 0, "unparsed_lines": 0},
            d,
        )
    report = result.to_dict()
    assert "evidence_id" in report
    assert "checks" in report
    assert isinstance(report["checks"], list)
