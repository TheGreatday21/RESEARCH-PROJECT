"""Assemble a forensic report from freshly verified evidence and analysis results."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from common import __version__
from phase3_analyze.consistency import ConsistencyResult
from phase3_analyze.timeline import TimelineResult
from phase4_detect.detectors import ATTACK_CLASSES, Detection, DetectorConfig
from phase4_detect.features import ClientSummary

LIMITATIONS = (
    "Signed provenance detects changes after acquisition. It cannot show that the logs were "
    "authentic or unaltered before collection.",
    "Detections are signature and heuristic matches on request lines. A match is a lead for "
    "examination, not proof of attacker intent or success; an absence is not proof of safety.",
    "Detection rules use fixed thresholds and cover five attack classes. Evasion by encoding, "
    "fragmentation across clients, or traffic that never reached nginx is not covered.",
    "Evaluation scores describe detector behaviour on the synthetic lab traffic only.",
    "Timestamps are converted to UTC from the target's recorded timezone; clock offset and its "
    "uncertainty come from the acquisition's before/after probes.",
)
_SAMPLE_ROWS = 5


def _timing_summary(manifest: Mapping[str, Any]) -> dict[str, Any]:
    timing = manifest.get("timing")
    timing = timing if isinstance(timing, dict) else {}
    return {
        "started_utc": timing.get("started_utc"),
        "finished_utc": timing.get("finished_utc"),
        "estimated_offset_seconds": timing.get("estimated_offset_seconds"),
        "estimated_offset_uncertainty_seconds": timing.get("estimated_offset_uncertainty_seconds"),
    }


def _findings(detections: Sequence[Detection]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Detection]] = defaultdict(list)
    for detection in detections:
        grouped[detection.attack_class].append(detection)
    findings: list[dict[str, Any]] = []
    for name in ATTACK_CLASSES:
        items = grouped.get(name, [])
        if not items:
            continue
        findings.append(
            {
                "attack_class": name,
                "detections": len(items),
                "distinct_requests": len({(d.artifact_path, d.line_no) for d in items}),
                "clients": sorted({d.remote_addr for d in items}),
                "detectors": sorted({d.detector for d in items}),
                "first_ts_utc": min(d.ts_utc for d in items),
                "last_ts_utc": max(d.ts_utc for d in items),
                "samples": [d.to_dict() for d in items[:_SAMPLE_ROWS]],
            }
        )
    return findings


def build_report(
    *,
    case_id: str,
    evidence_id: str,
    generated_utc: str,
    manifest: Mapping[str, Any],
    parse_report: Mapping[str, Any],
    consistency: ConsistencyResult,
    timeline: TimelineResult,
    clients: Sequence[ClientSummary],
    detections: Sequence[Detection],
    detector_config: DetectorConfig,
    evaluation: Mapping[str, Any] | None,
    isolation_forest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the machine-readable report; evidence and derived checks already passed."""
    target = manifest.get("target")
    target = target if isinstance(target, dict) else {}
    acquirer = manifest.get("acquirer")
    acquirer = acquirer if isinstance(acquirer, dict) else {}
    events = timeline.events
    return {
        "schema_version": 1,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "generated_utc": generated_utc,
        "lapa_version": __version__,
        "integrity": {"evidence_verified": True, "derived_verified": True},
        "acquisition": {
            "target_hostname": target.get("hostname"),
            "target_address": target.get("address"),
            "kernel": target.get("kernel"),
            "operator": acquirer.get("operator"),
            "tool_version": acquirer.get("version"),
            "timezone": manifest.get("timezone"),
            **_timing_summary(manifest),
        },
        "dataset": {
            "total_bytes": parse_report.get("total_bytes"),
            "total_lines": parse_report.get("total_lines"),
            "parsed_lines": parse_report.get("parsed_lines"),
            "unparsed_lines": parse_report.get("unparsed_lines"),
            "byte_coverage": parse_report.get("byte_coverage"),
            "assumed_utc_artifacts": parse_report.get("assumed_utc_artifacts", []),
        },
        "consistency": consistency.to_dict(),
        "timeline": {
            "events": len(events),
            "unparsed_count": timeline.unparsed_count,
            "first_ts_utc": events[0].ts_utc if events else None,
            "last_ts_utc": events[-1].ts_utc if events else None,
            "gaps": [gap.to_dict() for gap in timeline.gaps],
        },
        "clients": [client.to_dict() for client in clients],
        "detector_config": detector_config.to_dict(),
        "findings": _findings(detections),
        "total_detections": len(detections),
        "isolation_forest": dict(isolation_forest) if isolation_forest is not None else None,
        "evaluation": dict(evaluation) if evaluation is not None else None,
        "limitations": list(LIMITATIONS),
    }


def _cell(value: Any) -> str:
    return "n/a" if value is None else str(value).replace("|", "\\|")


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render the report as Markdown for human review."""
    acquisition = report["acquisition"]
    dataset = report["dataset"]
    timeline = report["timeline"]
    lines = [
        f"# Forensic report: case {report['case_id']}",
        "",
        f"- Evidence ID: `{report['evidence_id']}`",
        f"- Generated: {report['generated_utc']} by lapa {report['lapa_version']}",
        "- Integrity: evidence package and derived dataset were verified immediately "
        "before this report was generated.",
        "",
        "## Acquisition",
        "",
        f"- Target: {_cell(acquisition['target_hostname'])} "
        f"({_cell(acquisition['target_address'])})",
        f"- Operator: {_cell(acquisition['operator'])}",
        f"- Window: {_cell(acquisition['started_utc'])} to {_cell(acquisition['finished_utc'])}",
        f"- Target/control clock offset: {_cell(acquisition['estimated_offset_seconds'])} s "
        f"(± {_cell(acquisition['estimated_offset_uncertainty_seconds'])} s)",
        "",
        "## Dataset",
        "",
        f"- {dataset['total_lines']} lines, {dataset['total_bytes']} bytes; "
        f"{dataset['parsed_lines']} parsed, {dataset['unparsed_lines']} unparsed; "
        f"byte coverage: {dataset['byte_coverage']}",
        "",
        "## Consistency checks",
        "",
        "| Check | Status | Message |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {_cell(check['name'])} | {check['status']} | {_cell(check['message'])} |"
        for check in report["consistency"]["checks"]
    ]
    lines += [
        "",
        "## Timeline",
        "",
        f"- {timeline['events']} timestamped events from {_cell(timeline['first_ts_utc'])} "
        f"to {_cell(timeline['last_ts_utc'])}; {timeline['unparsed_count']} rows had no timestamp.",
    ]
    for gap in timeline["gaps"]:
        lines.append(
            f"- Gap of {gap['gap_seconds']:.1f} s between {gap['after_ts_utc']} "
            f"and {gap['before_ts_utc']}"
        )
    lines += ["", "## Clients", ""]
    lines.append("| Address | Requests | Distinct paths | 4xx ratio | 404 paths |")
    lines.append("| --- | --- | --- | --- | --- |")
    top_clients = sorted(
        report["clients"],
        key=lambda c: (-int(c["client_errors"]), -int(c["requests"]), str(c["remote_addr"])),
    )[:15]
    lines += [
        f"| {_cell(c['remote_addr'])} | {c['requests']} | {c['distinct_paths']} | "
        f"{c['client_error_ratio']} | {c['distinct_404_paths']} |"
        for c in top_clients
    ]
    lines += ["", "## Findings", ""]
    if not report["findings"]:
        lines.append("No detector fired on the parsed access requests.")
    for finding in report["findings"]:
        lines += [
            f"### {finding['attack_class']}",
            "",
            f"- {finding['distinct_requests']} requests from {', '.join(finding['clients'])} "
            f"between {finding['first_ts_utc']} and {finding['last_ts_utc']} "
            f"(rules: {', '.join(finding['detectors'])})",
            "",
            f"First {min(len(finding['samples']), finding['detections'])} of "
            f"{finding['detections']} detections shown; all are in detections.json.",
            "",
            "| Row | Request | Status | Reason |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            f"| `{s['artifact_path']}` line {s['line_no']} @ {s['byte_offset']} | "
            f"`{_cell(s['uri_raw'])}` | {_cell(s['status'])} | {_cell(s['reason'])} |"
            for s in finding["samples"]
        ]
        lines.append("")
    iforest = report.get("isolation_forest")
    if iforest:
        dist = iforest.get("score_distribution", {})
        lines += [
            "## Anomaly detection (Isolation Forest)",
            "",
            f"- Model: `{iforest['model']['algorithm']}` ({iforest['model']['n_trees']} trees, "
            f"max_samples={iforest['model']['max_samples']}, "
            f"threshold={iforest['threshold_used']})",
            f"- Scored {iforest['total_scored']} requests; flagged {iforest['anomaly_count']} "
            f"anomalies (score min={dist.get('min')}, median={dist.get('median')}, "
            f"p95={dist.get('p95')}, max={dist.get('max')})",
            "",
            "| Rank | Score | Row | Client | Status | Top features | URI |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        lines += [
            f"| {a['rank']} | {a['anomaly_score']:.4f} | `{a['artifact_path']}` L{a['line_no']} "
            f"@ {a['byte_offset']} | {_cell(a['remote_addr'])} | {_cell(a['status'])} | "
            f"`{', '.join(a['top_features'])}` | `{_cell(a['uri_raw'][:80])}` |"
            for a in iforest.get("anomalies", [])[:10]
        ]
        lines.append("")
    evaluation = report.get("evaluation")
    if evaluation:
        overall = evaluation["overall_attack_vs_benign"]
        lines += [
            "## Detector evaluation (synthetic lab labels)",
            "",
            f"- {evaluation['labelled_rows']} labelled rows; attack vs benign precision "
            f"{_cell(overall['precision'])}, recall {_cell(overall['recall'])}, "
            f"F1 {_cell(overall['f1'])}",
            f"- Labels with no joined log row: {evaluation['labels_without_joined_row']}; "
            f"rows with no trace ID: {evaluation['rows_without_trace_id']} "
            f"({evaluation['rows_without_trace_id_flagged']} flagged by a detector)",
            "",
            "| Class | Precision | Recall | F1 |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            f"| {name} | {_cell(m['precision'])} | {_cell(m['recall'])} | {_cell(m['f1'])} |"
            for name, m in evaluation["per_class"].items()
        ]
        lines.append("")
    lines += ["## Limitations", ""]
    lines += [f"- {text}" for text in report["limitations"]]
    return "\n".join(lines) + "\n"
