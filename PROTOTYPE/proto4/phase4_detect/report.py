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
    "Evaluation scores, when present, describe detector behaviour only on the provided labelled "
    "set.",
    "Timestamps are converted to UTC from the target's recorded timezone; clock offset and its "
    "uncertainty come from the acquisition's before/after probes.",
)
SUPPORTS_STATEMENT = (
    "the analysed files are exactly what the collector read from the server at acquisition time "
    "and are unchanged since, provided the signing key is uncompromised."
)
DOES_NOT_SUPPORT_STATEMENT = (
    "that the logs were genuine before acquisition; that the target reported its clock, identity "
    "and hashes honestly; any activity not recorded in nginx logs; legal admissibility."
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


def _trust_boundaries(
    *,
    manifest: Mapping[str, Any],
    custody_entries: Sequence[Mapping[str, Any]] | None,
    evaluation: Mapping[str, Any] | None,
    labels_file: str | None,
) -> dict[str, Any]:
    """Build the data-backed trust boundaries and limitations object from recorded inputs."""
    sig = manifest.get("signature")
    sig_dict = sig if isinstance(sig, Mapping) else {}
    timing = manifest.get("timing")
    timing_dict = timing if isinstance(timing, Mapping) else {}
    footprint = manifest.get("footprint")
    footprint_dict = footprint if isinstance(footprint, Mapping) else {}
    acquirer = manifest.get("acquirer")
    acquirer_dict = acquirer if isinstance(acquirer, Mapping) else {}
    target = manifest.get("target")
    target_dict = target if isinstance(target, Mapping) else {}

    if custody_entries is None:
        custody_count: int | None = None
        custody_actions: list[str] = []
        custody_coverage = "custody log not loaded"
    else:
        custody_count = len(custody_entries)
        seen_actions: list[str] = []
        for entry in custody_entries:
            action = str(entry.get("action", ""))
            if action and action not in seen_actions:
                seen_actions.append(action)
        custody_actions = seen_actions
        if custody_count == 1 and custody_actions == ["acquire"]:
            custody_coverage = (
                "1 entry (acquisition record only; Phases 2-4 do not append to custody.jsonl)"
            )
        else:
            custody_coverage = (
                f"{custody_count} entry(ies) covering: "
                f"{', '.join(custody_actions) or 'none'}"
            )

    commands = footprint_dict.get("commands")
    command_count = len(commands) if isinstance(commands, list) else 0
    files_created_raw = footprint_dict.get("files_created")
    files_created = (
        [str(item) for item in files_created_raw]
        if isinstance(files_created_raw, list)
        else []
    )

    cloud_raw = target_dict.get("cloud")
    cloud_dict = cloud_raw if isinstance(cloud_raw, Mapping) else {}
    reported_by_target_raw = cloud_dict.get("reported_by_target")
    if isinstance(reported_by_target_raw, Mapping):
        reported_by_target = dict(reported_by_target_raw)
    else:
        reported_by_target = {
            "provider": str(cloud_dict.get("provider") or ""),
            "instance_id": str(cloud_dict.get("instance_id") or ""),
            "region": str(cloud_dict.get("region") or ""),
            "account_id": str(cloud_dict.get("account_id") or ""),
            "source": "manifest_flat_fields",
        }
    reported_by_aws_raw = cloud_dict.get("reported_by_aws_api")
    reported_by_aws = (
        dict(reported_by_aws_raw)
        if isinstance(reported_by_aws_raw, Mapping)
        else {"status": "not_queried", "source": "aws ec2 describe-instances"}
    )
    cross_check_raw = cloud_dict.get("cross_check")
    cross_check = (
        dict(cross_check_raw)
        if isinstance(cross_check_raw, Mapping)
        else {
            "status": "not_checked",
            "details": ["No cloud cross-check recorded in manifest."],
        }
    )

    artifacts_raw = manifest.get("artifacts")
    artifacts = artifacts_raw if isinstance(artifacts_raw, list) else []
    grew_files = [
        str(item.get("stored_as") or item.get("logical_name") or "<unknown>")
        for item in artifacts
        if isinstance(item, Mapping) and item.get("grew_during_read") is True
    ]
    changed_files = [
        str(item.get("stored_as") or item.get("logical_name") or "<unknown>")
        for item in artifacts
        if isinstance(item, Mapping) and item.get("changed_during_read") is True
    ]
    errors_raw = manifest.get("collection_errors")
    collection_errors = (
        [str(err) for err in errors_raw] if isinstance(errors_raw, list) else []
    )
    collector_raw = acquirer_dict.get("collector")
    collector_hash = (
        dict(collector_raw)
        if isinstance(collector_raw, Mapping)
        else {"match": None, "status": "not_recorded"}
    )

    if evaluation is None:
        eval_labels: dict[str, Any] = {
            "status": "not_provided",
            "file": None,
            "labelled_requests": 0,
            "note": "not provided",
        }
    else:
        eval_labels = {
            "status": "provided",
            "file": labels_file or "provided",
            "labelled_requests": int(evaluation.get("labelled_rows", 0)),
            "unlabelled_detections_count": int(
                evaluation.get("unlabelled_detections_count", 0)
            ),
            "note": "scores describe only that labelled set",
        }

    return {
        "provenance": {
            "signing_key_id": sig_dict.get("key_id"),
            "acquisition_started_utc": timing_dict.get("started_utc"),
            "acquisition_finished_utc": timing_dict.get("finished_utc"),
            "custody_entry_count": custody_count,
            "custody_actions": custody_actions,
            "custody_coverage": custody_coverage,
        },
        "footprint": {
            "target_command_count": command_count,
            "files_created": files_created,
        },
        "cloud_identity": {
            "reported_by_target": reported_by_target,
            "reported_by_aws_api": reported_by_aws,
            "cross_check": cross_check,
        },
        "collection_warnings": {
            "grew_during_read": grew_files,
            "changed_during_read": changed_files,
            "collection_errors": collection_errors,
            "collector_hash": collector_hash,
        },
        "evaluation_labels": eval_labels,
        "supports": SUPPORTS_STATEMENT,
        "does_not_support": DOES_NOT_SUPPORT_STATEMENT,
    }


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
    custody_entries: Sequence[Mapping[str, Any]] | None = None,
    labels_file: str | None = None,
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
        "trust_boundaries": _trust_boundaries(
            manifest=manifest,
            custody_entries=custody_entries,
            evaluation=evaluation,
            labels_file=labels_file,
        ),
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
        unlabelled_det = evaluation.get("unlabelled_detections_count")
        unlabelled_line = (
            f"- Unlabelled detections (not scored, not counted as false positives): "
            f"{unlabelled_det} across "
            f"{evaluation.get('unlabelled_rows_flagged', 0)} unlabelled row(s)"
            if unlabelled_det is not None
            else (
                f"- Rows with no trace ID: {evaluation['rows_without_trace_id']} "
                f"({evaluation['rows_without_trace_id_flagged']} flagged by a detector)"
            )
        )
        lines += [
            "## Detector evaluation (provided labels)",
            "",
            f"- {evaluation['labelled_rows']} labelled rows; attack vs benign precision "
            f"{_cell(overall['precision'])}, recall {_cell(overall['recall'])}, "
            f"F1 {_cell(overall['f1'])} (scores describe only that labelled set).",
            f"- Labels with no joined log row: {evaluation['labels_without_joined_row']}; "
            f"rows with no trace ID: {evaluation['rows_without_trace_id']} "
            f"({evaluation['rows_without_trace_id_flagged']} flagged by a detector).",
            unlabelled_line,
            "",
            "| Class | Precision | Recall | F1 |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            f"| {name} | {_cell(m['precision'])} | {_cell(m['recall'])} | {_cell(m['f1'])} |"
            for name, m in evaluation["per_class"].items()
        ]
        lines.append("")

    trust = report.get("trust_boundaries")
    if isinstance(trust, Mapping):
        prov = trust["provenance"]
        fp = trust["footprint"]
        cloud = trust["cloud_identity"]
        t_cloud = cloud["reported_by_target"]
        a_cloud = cloud["reported_by_aws_api"]
        cross = cloud["cross_check"]
        warn = trust["collection_warnings"]
        collector_h = warn["collector_hash"]
        ev_labels = trust["evaluation_labels"]

        if collector_h.get("match") is True:
            collector_text = "match (target self-hash matched local collector.py)"
        elif collector_h.get("match") is False:
            collector_text = (
                f"MISMATCH (local={_cell(collector_h.get('sha256_local'))}, "
                f"reported={_cell(collector_h.get('sha256_reported_by_target'))})"
            )
        else:
            collector_text = "not recorded in manifest"

        if ev_labels["status"] == "provided":
            labels_text = (
                f"provided (`{_cell(ev_labels['file'])}`, "
                f"{ev_labels['labelled_requests']} labelled request(s)); "
                "scores describe only that labelled set."
            )
        else:
            labels_text = "not provided."

        target_cloud_summary = (
            f"source={_cell(t_cloud.get('source'))}, "
            f"instance_id={_cell(t_cloud.get('instance_id') or None)}, "
            f"region={_cell(t_cloud.get('region') or None)}, "
            f"account_id={_cell(t_cloud.get('account_id') or None)}"
        )
        if t_cloud.get("error"):
            target_cloud_summary += f" (error: {t_cloud['error']})"

        aws_status = a_cloud.get("status", "not_queried")
        if aws_status == "ok":
            aws_cloud_summary = (
                f"instance_id={_cell(a_cloud.get('instance_id'))}, "
                f"region={_cell(a_cloud.get('region'))}, "
                f"account_id={_cell(a_cloud.get('account_id'))}, "
                f"public_ip={_cell(a_cloud.get('public_ip') or None)}, "
                f"private_ip={_cell(a_cloud.get('private_ip') or None)}, "
                f"queried_by={_cell(a_cloud.get('caller_arn') or None)}, "
                f"queried_utc={_cell(a_cloud.get('queried_utc'))}"
            )
        elif aws_status == "unavailable":
            aws_cloud_summary = (
                f"unavailable ({_cell(a_cloud.get('error'))}); "
                f"queried_by={_cell(a_cloud.get('caller_arn') or None)}, "
                f"queried_utc={_cell(a_cloud.get('queried_utc'))}"
            )
        else:
            aws_cloud_summary = "not queried"

        cross_details = "; ".join(str(d) for d in cross.get("details", []))
        files_created_text = (
            "; ".join(fp["files_created"]) if fp["files_created"] else "none recorded"
        )
        grew_text = ", ".join(warn["grew_during_read"]) if warn["grew_during_read"] else "none"
        changed_text = (
            ", ".join(warn["changed_during_read"]) if warn["changed_during_read"] else "none"
        )
        errors_text = (
            "; ".join(warn["collection_errors"]) if warn["collection_errors"] else "none"
        )

        lines += [
            "## Trust boundaries and limitations",
            "",
            f"- **Signing key ID:** `{_cell(prov['signing_key_id'])}` "
            "(record this key ID outside this workstation)",
            f"- **Acquisition time (UTC):** {_cell(prov['acquisition_started_utc'])} to "
            f"{_cell(prov['acquisition_finished_utc'])}",
            f"- **Custody / acquisition record:** {prov['custody_coverage']}",
            f"- **Target footprint:** {fp['target_command_count']} recorded command(s)/request(s); "
            f"files created: {files_created_text}",
            f"- **Cloud identity (reported by target):** {target_cloud_summary}",
            f"- **Cloud identity (reported by AWS API):** {aws_cloud_summary}",
            f"- **Cloud identity cross-check:** `{cross.get('status', 'not_checked')}`"
            + (f" ({cross_details})" if cross_details else ""),
            f"- **Collection warnings:** grew_during_read={grew_text}; "
            f"changed_during_read={changed_text}; "
            f"collection_errors={errors_text}; "
            f"collector_hash={collector_text}",
            f"- **Evaluation labels:** {labels_text}",
            f"- **Supports:** {trust['supports']}",
            f"- **Does not support:** {trust['does_not_support']}",
            "",
        ]

    lines += ["## Limitations", ""]
    lines += [f"- {text}" for text in report["limitations"]]
    return "\n".join(lines) + "\n"
