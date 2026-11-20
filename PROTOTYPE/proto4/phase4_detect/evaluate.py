"""Score detector output against a ground-truth labels file joined by ``trace_id``.

Labels join to access rows through the ``X-Lapa-Trace`` header logged as ``trace_id``.
They are an external testing input, not signed evidence; reported scores describe only
the labelled set.

Detections on rows with no matching ``trace_id`` in the labels file (including requests
rejected before header parsing or background internet traffic) are reported separately
as unlabelled detections (not scored) and are never counted as false positives.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phase4_detect.detectors import ATTACK_CLASSES, Detection
from phase4_detect.features import RequestFeatures

BENIGN = "benign"


class LabelError(ValueError):
    """Report a malformed or inconsistent ground-truth label file."""


def load_labels(path: Path) -> dict[str, str]:
    """Read ``trace_id -> class`` from a JSONL label file, rejecting duplicates."""
    labels: dict[str, str] = {}
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise LabelError(f"{path}:{number}: invalid JSON: {error}") from error
            if not isinstance(record, dict):
                raise LabelError(f"{path}:{number}: label must be an object")
            trace_id, label_class = record.get("trace_id"), record.get("class")
            if not isinstance(trace_id, str) or not isinstance(label_class, str):
                raise LabelError(f"{path}:{number}: label needs string trace_id and class")
            if trace_id in labels:
                raise LabelError(f"{path}:{number}: duplicate trace_id {trace_id}")
            labels[trace_id] = label_class
    return labels


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _scores(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


@dataclass(frozen=True)
class EvaluationResult:
    """Row-level detector metrics plus every disagreement, for examiner review."""

    report: dict[str, Any]


def evaluate_detections(
    features: list[RequestFeatures],
    detections: list[Detection],
    labels: dict[str, str],
) -> EvaluationResult:
    """Compare detections with labels, per class and as a binary attack/benign task."""
    predicted: dict[tuple[str, int], set[str]] = defaultdict(set)
    for detection in detections:
        predicted[(detection.artifact_path, detection.line_no)].add(detection.attack_class)

    labelled = [item for item in features if item.trace_id in labels]
    labelled_keys = {(item.artifact_path, item.line_no) for item in labelled}
    unlabelled = [item for item in features if item.trace_id not in labels]
    untraced = [item for item in unlabelled if item.trace_id is None]
    unlabelled_detections = [
        detection
        for detection in detections
        if (detection.artifact_path, detection.line_no) not in labelled_keys
    ]
    unlabelled_by_class: dict[str, int] = defaultdict(int)
    for detection in unlabelled_detections:
        unlabelled_by_class[detection.attack_class] += 1
    seen = {item.trace_id for item in labelled}
    missing = sorted(trace for trace in labels if trace not in seen)

    binary = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    class_counts = {name: {"tp": 0, "fp": 0, "fn": 0} for name in ATTACK_CLASSES}
    disagreements: list[dict[str, Any]] = []
    for item in labelled:
        assert item.trace_id is not None
        truth = labels[item.trace_id]
        guess = predicted.get((item.artifact_path, item.line_no), set())
        is_attack, flagged = truth != BENIGN, bool(guess)
        if is_attack:
            binary["tp" if flagged else "fn"] += 1
        else:
            binary["fp" if flagged else "tn"] += 1
        for name in ATTACK_CLASSES:
            hit, expected = name in guess, truth == name
            if hit and expected:
                class_counts[name]["tp"] += 1
            elif hit:
                class_counts[name]["fp"] += 1
            elif expected:
                class_counts[name]["fn"] += 1
        if (is_attack != flagged) or (is_attack and truth not in guess):
            disagreements.append(
                {
                    "trace_id": item.trace_id,
                    "uri_raw": item.uri_raw,
                    "truth": truth,
                    "predicted": sorted(guess),
                    "artifact_path": item.artifact_path,
                    "line_no": item.line_no,
                }
            )

    total = sum(binary.values())
    overall = _scores(binary["tp"], binary["fp"], binary["fn"])
    overall["true_negatives"] = binary["tn"]
    overall["accuracy"] = _ratio(binary["tp"] + binary["tn"], total)
    label_counts: dict[str, int] = defaultdict(int)
    for value in labels.values():
        label_counts[value] += 1
    unknown_classes = sorted(set(label_counts) - {BENIGN, *ATTACK_CLASSES})

    report = {
        "labelled_rows": len(labelled),
        "unlabelled_rows": len(unlabelled),
        "unlabelled_rows_flagged": sum(
            bool(predicted.get((item.artifact_path, item.line_no))) for item in unlabelled
        ),
        "unlabelled_detections_count": len(unlabelled_detections),
        "unlabelled_detections_by_class": dict(sorted(unlabelled_by_class.items())),
        "unlabelled_detections": [
            {
                "attack_class": detection.attack_class,
                "detector": detection.detector,
                "artifact_path": detection.artifact_path,
                "line_no": detection.line_no,
                "byte_offset": detection.byte_offset,
                "trace_id": detection.trace_id,
                "uri_raw": detection.uri_raw,
                "note": "unlabelled detection, not scored",
            }
            for detection in unlabelled_detections
        ],
        "rows_without_trace_id": len(untraced),
        "rows_without_trace_id_flagged": sum(
            bool(predicted.get((item.artifact_path, item.line_no))) for item in untraced
        ),
        "labels_total": len(labels),
        "label_counts": dict(sorted(label_counts.items())),
        "labels_without_joined_row": len(missing),
        "unjoined_trace_ids": missing,
        "unrecognised_label_classes": unknown_classes,
        "overall_attack_vs_benign": overall,
        "per_class": {
            name: _scores(counts["tp"], counts["fp"], counts["fn"])
            for name, counts in class_counts.items()
        },
        "disagreements": disagreements,
    }
    return EvaluationResult(report)
