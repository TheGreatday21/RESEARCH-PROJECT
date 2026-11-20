# Phase 4: Attack Detection, Isolation Forest, Evaluation & Reporting (`phase4_detect/`)

Phase 4 extracts request-level features from verified derived access logs, runs transparent rule-based attack detectors and an unsupervised Isolation Forest anomaly detector, evaluates detections against synthetic lab ground-truth labels, and generates a forensic report.

## Modules

- `features.py` — Extracts `RequestFeatures` (decoded path/query, path depth, query length, percent-encoded char count, status class) and per-IP `ClientSummary` statistics.
- `detectors.py` — Rule-based detectors for 5 attack classes, preserving `(artifact_path, line_no, byte_offset)` provenance for every hit:
  - `path_scan` (`sensitive_path`)
  - `sqli_like` (`sqli_signature`)
  - `traversal` (`traversal_sequence`, `sensitive_file`)
  - `brute_force` (`login_burst`)
  - `low_slow` (`numbered_enumeration`)
- `isolation_forest.py` — Pure-Python deterministic Isolation Forest scoring 8 numerical request/client features to surface anomalous requests.
- `evaluate.py` — Joins detections to synthetic lab `labels.jsonl` via `X-Lapa-Trace` (`trace_id`) and computes per-class and binary precision, recall, and F1.
- `report.py` — Re-verifies evidence and derived data from scratch and writes `report.json` and `report.md` under `reports/<case_id>/<evidence_id>/`.
- `tests/` — Unit tests for feature extraction, rule detectors, Isolation Forest, evaluation metrics, and report rendering (`test_phase4.py`).

## CLI Commands

```sh
lapa detect C001 --evidence-id "$EVIDENCE_ID"
lapa evaluate C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl
lapa report C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl
```
