# Phase 3: Log Consistency Checks & Timeline Reconstruction (`phase3_analyze/`)

Phase 3 verifies the derived Parquet dataset against its parent evidence manifest, runs log consistency checks, and merges access and error events into a single chronological UTC timeline (`analysis/<case_id>/<evidence_id>/`).

## Modules

- `pipeline.py` — Verification gates (`require_verified_evidence`, `require_verified_derived`, `load_inputs`) ensuring no analysis runs on unverified or tampered data.
- `consistency.py` — Runs 7 consistency checks across evidence timing and derived Parquet tables:
  1. `clock_skew` (target vs. control clock offset)
  2. `byte_coverage` (100% of stream bytes accounted for in rows)
  3. `unparsed_ratio` (warns if > 5% of lines failed parsing)
  4. `line_continuity:access` and `line_continuity:error` (gapless `1..N` line numbers per file)
  5. `timestamp_monotonicity:access` and `timestamp_monotonicity:error` (flags retrograde timestamp jumps)
- `timeline.py` — Merges parsed `access.parquet` and `error.parquet` events in deterministic UTC order and detects silence gaps exceeding `gap_threshold_seconds`.
- `tests/` — Unit tests for consistency checks (`test_consistency.py`) and timeline/gap reconstruction (`test_timeline.py`).

## CLI Commands

```sh
lapa analyze C001 --evidence-id "$EVIDENCE_ID"
```
