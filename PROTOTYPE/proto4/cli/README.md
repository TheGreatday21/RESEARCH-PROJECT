# Command-Line Interface (`cli/`)

Unified Typer CLI (`lapa`) that connects all four phases:

| Phase | Commands | Notes |
| --- | --- | --- |
| **Phase 1 (`phase1_acquire`)** | `lapa keygen`, `lapa preflight`, `lapa acquire`, `lapa verify`, `lapa show` | `preflight` checks target access read-only (writes no evidence; exit 0/1). `acquire` supports optional `--aws-instance-id`, `--aws-profile`, `--aws-region` for read-only AWS identity cross-checking and outputs `cloud_cross_check` (exit 0 ok, exit 2 partial/collection errors, exit 1 fatal). `verify` enforces `acquisition_complete` alongside signature, acquisition record, and file hashes. |
| **Phase 2 (`phase2_parse`)** | `lapa parse`, `lapa verify-derived`, `lapa sql` | Verifies stored evidence in an isolated working copy, parses `lapa` and stock `combined` logs losslessly into signed Parquet tables, and queries with DuckDB. |
| **Phase 3 (`phase3_analyze`)** | `lapa analyze` | Verifies derived dataset, runs 7 consistency checks, and builds the merged UTC timeline with silence-gap detection. |
| **Phase 4 (`phase4_detect`)** | `lapa detect`, `lapa evaluate`, `lapa report` | `evaluate --labels <file>` reports unlabelled detections separately (not scored, not counted as false positives). `report` writes `report.md` and `report.json` with the data-backed **Trust boundaries and limitations** section (`--labels` is optional). |
