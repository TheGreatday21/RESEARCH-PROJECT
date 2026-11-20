# Phase 2: Parsing & Derived Parquet Dataset (`phase2_parse/`)

Phase 2 verifies a stored evidence package, copies it to an isolated temporary working directory, re-verifies the working copy, and streams every log line losslessly into signed Parquet tables (`derived/<case_id>/<evidence_id>/`).

## Modules

- `formats.py` — Extracts `log_format` directives from the captured `nginx.conf` (or falls back to the documented lab format).
- `parse_nginx.py` — Lossless line-by-line parser for access and error logs (including `.gz` rotated logs). Every physical line produces a row with `artifact_path`, `line_no`, `byte_offset`, `byte_length`, `raw_bytes`, `parse_ok`, and `beyond_prefix`.
- `dataset.py` — Manages the verified working copy, writes `access.parquet`, `error.parquet`, `parse_report.json`, and signs `derived_manifest.json` with a canonical row-level `content_hash`. Also implements `verify_derived_dataset`.
- `sql.py` — Registers `access` and `error` Parquet tables as read-only in-memory DuckDB views and executes SQL queries.
- `tests/` — Unit tests for log format derivation, lossless parsing (`test_parser.py`), and working-copy/derivation verification (`test_derivation.py`).

## CLI Commands

```sh
lapa parse C001 --evidence-id "$EVIDENCE_ID"
lapa verify-derived C001 --evidence-id "$EVIDENCE_ID"
lapa sql C001 "$EVIDENCE_ID" "SELECT status, count(*) FROM access GROUP BY status"
```
