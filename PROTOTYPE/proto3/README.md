# LAPA (LAPA) — Simplified Phase Layout (`proto3`)

LAPA (`lapa`) acquires nginx access and error logs over SSH using Ansible, records Ed25519-signed provenance and a hash-chained custody log, parses verified evidence losslessly into Parquet tables, checks log consistency and timelines, and detects web attacks.

## Directory Layout

Each phase of the pipeline lives in its own top-level folder with its own code, `README.md`, and `tests/`:

```text
proto3/
├── common/             # Shared deterministic JSON, SHA-256 hashing, and case/key config
├── phase1_acquire/     # Phase 1: SSH/Ansible acquisition, local evidence store, Ed25519 manifest & custody
├── phase2_parse/       # Phase 2: Verified working copy, lossless nginx log parser, Parquet & DuckDB SQL
├── phase3_analyze/     # Phase 3: Log consistency checks and merged UTC timeline reconstruction
├── phase4_detect/      # Phase 4: Feature extraction, rule detectors, Isolation Forest, evaluation & report
├── cli/                # Unified `lapa` CLI connecting Phases 1–4
├── gui/                # Desktop Tkinter/ttk GUI driving the `lapa` CLI (#1a81a3–#2bc2c4 teal theme)
├── lab/                # Docker target server and seeded synthetic traffic generator
└── dataset/            # External test-server nginx access.log and ingestion script
```

## Setup

Using the existing virtual environment from `proto2` or a fresh `.venv`:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
lapa keygen
```

## Launching the Desktop GUI (`gui/`)

Run the Tkinter/ttk desktop application from the project root:

```sh
make gui
# or directly:
.venv/bin/python -m gui.lapa_gui
```

## Pipeline Walkthrough by Phase

### Phase 1 — Acquire & Verify (`phase1_acquire/`)
Start the Docker lab, generate seeded traffic, acquire logs over SSH, and verify the signed evidence package:

```sh
make lab-up
make traffic
lapa acquire --inventory lab/inventory.ini --case-id C001 --store local
lapa show C001 --evidence-id "$EVIDENCE_ID"
lapa verify C001 --evidence-id "$EVIDENCE_ID"
```

### Phase 2 — Parse & Query (`phase2_parse/`)
Verify the evidence in an isolated working copy, parse logs into signed Parquet tables, and query with DuckDB:

```sh
lapa parse C001 --evidence-id "$EVIDENCE_ID"
lapa verify-derived C001 --evidence-id "$EVIDENCE_ID"
lapa sql C001 "$EVIDENCE_ID" "SELECT status, count(*) FROM access GROUP BY status"
```

### Phase 3 — Consistency & Timeline (`phase3_analyze/`)
Run the 7 log consistency checks and reconstruct the merged access + error UTC timeline:

```sh
lapa analyze C001 --evidence-id "$EVIDENCE_ID"
```

### Phase 4 — Detect, Evaluate & Report (`phase4_detect/`)
Run rule-based attack detectors + Isolation Forest anomaly scoring, evaluate against lab ground-truth labels, and generate the forensic report:

```sh
lapa detect C001 --evidence-id "$EVIDENCE_ID"
lapa evaluate C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl
lapa report C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl
```

## Running Tests

Run all unit tests across all phases, or test an individual phase folder:

```sh
make test          # All unit tests
make test-phase1   # Only Phase 1 (acquisition & provenance)
make test-phase2   # Only Phase 2 (parsing & Parquet derivation)
make test-phase3   # Only Phase 3 (consistency & timeline)
make test-phase4   # Only Phase 4 (detection, evaluation & reporting)
make lint          # Ruff + Mypy strict type checking
```
