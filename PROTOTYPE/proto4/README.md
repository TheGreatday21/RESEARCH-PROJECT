# LAPA — Log Acquisition with Provenance and Analysis (`proto4`)

LAPA (`lapa`) connects to an existing nginx server over SSH, copies its access and error logs read-only with Ed25519-signed provenance and a hash-chained acquisition record (`custody.jsonl`), parses verified evidence losslessly into Parquet tables, checks log consistency and timelines, and detects web-attack patterns.

## Capabilities & Limits (Summary)

- **LAPA can show:** byte-for-byte fidelity between what the collector read on the target and what is analysed (source and destination SHA-256 prefix hashes match); any post-acquisition tampering (assuming the signing key is uncompromised); exact byte-range provenance for every parsed row; 7 log consistency checks plus 5 rule detectors and an unsupervised Isolation Forest anomaly score; and dual-source AWS instance identity (target IMDSv2 vs. analyst-side AWS API) with mismatches flagged.
- **LAPA cannot show:** that logs were genuine before acquisition; that the target reported its own clock, identity, or hashes honestly; activity outside nginx logs; legal admissibility; or precision/recall/F1 on real unlabelled traffic without manual sample review.
- **Known limits:** the signing key (`~/.lapa/keys/ed25519.pem`) is unencrypted on the workstation (record the manifest's `key_id` outside the machine); `custody.jsonl` is an **acquisition record (one signed, hash-chained entry)** rather than a multi-phase chain of custody; and SSH acquisition leaves a small, documented target footprint.

See [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md), [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md), [`docs/TARGET_FOOTPRINT.md`](docs/TARGET_FOOTPRINT.md), and [`docs/EVALUATION.md`](docs/EVALUATION.md) for full details.

## Directory Layout

Each phase of the pipeline lives in its own top-level folder with its own code, `README.md`, and `tests/`:

```text
proto4/
├── common/             # Shared deterministic JSON, SHA-256 hashing, and case/key config
├── phase1_acquire/     # Phase 1: Preflight, SSH/Ansible acquisition, IMDSv2 + AWS API cross-check, store, Ed25519 manifest & verify
├── phase2_parse/       # Phase 2: Verified working copy, lossless nginx log parser (lapa & combined), Parquet & DuckDB SQL
├── phase3_analyze/     # Phase 3: 7 log consistency checks and merged UTC timeline reconstruction
├── phase4_detect/      # Phase 4: Features, 5 rule detectors, Isolation Forest, evaluation & trust-bounded reports
├── cli/                # Unified `lapa` CLI connecting Phases 1–4
├── gui/                # Desktop Tkinter/ttk GUI driving the `lapa` CLI (#1a81a3–#2bc2c4 teal theme)
├── docs/               # CAPABILITIES.md, PREREQUISITES.md, TARGET_FOOTPRINT.md, EVALUATION.md, archive/
├── lab/                # Local Docker target server and seeded synthetic traffic generator
├── aws_lab/            # Optional throwaway EC2 test-target templates (test tooling, not part of LAPA)
└── dataset/            # External test-server nginx access.log and ingestion script
```

## Setup

Inside `proto4/`:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/lapa keygen
```

## Launching the Desktop GUI (`gui/`)

```sh
make gui
# or directly:
.venv/bin/python -m gui.lapa_gui
```

## Pipeline Walkthrough by Phase

### Phase 1 — Preflight, Acquire & Verify (`phase1_acquire/`)

Check target prerequisites without writing evidence, acquire logs over SSH (optionally cross-checking AWS EC2 identity), inspect the manifest, and verify integrity and completeness:

```sh
# Local Docker lab test target:
make lab-up
make traffic
lapa preflight --inventory lab/inventory.ini
lapa acquire --inventory lab/inventory.ini --case-id C001 --store local

# Existing AWS EC2 server (read-only acquisition + AWS API identity cross-check):
lapa preflight --inventory my_server.ini
lapa acquire --inventory my_server.ini --case-id C001 --store local \
  --aws-instance-id i-0123456789abcdef0 --aws-region eu-west-1

lapa show C001 --evidence-id "$EVIDENCE_ID"
lapa verify C001 --evidence-id "$EVIDENCE_ID"
```

### Phase 2 — Parse & Query (`phase2_parse/`)

Verify the evidence in an isolated working copy, parse logs (`lapa` or stock nginx `combined` format) into signed Parquet tables, and query with DuckDB:

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

Run rule-based attack detectors + unsupervised Isolation Forest anomaly scoring, optionally evaluate against a ground-truth labels file, and generate `report.md` and `report.json` (including the **Trust boundaries and limitations** section):

```sh
lapa detect C001 --evidence-id "$EVIDENCE_ID"
lapa evaluate C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl   # optional, when labels exist
lapa report C001 --evidence-id "$EVIDENCE_ID"                                  # add --labels <file> if available
```

## Running Tests & Linters

```sh
make test          # All unit tests
make test-phase1   # Only Phase 1 (acquisition, cloud cross-check, preflight, verification)
make test-phase2   # Only Phase 2 (parsing & Parquet derivation)
make test-phase3   # Only Phase 3 (consistency & timeline)
make test-phase4   # Only Phase 4 (detection, evaluation & reporting)
make test-gui      # Only GUI core tests (target rules, preflight/manifest/verify formatters)
make lint          # Ruff + Mypy strict type checking
make integration   # Opt-in Docker lab acquisition & tamper test (LAPA_RUN_LAB_TESTS=1)
```
