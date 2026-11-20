# Phase 1: Acquisition & Signed Provenance (`phase1_acquire/`)

Phase 1 acquires nginx access and error logs over SSH using Ansible, stores them in a read-only local evidence store (`evidence/<case_id>/<evidence_id>/`), signs an Ed25519 manifest, records a hash-chained custody log, and verifies evidence integrity.

## Modules

- `collector.py` — Standalone read-only target collector executed over SSH by Ansible; hashes active and rotated logs (`size_at_open` prefix) and captures nginx config and timezone context.
- `ansible/` — Ansible playbook (`acquire.yml`) and role (`acquire_nginx_logs`) that run `collector.py` and fetch log files to staging.
- `orchestrator.py` — Runs the Ansible playbook, verifies fetched artifact prefixes against collector hashes, estimates clock offset, and stores the signed evidence package.
- `store.py` — `EvidenceStore` interface and `LocalStore` implementation (`0444` read-only, create-only files under `evidence/<case_id>/<evidence_id>/`).
- `manifest.py` — Builds and validates schema v1/v2 acquisition manifests.
- `custody.py` — Append-only `custody.jsonl` entries with SHA-256 hash chaining (`prev_hash` -> `entry_hash`).
- `signing.py` — Ed25519 key pair generation (`keygen`), canonical manifest signing, and signature verification.
- `verify.py` — Runs structured verification (`manifest_present`, `manifest_json`, `manifest_schema`, `manifest_signature`, `custody_*`, `artifact_prefix:*`, `artifact_full:*`).
- `tests/` — Phase 1 unit tests and schema-v1 evidence fixture.

## CLI Commands

```sh
lapa keygen
lapa acquire --inventory lab/inventory.ini --case-id C001 --store local
lapa show C001 --evidence-id "$EVIDENCE_ID"
lapa verify C001 --evidence-id "$EVIDENCE_ID"
```
