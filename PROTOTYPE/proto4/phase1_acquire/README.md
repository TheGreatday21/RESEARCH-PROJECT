# Phase 1: Acquisition, Cloud Cross-Check, Preflight & Verification (`phase1_acquire/`)

Phase 1 runs read-only target prerequisite checks (`preflight`), acquires nginx access and error logs over SSH using Ansible, records dual-source cloud identity (target IMDSv2 + optional analyst-side AWS API cross-check), stores read-only evidence (`0444`, create-only) under `evidence/<case_id>/<evidence_id>/`, signs an Ed25519 manifest, records a hash-chained acquisition entry (`custody.jsonl`), and verifies integrity and completeness.

## Modules

- `collector.py` — Standalone Python 3.8+ stdlib-only read-only target collector executed over SSH by Ansible; hashes active and rotated logs (`size_at_open` prefix), captures nginx config and timezone context, probes AWS EC2 IMDSv2 (`--imds-base-url`, `--imds-timeout`, `--no-imds`), records every command and HTTP request in `footprint.commands`, and emits `collector_sha256`.
- `cloud.py` — Analyst-side read-only AWS CLI lookup (`aws ec2 describe-instances`, `aws sts get-caller-identity`, no shell / no boto3) and pure `cross_check_cloud_identity()` comparing instance ID, region, account ID, and SSH target IP.
- `preflight.py` — Read-only target readiness runner (`lapa preflight`) using `ansible/preflight.yml` and the same `ansible.cfg` as `acquire`; writes no evidence and returns structured `{ok, checks: [{name, passed, message, hint}]}`.
- `ansible/` — `ansible.cfg`, `acquire.yml`, `preflight.yml`, and role `acquire_nginx_logs`.
- `orchestrator.py` — Runs `acquire.yml`, verifies fetched artifact prefixes against collector hashes, checks `collector_sha256` against local `collector.py` (`acquirer.collector`), estimates clock offset, merges dual-source `target.cloud`, and stores the signed evidence package.
- `store.py` — `EvidenceStore` interface and `LocalStore` implementation (`0444` read-only, create-only files).
- `manifest.py` — Builds and validates schema v1/v2 acquisition manifests.
- `custody.py` — SHA-256 hash-chained `custody.jsonl` entries (`prev_hash` -> `entry_hash`). Note: `LocalStore` is create-only and Phases 2–4 do not append to `custody.jsonl`, so it acts as a signed, hash-chained acquisition record (see `docs/CAPABILITIES.md`).
- `signing.py` — Ed25519 key pair generation (`keygen`), canonical manifest signing, and signature verification.
- `verify.py` — Structured verification (`manifest_*`, `acquisition_complete`, `custody_*`, `artifact_present:*`, `artifact_prefix:*`, `artifact_full:*`). Fails on non-empty `collection_errors` or missing stored `access.log*` artifacts; remains backward-compatible with schema v1 fixtures.
- `tests/` — Phase 1 unit tests (including IMDSv2 fake-server tests, cloud cross-check tests, preflight tests, completeness/collector-hash tests, and schema v1 fixture) plus opt-in Docker lab integration test.

## CLI Commands

```sh
lapa keygen
lapa preflight --inventory lab/inventory.ini
lapa acquire --inventory lab/inventory.ini --case-id C001 --store local \
  [--aws-instance-id i-...] [--aws-profile <profile>] [--aws-region <region>]
lapa show C001 --evidence-id "$EVIDENCE_ID"
lapa verify C001 --evidence-id "$EVIDENCE_ID"
```
