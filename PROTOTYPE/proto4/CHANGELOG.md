# Changelog

All notable changes in **proto4** (`0.3.0`) over **proto3** (`0.2.0`) are documented here. All manifest and CLI JSON changes are additive, preserving full compatibility with proto3 schema v1 and v2 evidence packages.

## [0.3.0] — proto4

### Acquisition & Verification Honesty (`phase1_acquire/`)
- **Incomplete acquisition check (`verify.py`):** Added `acquisition_complete` check to `verify_evidence()`. Verification now fails if `manifest.collection_errors` is non-empty (surfacing exact failure messages) or if no stored `access.log*` artifact is present. Legacy/schema v1 manifests without `collection_errors` continue to pass with an explanatory message when an access log is present.
- **Collector self-hash verification (`orchestrator.py`):** Compares local `phase1_acquire/collector.py` SHA-256 against target-reported `collector_sha256` and records `acquirer.collector = {sha256_local, sha256_reported_by_target, match}` in the signed manifest. Mismatches append an error to `collection_errors` in both the manifest and `AcquisitionResult` (causing `lapa acquire` to exit 2 and `lapa verify` to fail `acquisition_complete`).
- **Footprint accuracy (`ansible/roles/acquire_nginx_logs/defaults/main.yml`, `docs/TARGET_FOOTPRINT.md`):** Updated `lapa_remote_tmp` to track `ansible_remote_tmp | default('~/.ansible/tmp')` so `run_metadata.files_created` accurately reports where Ansible places temporary files; documented every target command, file read, HTTP probe, and SSH log side effect.

### Dual-Source Cloud Identity (`phase1_acquire/collector.py`, `phase1_acquire/cloud.py`, `cli/app.py`)
- **Target-reported IMDSv2 (`collector.py`):** Added an optional, non-fatal stdlib-only (`urllib.request`) IMDSv2 probe (`PUT /latest/api/token` + `GET /latest/dynamic/instance-identity/document`, plus optional raw document and PKCS7 context artifacts marked `verified_offline: false`), with `--imds-base-url`, `--imds-timeout`, and `--no-imds`. Every HTTP probe is recorded in `footprint.commands`. Stays Python 3.8 compatible.
- **Analyst-side AWS API lookup (`cloud.py`, `lapa acquire`):** Added `--aws-instance-id`, `--aws-profile`, and `--aws-region` to `lapa acquire`. Runs read-only `aws ec2 describe-instances` and `aws sts get-caller-identity` via `subprocess` (no shell, no boto3), recording `status: "unavailable"` on CLI/credential errors without failing acquisition.
- **Cross-check (`cloud.py`, `orchestrator.py`):** Preserves the four flat target-reported keys in `target.cloud` and adds `reported_by_target`, `reported_by_aws_api`, and `cross_check` (`match`, `mismatch`, `not_checked`, `unavailable`) comparing instance ID, region, account ID, and SSH target address against AWS public/private IPs. Mismatches appear in `lapa acquire` JSON (`cloud_cross_check`), GUI warnings, and reports without blocking acquisition or failing Verify.

### Preflight & Prerequisites (`phase1_acquire/preflight.py`, `phase1_acquire/ansible/preflight.yml`, `cli/app.py`)
- Added `lapa preflight --inventory <file>` running read-only checks (SSH connect, non-root UID, `adm` group, `/var/log/nginx` readable, readable `access.log*` and `error.log*`, `python3 >= 3.8`, `nginx` present) using the same `ansible.cfg` as `acquire`, writing zero evidence and emitting `{ok, checks: [{name, passed, message, hint}]}` (exit 0 when all pass, else 1).
- Added `docs/PREREQUISITES.md` ("Preparing a server for acquisition") covering Debian/Ubuntu vs. Amazon Linux permissions, least-privilege IAM actions, and incident-timing warnings.

### Desktop GUI (`gui/`)
- **Target-driven controls (`gui/targets.py`, `gui/lab_tools.py`, `gui/ec2_panel.py`, `gui/pages/page_acquire.py`):** Renamed target radios to **Docker lab** and **My server (AWS EC2) (untested)** (keeping the `(untested)` suffix in one constant) with a neutral description line underneath and no mode switch. Isolated lab-only commands (`Start lab`, `Generate traffic`) into `gui/lab_tools.py`, strictly excluded from EC2 target modules and actions (`gui/targets.py`).
- **Check access:** Added **Check access** button and pass/fail checklist with remediation hints to the EC2 target panel; passes `--aws-instance-id`, `--aws-profile`, and `--aws-region` through to `lapa acquire`.
- **Acquire & Verify UX:** Exit code 2 and cloud mismatches show amber banners listing unverified artifacts, collection errors, or mismatch details. Verify checklist displays the new **Completeness** group (`acquisition_complete`).
- **Enhanced Show manifest:** Shows per-file `size_at_open`, `grew_during_read` (with plain-English note), `changed_during_read`, and `verified`, two-column cloud identity (**Reported by the server** vs. **Reported by AWS**) with status chip, full signing key ID, collector self-hash status, and footprint command count.
- **Labels as input, not mode (`gui/pages/page_analyze.py`, `gui/lapa_gui.py`):** Added collapsed **Advanced: ground-truth labels (testing only)** picker on Page 3, auto-filled with `lab/out/labels.jsonl` for Docker lab when present. **Evaluate** runs whenever a labels file is chosen regardless of target, shows `○ Not run - needs a labels file` when empty, and `report` receives `--labels` only when chosen.

### Evaluation, Parser & Optional AWS Lab (`phase4_detect/`, `phase2_parse/`, `lab/`, `aws_lab/`)
- **Unlabelled detections (`phase4_detect/evaluate.py`):** Explicitly reports detections without a matching `trace_id` in `unlabelled_detections_count`, `unlabelled_detections_by_class`, and `unlabelled_detections` (marked `"unlabelled detection, not scored"`, never counted as false positives).
- **Combined format parser test (`phase2_parse/tests/test_parser.py`):** Added lossless parsing test for stock nginx `combined` format logs alongside the existing `lapa` format tests.
- **Optional test tooling (`aws_lab/`, `lab/traffic/generate.py`):** Added `--base-url` (default `http://target`) to `lab/traffic/generate.py` and created standalone `aws_lab/README.md` and `aws_lab/user_data_bootstrap.sh` (clearly marked test tooling, not part of LAPA, never wired into the GUI).

### Forensic Report & Documentation (`phase4_detect/report.py`, `docs/`)
- Added data-backed **Trust boundaries and limitations** section to `report.md` and matching `trust_boundaries` object to `report.json` (signing key ID, acquisition time, custody entry count/coverage, footprint counts, dual-source cloud identity + caller ARN + cross-check, collection warnings, collector hash match, evaluation labels status without assuming synthetic/real, and explicit **Supports** / **Does not support** statements).
- Created `docs/CAPABILITIES.md`, `docs/PREREQUISITES.md`, `docs/TARGET_FOOTPRINT.md`, and `docs/EVALUATION.md`; archived superseded `PROTOTYPE_HANDOFF_AND_AWS_SPEC.md` under `docs/archive/`.
- Updated `README.md`, `phase1_acquire/README.md`, `cli/README.md`, and `gui/README.md`.
- Bumped package version from `0.2.0` to `0.3.0`.
