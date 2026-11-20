# LAPA (`proto3`) — Architecture Summary, Current State & Next Prototype (AWS EC2) Handoff Specification

> **Purpose of this document:**
> 1. Record everything built and refactored in `proto3` alongside the exact current state of the codebase, CLI, test suite, and Tkinter/ttk desktop GUI.
> 2. Serve as a complete, self-contained specification for another LLM to build the next independent prototype (with its own directory, virtual environment, dependencies, and files) focused on **making the AWS EC2 acquisition, traffic generation, and GUI workflow work end-to-end**.

---

## 1. Summary of Work Completed in `proto3`

### 1.1 Simplified Top-Level Phase Architecture
We refactored the earlier nested `proto2/elijah` layout (`src/elijah/acquire`, `src/elijah/prov`, `src/elijah/store`, `src/elijah/analysis`) into a flat, phase-oriented top-level directory structure in `proto3/`. Every phase now lives in its own top-level folder containing its code, its own `README.md`, and its own unit `tests/`:

```text
proto3/
├── README.md                          # Root overview, setup, GUI launch, and 4-phase CLI walkthrough
├── PROTOTYPE_HANDOFF_AND_AWS_SPEC.md  # This handoff & AWS prototype specification
├── pyproject.toml                     # Package config (`lapa`), dependencies, pytest, ruff, and mypy settings
├── Makefile                           # Targets: test, test-phase1..4, test-gui, gui, lint, lab-up, traffic, lab-down
├── common/                            # Shared deterministic JSON, SHA-256 stream/prefix hashing, Settings & case ID validation
│   ├── README.md
│   ├── __init__.py                    # __version__ = "0.2.0"
│   ├── canonical.py                   # canonical_json_bytes, sha256_bytes, hash_stream, hash_file
│   ├── config.py                      # Settings (default ~/.lapa/keys), validate_case_id (C001..C999)
│   └── tests/                         # test_canonical.py, test_config.py
├── phase1_acquire/                    # Phase 1: SSH/Ansible acquisition, local store, Ed25519 manifest & custody chain
│   ├── README.md
│   ├── collector.py                   # Standalone Python 3.8+ read-only target collector executed over SSH
│   ├── orchestrator.py                # Runs ansible-playbook, checks source prefixes, builds signed package
│   ├── store.py                       # EvidenceStore ABC & LocalStore (create-only, chmod 0444 files)
│   ├── manifest.py                    # Schema v1/v2 manifest construction & structural validation
│   ├── custody.py                     # Append-only custody.jsonl with SHA-256 prev_hash -> entry_hash chain
│   ├── signing.py                     # Ed25519 keygen (0600 private key), sign_manifest, verify_manifest_signature
│   ├── verify.py                      # verify_evidence (manifest, signature, custody chain, prefix & full file hashes)
│   ├── ansible/                       # acquire.yml, ansible.cfg, roles/acquire_nginx_logs/{defaults,tasks}/main.yml
│   └── tests/                         # 8 unit test modules + integration test + fixtures/evidence_v1
├── phase2_parse/                      # Phase 2: Verified working copy, lossless nginx log parser, Parquet & DuckDB SQL
│   ├── README.md
│   ├── formats.py                     # Extracts log_format from captured nginx.conf or uses fallback format
│   ├── parse_nginx.py                 # Lossless streaming line-by-line parser for access.log, error.log, and .gz logs
│   ├── dataset.py                     # Verified working copy, Parquet writer, canonical row content_hash, verify_derived_dataset
│   ├── sql.py                         # Read-only in-memory DuckDB query runner (access and error views)
│   └── tests/                         # test_parser.py, test_derivation.py
├── phase3_analyze/                    # Phase 3: Log consistency checks & merged UTC timeline reconstruction
│   ├── README.md
│   ├── pipeline.py                    # Verification gates (require_verified_evidence, require_verified_derived)
│   ├── consistency.py                 # 7 checks: clock_skew, byte_coverage, unparsed_ratio, line_continuity, timestamp_monotonicity
│   ├── timeline.py                    # Chronological merged access+error UTC timeline and silence gap detector
│   └── tests/                         # test_consistency.py, test_timeline.py
├── phase4_detect/                     # Phase 4: Feature extraction, rule detectors, Isolation Forest, evaluation & reporting
│   ├── README.md
│   ├── features.py                    # RequestFeatures extraction & per-IP ClientSummary aggregation
│   ├── detectors.py                   # Rule detectors for 5 attack classes: path_scan, sqli_like, traversal, brute_force, low_slow
│   ├── isolation_forest.py            # Pure-Python deterministic Isolation Forest anomaly scoring over 8 numerical features
│   ├── evaluate.py                    # Joins detections to labels.jsonl via trace_id (X-Lapa-Trace) for precision/recall/F1
│   ├── report.py                      # Re-verifies evidence & derived data and outputs report.json and report.md
│   └── tests/                         # test_phase4.py
├── cli/                               # Unified Typer CLI (`lapa`) connecting Phases 1–4
│   ├── README.md
│   ├── app.py                         # Commands: keygen, acquire, show, verify, parse, verify-derived, sql, analyze, detect, evaluate, report
│   └── tests/                         # test_cli.py + fixtures/phase2-demo
├── gui/                               # Desktop Tkinter/ttk GUI front-end driving the `lapa` CLI
│   ├── README.md
│   ├── lapa_gui.py                    # Main window, workspace/case/evidence header, 3-tab Notebook, live log, pipeline runner
│   ├── theme.py                       # Teal palette (#1a81a3–#2bc2c4), semantic status colors, font picker, clam styles
│   ├── runner.py                      # Tkinter-free CommandRunner (Popen + thread + Queue), SQL guard, JSON groupers
│   ├── aws.py                         # Tkinter-free EC2 temp inventory writer, .pem 0600 checker, AWS CLI & SSH command builders
│   ├── widgets.py                     # StatusChip, StepBlock, collapsible JsonViewer, ResultTable, Tooltip, ScrollablePage
│   ├── pages/                         # page_acquire.py (Tab 1), page_parse.py (Tab 2), page_analyze.py (Tab 3)
│   └── tests/                         # test_gui_core.py (11 unit tests for runner.py and aws.py)
├── lab/                               # Local Docker Compose target server (127.0.0.1:2222) & seeded traffic generator
│   ├── README.md
│   ├── docker-compose.yml             # Services: target (nginx + sshd) and traffic (generate.py)
│   ├── inventory.ini                  # Ansible inventory for 127.0.0.1:2222 as forensic-acq
│   ├── target/                        # Dockerfile, nginx.conf, sshd_lapa.conf, supervisord.conf, index.html, assets.css
│   ├── traffic/                       # generate.py, tamper.py
│   ├── out/                           # labels.jsonl
│   └── tests/                         # test_lab.py
└── dataset/                           # External test-server nginx access.log, client_hostname.csv, and ingest_dataset.py
```

### 1.2 Complete Tool Rename from `elijah` to `lapa` / `LAPA`
- **CLI executable**: `lapa` (`.venv/bin/lapa` or `python -m cli.app`).
- **Default signing key directory**: `~/.lapa/keys` (`ed25519.pem` with mode `0600`, `ed25519.pub` with mode `0644`).
- **Ansible variables & environment variables**: `lapa_case_id`, `lapa_staging_dir`, `lapa_log_directory`, `LAPA_LOG_GLOBS`, `LAPA_CONTEXT_COMMANDS`, `LAPA_RUN_LAB_TESTS`.
- **Nginx log format & trace header**: `log_format lapa`, `$http_x_lapa_trace` (from HTTP request header `X-Lapa-Trace`), user agent `lapa-synthetic-traffic/0.2`.
- **Provenance metadata**: `"tool": "lapa"` in `manifest.json`, `"name": "lapa"` in `derived_manifest.json`, and `"lapa_version"` in `report.json`.
- **Test fixtures**: Re-signed and re-derived `phase1_acquire/tests/fixtures/evidence_v1` and `cli/tests/fixtures/phase2-demo` with fresh Ed25519 signatures and SHA-256 digests matching the `"lapa"` metadata.

### 1.3 Desktop Tkinter/ttk GUI (`gui/`)
- **Strict Separation**: Uses only the Python standard library (`tkinter`, `subprocess`, `threading`, `queue`, `json`, `pathlib`, `tempfile`, `shutil`, `os`, `sys`, `stat`) and executes the `lapa` CLI as a subprocess. Imports **zero** LAPA phase modules.
- **Visual Theme**: Styled with the `clam` theme in the `#1a81a3` (primary) to `#2bc2c4` (accent) teal palette, paired with semantic status badges (`✓ Passed` `#2f9e44`, `▲ Warning` `#e8a317`, `✗ Failed` `#c92a2a`, `● Running…` `#1a81a3`, `○ Not run` `#5b7c85`).
- **Session Verification Gating**:
  - **Tab 1 (`1. Acquire & Verify`)**: Always accessible. Running **Verify** and passing unlocks Tab 2 for the active `(case_id, evidence_id)`.
  - **Tab 2 (`2. Parse & Query`)**: Locked until **Verify** passes. Running **Verify derived** and passing unlocks Tab 3.
  - **Tab 3 (`3. Analyze, Detect & Report`)**: Locked until **Verify derived** passes.
- **Decoupled Working Folder vs. Project Root**:
  - Users can set **Working folder** in the GUI header to any external directory (e.g. `~/Desktop/TEST`) so `evidence/`, `derived/`, `analysis/`, `bench/`, and `reports/` are written cleanly outside the source repository.
  - **Start lab** (`make lab-up`) and **Generate traffic** (`make traffic`) always execute with `cwd=project_root`, and relative lab paths (`lab/inventory.ini` and `lab/out/labels.jsonl`) automatically resolve against `project_root` when not present in the external Working folder.

---

## 2. Current Verification & Environment State

- **Python & Tkinter**: Python 3.14 (`.venv/bin/python`) with Homebrew `python-tk@3.14` (Tk 9.1).
- **Dependencies (`pyproject.toml`)**:
  - Runtime: `ansible-core>=2.19.15,<2.20`, `cryptography>=42,<47`, `pyyaml>=6,<7`, `typer>=0.12,<1`, `pyarrow==26.0.1`, `duckdb==1.5.6`
  - Dev: `mypy>=1.11,<2`, `pytest>=8,<10`, `ruff>=0.6,<1`
- **Test & Linter Status**:
  - `make test`: **166 passed, 1 deselected** (integration test is opt-in via `LAPA_RUN_LAB_TESTS=1`).
  - `make lint`: **Ruff** (`All checks passed!`) and **Mypy `--strict`** (`Success: no issues found in 85 source files`).

---

## 3. Specification for the Next Prototype: Independent Environment & Full AWS EC2 Integration

When building the next prototype (e.g., `proto4/`), copy `proto3/` into a new independent directory with its own `.venv` and dependencies, keeping all 4 phases, the `lapa` CLI, and the `gui/` intact. Then implement and verify the following **AWS EC2 components** so the GUI's **AWS EC2** mode works end-to-end against a real cloud server.

### 3.1 How Phase 1 (`lapa acquire`) Connects to a Target Server
Before provisioning an EC2 target, understand what `phase1_acquire/ansible/roles/acquire_nginx_logs/tasks/main.yml` enforces on the remote Linux host over SSH:

1. **Non-root SSH user**:
   - Task `Confirm the acquisition account is not root` runs `id -u` and **fails if UID is `0`**.
   - Direct root acquisition is forbidden. On EC2, use `ubuntu` (Ubuntu AMI), `ec2-user` (Amazon Linux / RHEL), `admin` (Debian), or a dedicated `forensic-acq` user.
2. **`adm` group membership**:
   - Task `Require adm-group membership` runs `id -nG` and asserts that **`adm` is in the user's groups**.
   - Task `Require a readable nginx log directory` runs `test -d /var/log/nginx && test -r /var/log/nginx`.
   - *Note for Amazon Linux / RHEL AMIs*: On Ubuntu/Debian, `/var/log/nginx` is owned by `www-data:adm` by default and the `adm` group exists out of the box. On Amazon Linux 2023, ensure the `adm` group exists (`sudo groupadd -f adm`), add the SSH user to `adm` (`sudo usermod -aG adm ec2-user`), and grant group read/execute on `/var/log/nginx` (`sudo chgrp -R adm /var/log/nginx && sudo chmod 750 /var/log/nginx && sudo chmod 640 /var/log/nginx/*.log`).
3. **Python 3.8+ on Target**:
   - Task `Require Python 3 on the target` runs `command -v python3`.
   - `phase1_acquire/collector.py` uses only the Python 3.8 standard library.
4. **Nginx Configuration Context (`nginx -T`)**:
   - `collector.py` runs `nginx -T`, `nginx -V`, `uname -a`, `date +%z`, `date +%Z`, and reads `/etc/os-release`, `/etc/logrotate.d/nginx`, `/etc/localtime`, and `/etc/timezone`.
   - If `nginx -T` requires root privileges or `/usr/sbin` is not in non-root `PATH`, `collector.py` automatically falls back to reading `/etc/nginx/nginx.conf` and `/etc/nginx/conf.d/*.conf` directly from disk (so ensure `/etc/nginx` files are world-readable `0644`, which is the default).

### 3.2 What the GUI Currently Does in AWS EC2 Mode (`gui/aws.py` & `gui/pages/page_acquire.py`)
In `gui/pages/page_acquire.py`, selecting **AWS EC2** reveals:
- **Instance ID** (`i-...`) + **Look up IP** button:
  Runs `aws ec2 describe-instances --instance-ids <id> --query Reservations[0].Instances[0].PublicIpAddress --output text` (with optional `--profile` and `--region`) and fills the **Public IP / Host** box.
- **Public IP / Host**, **SSH user** (default `ec2-user`), **SSH key (server access) `.pem`** file picker (warns if mode is not `0600`), **AWS profile**, **AWS region**, and **Remote Python path** (default `/usr/bin/python3`).
- **Test SSH** button:
  Runs `ssh -i <pem> -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new <user>@<host> true`.
- **Run Acquire** button:
  Calls `gui.aws.write_ec2_inventory(...)` to create a temporary mode-`0600` Ansible inventory file:
  ```ini
  [target]
  ec2-target ansible_host=<ip> ansible_port=22 ansible_user=<user> ansible_python_interpreter=/usr/bin/python3 ansible_remote_tmp=/tmp ansible_ssh_private_key_file=<absolute path to .pem> ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new' ansible_connect_timeout=10
  ```
  It passes `--inventory <temp_file>` to `lapa acquire --case-id <case> --store local`, and deletes `<temp_file>` when the subprocess finishes.

### 3.3 Tasks for the Next LLM to Complete in the New Prototype

#### Task 1: Independent Prototype Setup
- Create the new prototype folder with its own virtual environment (`python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'`) and verify `make test` and `make lint` pass out of the box.

#### Task 2: AWS EC2 Target Bootstrap Script / Infrastructure (`aws_lab/`)
Create an `aws_lab/` folder containing:
1. **`aws_lab/user_data_bootstrap.sh`** (can be passed as EC2 User Data when launching an Ubuntu 24.04 / Debian 12 / Amazon Linux 2023 instance, or run over SSH on an existing EC2 instance):
   - Installs `nginx` and `python3`.
   - Configures `/etc/nginx/nginx.conf` with the `lapa` log format so Phase 2 parses rich timing and trace fields (note that Phase 2 also supports standard `combined` logs if a stock nginx config is used):
     ```nginx
     log_format lapa '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                     'msec=$msec request_time=$request_time request_id=$request_id '
                     'connection=$connection trace_id=$http_x_lapa_trace';
     access_log /var/log/nginx/access.log lapa;
     ```
   - Configures permissions so the non-root SSH account (`ubuntu` or `ec2-user`) belongs to the `adm` group and can read `/var/log/nginx/access.log*` and `/var/log/nginx/error.log*` without `sudo`.
   - Updates `/etc/logrotate.d/nginx` (`create 0640 www-data adm` or `nginx adm`) so rotated logs stay readable by `adm`.
2. **`aws_lab/provision_ec2.py` or `aws_lab/README.md`**:
   - Step-by-step instructions or a helper CLI script using `aws ec2` to launch/configure a `t3.micro` / `t2.micro` test instance, open ports 22 (restricted to the analyst's IP) and 80, and apply `user_data_bootstrap.sh`.

#### Task 3: Capture AWS EC2 Instance Metadata (IMDSv2) During Acquisition
Currently, `phase1_acquire/orchestrator.py` writes an empty cloud block in `manifest.json`:
```python
"cloud": {"provider": "", "instance_id": "", "region": "", "account_id": ""}
```
Update `phase1_acquire/collector.py` and `phase1_acquire/orchestrator.py`:
- In `collector.py`, add an optional, non-fatal IMDSv2 probe (`http://169.254.169.254/latest/api/token` + `http://169.254.169.254/latest/dynamic/instance-identity/document` with a short `0.5s` timeout using `urllib.request`) that records `provider: "aws"`, `instance_id`, `region`, and `account_id` when running on an EC2 instance, and cleanly returns empty strings when running in the local Docker lab or non-AWS hosts.
- Populate `target["cloud"]` in `orchestrator.py` from `collector.get("cloud", ...)` and display the EC2 `instance_id` / `region` in the GUI's **Step 2 – Show manifest** table when present.

#### Task 4: Remote Traffic Generation & Evaluation Option for EC2 Testing
Currently, `lab/traffic/generate.py` hardcodes `ALLOWED_HOST = "target"` (`http://target/...`) so the Docker traffic container only talks to the Docker target container.
- Add a `--base-url` option to `lab/traffic/generate.py` (defaulting to `http://target` for Docker Compose compatibility, or accepting `http://<ec2-ip>` when explicitly passed from the host).
- In `gui/pages/page_acquire.py` (under the **AWS EC2** target panel), add a **"Send test traffic to EC2"** button that runs `python -m lab.traffic.generate --base-url http://<ec2_host> --output <working_folder>/labels.jsonl`.
- Allow **Step 3 – Evaluate** on Page 3 of the GUI to run whenever a valid `labels.jsonl` file is selected (even in EC2 mode if synthetic test traffic was sent to the EC2 instance).
