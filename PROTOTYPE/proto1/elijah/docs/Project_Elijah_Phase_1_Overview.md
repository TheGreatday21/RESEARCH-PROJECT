---
title: "Project Elijah"
subtitle: "Phase 1 Implementation Overview"
author: "Read-only nginx log acquisition with signed provenance"
date: "11 November 2026  |  Version 0.1.0"
lang: en-GB
mainfont: "Avenir Next"
monofont: "Menlo"
fontsize: 10.5pt
geometry: "top=0.82in,bottom=0.82in,left=0.82in,right=0.82in"
colorlinks: true
linkcolor: "ElijahBlue"
urlcolor: "ElijahBlue"
toc-depth: 2
header-includes:
  - \usepackage{xcolor}
  - \usepackage{fancyhdr}
  - \usepackage{titlesec}
  - \usepackage{booktabs}
  - \usepackage{caption}
  - \usepackage{longtable}
  - \usepackage{array}
  - \usepackage[most]{tcolorbox}
  - \definecolor{ElijahNavy}{HTML}{12355B}
  - \definecolor{ElijahBlue}{HTML}{185A9D}
  - \definecolor{ElijahTeal}{HTML}{0E7C7B}
  - \definecolor{ElijahLight}{HTML}{EEF4FA}
  - \definecolor{ElijahGrey}{HTML}{52606D}
  - \pagestyle{fancy}
  - \fancyhf{}
  - \fancyhead[L]{\small\color{ElijahGrey}PROJECT ELIJAH}
  - \fancyhead[R]{\small\color{ElijahGrey}PHASE 1 IMPLEMENTATION OVERVIEW}
  - \fancyfoot[L]{\small\color{ElijahGrey}Version 0.1.0}
  - \fancyfoot[R]{\small\color{ElijahGrey}\thepage}
  - \renewcommand{\headrulewidth}{0.4pt}
  - \renewcommand{\footrulewidth}{0.2pt}
  - \titleformat{\section}{\Large\bfseries\color{ElijahNavy}}{\thesection}{0.7em}{}
  - \titleformat{\subsection}{\large\bfseries\color{ElijahBlue}}{\thesubsection}{0.6em}{}
  - \setcounter{secnumdepth}{2}
  - \renewcommand{\arraystretch}{1.25}
  - |-
      \renewcommand{\maketitle}{\begin{titlepage}\thispagestyle{empty}\vspace*{8mm}{\small\bfseries\color{ElijahTeal}TECHNICAL IMPLEMENTATION REPORT}\par\vspace{13mm}{\color{ElijahBlue}\rule{\textwidth}{2.2pt}}\par\vspace{13mm}{\Huge\bfseries\color{ElijahNavy}Project Elijah\par}\vspace{5mm}{\LARGE\color{ElijahBlue}Phase 1 Implementation Overview\par}\vspace{9mm}{\Large\color{ElijahGrey}Read-only nginx log acquisition\\with signed provenance\par}\vfill\begin{tcolorbox}[colback=ElijahLight,colframe=ElijahLight,borderline west={2pt}{0pt}{ElijahTeal},sharp corners,boxrule=0pt,left=4mm,right=4mm,top=3mm,bottom=3mm]\textbf{\color{ElijahNavy}Delivered foundation}\par\vspace{1.5mm}A working acquisition pipeline, canonical evidence model, Ed25519-signed manifests, hash-chained custody records, create-only local storage, a synthetic Docker lab, and automated verification.\end{tcolorbox}\vfill{\small\color{ElijahGrey}Implementation status: Phase 1 complete\par}\vspace{2mm}{\small\color{ElijahGrey}11 November 2026\hfill Version 0.1.0\par}\end{titlepage}}
---

# Executive summary

Project Elijah is a Python-based evidence acquisition system for nginx deployments. Its first phase establishes a controlled path from a Linux target to locally stored evidence while preserving information needed to detect later changes. It collects access logs, error logs, rotated files, and supporting system context without requiring root access or modifying the target logs.

The implemented pipeline combines Ansible-based remote collection, SHA-256 transfer verification, canonical JSON, Ed25519 manifest signatures, hash-chained custody records, and a create-only local evidence store. A Typer command-line interface exposes key generation, acquisition, verification, and evidence inspection.

A reproducible Docker lab supplies synthetic nginx traffic and labelled attack-like requests. The lab uses the researcher's existing Floci service and AWS CLI configuration for future S3-compatible work; Phase 1 itself stores evidence locally and never requires real AWS access.

\begin{tcolorbox}[colback=ElijahLight,colframe=ElijahLight,borderline west={2pt}{0pt}{ElijahBlue},sharp corners,boxrule=0pt]
\textbf{\color{ElijahNavy}Current outcome.} Phase 1 is implemented and validated: 70 unit tests pass, Ruff and strict mypy checks pass, Compose configuration validates, and the live Docker integration test successfully acquires evidence and detects bytewise tampering across artifacts, the signed manifest, and the custody chain.
\end{tcolorbox}

# Purpose and scope

## Problem addressed

Raw log copying alone does not answer important evidence-handling questions: which bytes were present when collection began, whether the transferred copy matches those bytes, what system context surrounded the acquisition, and whether stored evidence has changed since it was acquired. Project Elijah records these properties in a structured, verifiable evidence package.

## Phase 1 objectives

- Acquire nginx access and error logs, including rotated and gzip-compressed files.
- Use a dedicated, non-root acquisition account with read access through the `adm` group.
- Hash source bytes before transfer and verify the destination prefix after transfer.
- Preserve additional fetched bytes without truncating growing log files.
- Capture nginx, logrotate, operating-system, kernel, directory, and clock context.
- Produce deterministic JSON, signed manifests, and hash-chained custody records.
- Store evidence beneath `evidence/<case_id>/<evidence_id>/` without overwriting existing objects.
- Provide a synthetic lab, automated tests, and continuous-integration checks.

## Deliberately deferred

Log parsing, behavioural analysis, report generation, S3 evidence storage, and cloud metadata collection remain later-phase work. The CLI commands `parse`, `analyze`, and `report` are explicit stubs rather than incomplete hidden implementations.

# Architecture and acquisition flow

\begin{figure}[h]
\centering
\begin{tcolorbox}[colback=ElijahLight,colframe=ElijahLight,sharp corners,boxrule=0pt,width=\textwidth]
\small\ttfamily
Linux target\hfill Control host\hfill Evidence store\\[2pt]
nginx logs + context\hfill Ansible + collector\hfill artifacts/ + context/\\
read-only account\hfill hash + sign + chain\hfill manifest.json\\
forensic-acq : adm\hfill orchestration + CLI\hfill custody.jsonl
\end{tcolorbox}
\caption*{Evidence moves from left to right; verification reads the stored package without modifying it.}
\end{figure}

The acquisition sequence is:

1. **Preflight.** Ansible confirms SSH connectivity, target Python, log-directory readability, non-root UID, and `adm` group membership. Privilege escalation is disabled.
2. **Collection.** A standalone, standard-library-only collector runs on the target and emits one canonical JSON document describing artifacts and context.
3. **Transfer.** Ansible fetches each available source file into an indexed staging directory, preventing same-name files from overwriting one another.
4. **Verification.** The control host compares source and destination prefix hashes and records a separate full-file hash and stored size.
5. **Provenance.** The orchestrator builds a schema-versioned manifest, links a custody entry, and signs the canonical manifest with Ed25519.
6. **Storage.** Log bytes, context bytes, custody data, and the signed manifest are written through the evidence-store abstraction using create-only operations.
7. **Independent verification.** The verifier reloads stored bytes and reports structured check results for signatures, custody, presence, size, prefix hashes, and full hashes.

# What has been implemented

## Remote collector

The collector is compatible with Python 3.8+ and uses only the Python standard library. It treats compressed logs as opaque bytes and never discards content because it cannot be parsed.

For each artifact it records inode and device identifiers, file mode, ownership, timestamps, size at open, bytes read for the source prefix, source SHA-256, size after reading, growth, and whether the file changed during collection. Rotation, truncation, read failures, and stat-after failures are reported as collection errors rather than silently ignored.

Context collection includes:

- `nginx -T`, with direct configuration-file fallback;
- `nginx -V` version and build information;
- logrotate configuration;
- `uname -a` and `/etc/os-release`;
- sorted nginx log-directory statistics; and
- UTC clock readings before and after collection.

Configured commands execute without a shell. Command failures retain standard output and standard error and are marked unsuccessful.

## Transfer integrity

The required destination hash is calculated over exactly `size_at_open` bytes, allowing it to be compared with the source prefix captured before transfer. A second SHA-256 covers the complete fetched file, and `stored_size` records its actual length.

This design preserves trailing bytes written while acquisition is in progress. It does not truncate a growing file to make hashes match. Prefix mismatch, incomplete prefix reads, missing fetched files, and collection failures produce explicit verification states.

## Provenance and custody

Canonical JSON uses sorted keys, compact separators, UTF-8 encoding, and rejection of non-finite numbers. The manifest includes case, evidence, acquisition, acquirer, target, timing, artifact, context, footprint, and custody-reference fields.

The Ed25519 signature is calculated over the canonical manifest with the `signature` field omitted. Private keys are created non-overwriting with mode `0600`.

The custody log is canonical JSON Lines. Phase 1 creates one `acquire` entry per evidence ID, beginning with an all-zero previous hash. Each entry hash is:

```text
SHA256(ASCII(prev_hash) || canonical_json(entry_without_entry_hash))
```

Verification replays the chain and rejects malformed or blank records rather than skipping them.

## Evidence storage

`LocalStore` validates case identifiers, canonical UUIDv4 evidence identifiers, and traversal-free relative paths. New objects are opened exclusively, so an existing object cannot be overwritten. Successfully written objects and partially written new objects are set to mode `0444`; failed writes are not silently deleted.

The storage boundary is abstracted so a later S3-compatible implementation can use the same acquisition and verification model.

## Command-line interface

| Command | Phase 1 behaviour |
|:---|:---|
| `elijah keygen` | Generate a non-overwriting Ed25519 key pair. |
| `elijah acquire` | Run remote acquisition and store a signed evidence package. |
| `elijah verify` | Verify one evidence ID or every acquisition under a case. |
| `elijah show` | Display discovered evidence and manifest information. |
| `elijah parse` | Explicit later-phase stub. |
| `elijah analyze` | Explicit later-phase stub. |
| `elijah report` | Explicit later-phase stub. |

Verification emits deterministic JSON and returns a nonzero exit status when checks fail or artifacts remain unverified.

# Evidence package and integrity checks

A stored acquisition has the following logical structure:

```text
evidence/<case_id>/<evidence_id>/
├── artifacts/       acquired nginx log bytes
├── context/         captured configuration and system context
├── custody.jsonl    hash-chained acquisition record
└── manifest.json    signed provenance and artifact metadata
```

The structured verifier checks:

- manifest presence, JSON validity, schema version, and Ed25519 signature;
- custody presence, JSONL validity, hash linkage, and manifest reference; and
- every declared log and context artifact for presence, stored size, source/destination prefix hash, and complete-file hash.

Failures are named, for example `manifest_signature`, `custody_chain`, `artifact_prefix:<path>`, and `artifact_full:<path>`. This makes verification suitable for both human inspection and automation.

# Security and evidence-handling boundaries

## Controls in place

- Acquisition uses key-based SSH as `forensic-acq`, never direct root.
- The account relies on `adm` read access and does not use sudo.
- The collector does not rotate logs, signal processes, change clocks, or intentionally write target files.
- The traffic generator is confined to the Compose hostname `target`; arbitrary hosts, network-path URLs, and redirects are rejected.
- Tests use synthetic data and local files. They do not call real AWS.
- Lab SSH keys are separate from manifest-signing keys and are generated only for the local target container.

## Limits that must not be overstated

Signed provenance can detect changes **after acquisition**. It cannot prove that logs were authentic or untouched before collection; a privileged attacker could already have altered them. Consistency analysis and independent control-plane evidence are separate, later-phase concerns.

Local mode `0444` is an integrity aid, not true immutability. A sufficiently privileged user can change permissions and bytes, although cryptographic verification is designed to detect subsequent content changes. Ansible may create temporary collector and module files below the configured remote temporary directory; the acquisition footprint records this limitation even though every random temporary name is not exposed.

Production deployments should protect signing keys with a KMS or HSM rather than relying on a local private-key file.

# Synthetic lab and Floci

The Compose lab contains only the nginx target and synthetic traffic services. The target runs Debian 12, nginx, OpenSSH, Python 3.11, cron, logrotate, and supervisor. SSH is exposed on `127.0.0.1:2222`, and nginx is exposed on `127.0.0.1:8080`.

The traffic generator produced 74 requests per seeded run during validation: benign traffic shaped by a compressed daily-rate pattern plus labelled examples of path scanning, SQL-injection-like requests, path traversal, login brute force, and low-and-slow scanning. A synthetic upstream outage ensures error-log content.

The researcher's existing Floci instance remains external to Compose at `http://127.0.0.1:4566`. The project does not start, stop, expose, or reconfigure that service and does not alter its AWS CLI configuration. Phase 1 uses `LocalStore`; Floci is reserved for a later S3-compatible store without real AWS access.

# Using the project

## Installation and key generation

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
elijah keygen
```

## Lab, acquisition, and verification

```sh
make lab-up
make traffic

elijah acquire --inventory lab/inventory.ini --case-id C001 --store local
elijah verify C001
elijah show C001
```

To select a specific acquisition or key:

```sh
elijah verify C001 --evidence-id <uuid> --public-key ~/.elijah/keys/ed25519.pub
```

## Routine validation

```sh
make test
make lint
docker compose -f lab/docker-compose.yml config --quiet
make integration
```

The integration suite requires the prepared Docker lab and explicit opt-in through `ELIJAH_RUN_LAB_TESTS=1`; ordinary unit tests never start containers.

# Validation results

| Check | Result on 11 November 2026 |
|:---|:---|
| Unit tests | **70 passed** |
| Ruff linting | **All checks passed** |
| Strict mypy | **No issues in 22 source modules** |
| Compose validation | **Passed** |
| Live integration | **1 passed** |
| Synthetic traffic | **74 requests; 5 labelled attack classes** |
| Existing Floci service | **Healthy on port 4566; left untouched** |

The live integration test generated signing keys, acquired evidence from the running target, and passed baseline verification. It then flipped one byte in every stored log and context artifact, the manifest, and the custody record. Each mutation produced the expected failed check, and every original byte and mode was restored before the next check.

A live-run inventory issue was also corrected: spaces inside an Ansible INI Jinja expression caused the inventory to parse with no target hosts while returning success. The expression was fixed, and a regression test now confirms that `lab-target` is present in the parsed target group.

CI is configured for Python 3.11, dependency installation, Ruff, mypy, Compose validation, and unit tests. The Ansible playbook also passes syntax validation without initiating SSH.

# Repository map

| Location | Responsibility |
|:---|:---|
| `src/elijah/acquire/collector.py` | Standalone target-side collector. |
| `src/elijah/acquire/ansible/` | Playbook, role, defaults, and pipelining configuration. |
| `src/elijah/acquire/orchestrator.py` | Ansible execution, transfer checks, context preparation, signing, and storage. |
| `src/elijah/prov/` | Canonical manifests, Ed25519 signing, custody chaining, and verification. |
| `src/elijah/store/` | Evidence-store abstraction and create-only local implementation. |
| `src/elijah/cli.py` | Typer command-line interface. |
| `lab/` | Docker target, seeded traffic, and lab inventory. |
| `tests/unit/` | Unit, security-boundary, configuration, and regression tests. |
| `tests/integration/` | Opt-in live acquisition and bytewise tamper tests. |
| `docs/ASSUMPTIONS.md` | Resolved design decisions and limitations. |

# Next-phase foundation

Phase 1 provides the acquisition and verification boundary on which later work can build. Natural next steps are implementing read-only log parsing without discarding unparsed lines, adding analysis and reporting, introducing an S3-compatible store backed by the existing Floci service, collecting cloud metadata where authorised, and validating clock and rotation behaviour on a researcher-owned virtual machine.

These additions should preserve the current principles: explicit scope, read-only acquisition, deterministic evidence structures, non-destructive verification, synthetic test data, and clear separation between demonstrated integrity properties and assumptions.
