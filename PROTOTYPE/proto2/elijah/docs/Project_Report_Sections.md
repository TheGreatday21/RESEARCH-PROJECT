<!--
DRAFTING NOTES (delete before submission)
- Fill every [PLACEHOLDER] on the title page. I did not invent names, institution or dates.
- The README calls the project "LAPA"; the code, CLI and Phase 1 report call it "Project Elijah" (CLI: `elijah`).
  I used "Project Elijah". Change the title if "LAPA" is the official name.
- The research questions are my proposal, derived from what the prototype demonstrates. Adjust them to match
  your proposal or what your supervisors approved.
- Check the three references at the end against the original documents before citing them.
- Figures quoted come from the recorded lab run (case C002) and the 153-test unit suite, both reproducible
  with `make demo-live` and `make test`.
-->

# Title Page

## Project Elijah: Verifiable Acquisition and Analysis of Web-Server Logs for Cloud Forensics

*A prototype for signed-provenance evidence handling of nginx logs from Linux systems*

| | |
|:--|:--|
| **Student** | [Your full name] |
| **Student ID** | [ID number] |
| **Supervisor(s)** | [Supervisor name(s)] |
| **Programme / Department** | [Programme, department] |
| **Institution** | [Institution] |
| **Submission date** | [Date] |
| **Prototype version** | 0.2.0 |

### Abstract

Web-server logs are often the first and sometimes the only record of an attack on a cloud-hosted application, yet they are routinely collected with ordinary file copies that carry no proof of what was collected, when, by whom, or whether it has since been altered. This project presents Project Elijah, a command-line prototype that treats log collection as an evidence-handling problem. It acquires nginx access and error logs from a Linux target over SSH using a non-root, read-only account; hashes the source bytes before transfer and verifies them after; and stores the result as an evidence package containing an Ed25519-signed manifest and a hash-chained custody record. A verified working copy is then parsed losslessly into signed Parquet tables in which every physical log line is a row that can be traced back to its original byte offset. Analysis stages check the dataset's internal consistency, rebuild a timeline, run an unsupervised Isolation Forest anomaly detector alongside five classes of transparent attack rules, score those detectors against ground-truth labels from a synthetic Docker lab as well as a 5,000-request real-world nginx dataset from Kaggle, and generate a report that re-verifies every input. In the recorded lab run, all 44 evidence checks and 11 derived-data checks passed, a single flipped bit in a stored log or derived file was detected and named, and the detectors flagged all 23 labelled attack requests that could be joined to log rows with no false positives among 49 benign requests. On the 5,000-request Kaggle nginx dataset (`C003`), the 100-tree Isolation Forest ranked a real-world ThinkPHP/Yowai remote-code-execution exploit (`score = 0.8094`) as the #1 most anomalous request without supervision. The prototype detects changes made after acquisition; it cannot establish that logs were genuine before collection.

**Keywords:** cloud forensics, digital evidence, chain of custody, log integrity, provenance, nginx, Ed25519, Parquet, Isolation Forest, attack detection

---

# 1. Introduction and Problem Statement

## 1.1 Background

Applications increasingly run on virtual machines and containers operated through cloud providers. When such a system is attacked, investigators must reconstruct events from whatever evidence remains, and for web applications the web-server logs are frequently the primary source. Each access-log line records a client address, time, request and response status, so together the logs can show scanning, injection attempts and credential guessing.

Cloud environments make this evidence fragile. Instances are short-lived and can be terminated or rebuilt, log files rotate and are compressed, and a compromised host may allow an attacker to edit or delete entries. Investigators also rarely have unrestricted access: they typically hold a limited account on a system they do not control, and must avoid changing the system they are examining.

Good practice for handling digital evidence requires that collection be documented, minimally invasive and verifiable, and that a chain of custody show who handled the evidence and when. Guidance such as ISO/IEC 27037 and NIST SP 800-86 describes these expectations at a procedural level. In practice, however, log collection is often an ad hoc copy (`scp` or `rsync`) with a hash recorded by hand, if at all. Three gaps follow:

1. **No verifiable provenance.** A copied file does not prove which bytes existed when collection began, how they were transferred, or what system context (configuration, timezone, clock) is needed to interpret them.
2. **No tamper evidence after collection.** Without a signed record tied to the stored bytes, later modification of the copy may go unnoticed.
3. **Analysis disconnected from evidence.** Parsing and detection tools commonly emit results with no link back to the original bytes, and may silently discard lines they cannot parse.

## 1.2 Problem Statement

Investigators of cloud-hosted web applications lack a lightweight, reproducible way to acquire nginx logs so that (a) the acquisition is read-only and attributable, (b) any later change to the evidence is detectable, and (c) every analytical finding can be traced to the exact original bytes and re-verified before it is relied upon. This project designs, implements and evaluates a prototype that provides these properties, and states plainly what they do and do not prove.

## 1.3 Objectives

The overall aim is to build and evaluate a prototype pipeline from acquisition to reporting that preserves evidential integrity at every stage. The specific objectives are:

| ID | Objective |
|:--|:----------------------------------------------------------------|
| O1 | Acquire nginx access and error logs, including rotated and gzip-compressed files, from a Linux target using a non-root account, without modifying target logs. |
| O2 | Capture the system context needed to interpret the logs: nginx configuration, operating-system and kernel details, timezone, and clock readings. |
| O3 | Record provenance: source and destination hashes, an Ed25519-signed manifest, and a hash-chained custody record, stored without overwriting existing objects. |
| O4 | Provide independent verification that names every failed check, and demonstrate detection of single-bit tampering. |
| O5 | Convert verified evidence losslessly into a queryable form in which every log line, including unparsed lines, traces to its original byte offset. |
| O6 | Analyse the verified data for internal consistency, reconstruct a timeline, detect common web attacks with explainable rules, and evaluate the detectors against labelled synthetic traffic. |
| O7 | Generate a report that re-verifies its inputs and states the limitations of its findings. |

## 1.4 Research Questions

| ID | Research question | Addressed by |
|:--|:--------------------------------------------|:------------------------------|
| RQ1 | Can nginx logs and their interpretive context be acquired from a Linux target with a non-root, read-only account while recording enough provenance to verify the transfer? | O1–O3; acquisition design and live-lab acquisition |
| RQ2 | Can a signed manifest and hash-chained custody record make any change to stored evidence or derived data detectable and attributable to a specific check? | O3–O4; verification suite and tamper tests |
| RQ3 | Can raw logs be converted into a queryable dataset without discarding information, so that each analytical row remains traceable to the original bytes? | O5; byte-coverage and row-to-bytes trace |
| RQ4 | How well can transparent rule-based detectors and consistency checks identify attack activity in verified logs, and how should their performance be reported honestly given synthetic ground truth? | O6–O7; evaluation against lab labels |

## 1.5 Scope

**In scope.**

| Area | Coverage |
|:--------------|:---------------------------------------------------------------|
| Evidence source | nginx access and error logs, including rotated and gzip files, on Linux targets reachable over SSH |
| Access method | Ansible over key-based SSH, non-root account with read access through the `adm` group, privilege escalation disabled |
| Storage | Local, create-only evidence store (read-only file mode) |
| Provenance | SHA-256 hashing, Ed25519 signatures, hash-chained custody, canonical JSON |
| Derived data | Lossless parsing to Parquet, SQL queries with DuckDB |
| Analysis | Seven consistency checks, merged timeline with gap detection, unsupervised Isolation Forest anomaly detection (100 trees, 8 behavioral/structural features), five rule-based detector classes, evaluation against labelled synthetic traffic and real-world Kaggle nginx logs, report generation |
| Test environment | A synthetic Docker lab on the loopback interface with seeded, labelled traffic, plus a 5,000-request real-world nginx dataset from Kaggle (`C003`) |

**Out of scope for this stage.**

- Cloud provider control-plane evidence (for example load-balancer logs, flow logs, API audit trails) and cloud metadata collection.
- S3-compatible or object-lock storage; disk and memory acquisition.
- Scoring of `error.log` content and signing of analysis outputs.
- Validation on real cloud virtual machines, including real clock-drift and log-rotation behaviour.
- Live or real-world traffic: all data are synthetic, and no real cloud account is accessed.

**Threat model and limits.** The design detects modification of evidence *after* acquisition. It cannot prove that logs were authentic or untouched *before* collection: a privileged attacker who altered logs earlier would be invisible to signatures alone. Local read-only file modes reduce accidental changes but are not true immutability, and a production deployment would hold the signing key in a KMS or HSM rather than a local file. Detections are leads for examination, not proof of intent or success.

---

# 2. Methodology

## 2.1 Research Approach

The project follows an iterative design-and-evaluate approach. A prototype was built in four phases, each adding a capability that depends on the integrity guarantees of the previous one, and each validated with automated tests and a reproducible demonstration:

| Phase | Capability | Validation |
|:--|:-----------------------------------------|:------------------------------------|
| 1 | Acquisition, signed manifest, custody chain, local store, verification | Unit tests; live Docker acquisition; byte-flip tamper test on every stored object |
| 2 | Verified working copy, lossless parsing, signed Parquet derivatives, SQL queries | Row-to-bytes trace; derived-data verification; tamper tests |
| 3 | Consistency checks and timeline reconstruction | Unit tests; run on the recorded package |
| 4 | Feature extraction, detectors, evaluation, report | Unit tests including benign near-misses; evaluation against labels |

## 2.2 Design Principles

1. **Read-only acquisition.** The collector does not rotate logs, signal processes, change clocks or intentionally write to the target; privilege escalation is disabled.
2. **Deterministic evidence structures.** Canonical JSON (sorted keys, compact separators, UTF-8, no non-finite numbers) so that hashes and signatures are reproducible.
3. **Verify before use.** Every stage that reads evidence or derived data verifies it first and refuses to continue, writing nothing, if a check fails.
4. **Nothing silently discarded.** Every physical log line becomes a row, including lines that fail to parse; failures are reported, not dropped.
5. **Create-only storage.** Stored objects are opened exclusively and cannot be overwritten through the store.
6. **Explicit limits.** Demonstrated integrity properties are kept separate from assumptions, and limitations are written into the outputs.
7. **Synthetic data only.** Tests and evaluation never touch real systems or accounts.

## 2.3 Design Architecture

The system follows a three-stage **EXTRACT → LOAD → TRANSFORM** forensic architecture across the **target** (the AWS EC2 / Linux system being examined) and the **control host** (where the investigator runs the pipeline):

1. **EXTRACT (Target → SSH):** Acquires `access.log` and `error.log` plus system context (`nginx -T`, timezone, clocks) over SSH using a non-root `adm` account and computes pre-transfer SHA-256 hashes.
2. **LOAD (Control Host Verification & Immutable Store):** Verifies SHA-256 source/destination prefix and full hashes, signs the schema-v2 `manifest.json` with Ed25519, chains `custody.jsonl`, stores evidence in a create-only read-only store (`0444`), and stages a verified working copy for parsing.
3. **TRANSFORM (Parquet, Isolation Forest ML & Attack Timeline):** Converts logs losslessly into signed Parquet tables (`access.parquet`, `error.parquet`), runs a 100-tree **Isolation Forest** anomaly detector alongside rule-based detectors, reconstructs the chronological attack timeline, and emits a self-verifying forensic report.

```text
 TARGET (Linux, nginx)                CONTROL HOST (investigator)
 --------------------                 ------------------------------------------------
 nginx access/error logs   --SSH-->   Ansible role + standalone collector
 (rotated + gzip)           (non-root,  |  preflight, read-only collection, fetch
 context: config, OS,        adm group, v
 timezone, clock             no sudo)  Orchestrator: hash check, manifest, signature
 account: forensic-acq                   |
                                         v
                              evidence/<case>/<evidence-id>/        (signed, create-only)
                                artifacts/  context/  custody.jsonl  manifest.json
                                         |  verify -> working copy -> verify copy
                                         v
                              derived/<case>/<evidence-id>/         (signed Parquet)
                                access.parquet  error.parquet  parse_report.json
                                derived_manifest.json
                                         |  verify-derived (gate before every read)
                                         v
                       analysis/   bench/   reports/               (regenerable)
                       consistency, timeline, detections, evaluation, report
```

**Trust boundaries.** Evidence (`evidence/`) and derived data (`derived/`) are cryptographically signed. Analysis outputs (`analysis/`, `bench/`, `reports/`) are regenerable and unsigned, which is why the report command recomputes everything from verified inputs instead of reading earlier output files.

**Components.**

| Component | Responsibility | Location |
|:-----------------|:--------------------------------------------|:-------------------------------|
| Collector | Standalone, standard-library-only (Python 3.8+) program run on the target; records file metadata, source hashes, context and clocks | `src/elijah/acquire/collector.py` |
| Ansible role | Preflight checks, runs the collector, brackets it with control-host timestamps, fetches files to collision-free staging paths | `src/elijah/acquire/ansible/` |
| Orchestrator | Compares source and destination hashes, builds the manifest and custody entry, signs, stores | `src/elijah/acquire/orchestrator.py` |
| Provenance | Canonical JSON, Ed25519 signing, custody chain, structured verification | `src/elijah/canonical.py`, `src/elijah/prov/` |
| Store | Evidence-store interface and create-only local implementation | `src/elijah/store/` |
| Parser and dataset | Format derivation from captured nginx configuration, lossless parsing, signed Parquet, derived verification | `src/elijah/analysis/parse_nginx.py`, `formats.py`, `dataset.py` |
| Query | DuckDB views over the Parquet tables | `src/elijah/analysis/sql.py` |
| Analysis | Consistency checks, timeline, features, detectors, evaluation, report | `src/elijah/analysis/` |
| CLI | One command per stage | `src/elijah/cli.py` |
| Lab | Docker target and labelled traffic generator | `lab/` |

**Evidence package and provenance design.**

- **Manifest (schema v2).** Records case and evidence identifiers (UUIDv4), acquirer, target details, timing (control and target clock readings with an estimated offset and its uncertainty), timezone, every artifact (source path, size at open, source and destination SHA-256, full-file SHA-256, stored size, verification flag), context artifacts, footprint, and a reference to the custody entry. Schema v1 packages remain verifiable.
- **Signature.** Ed25519 over the canonical manifest with the signature field omitted.
- **Custody chain.** Canonical JSON Lines. Each entry hash is `SHA256(ASCII(prev_hash) || canonical_json(entry without entry_hash))`, starting from an all-zero previous hash.
- **Prefix and full hashes.** The required destination hash covers exactly `size_at_open` bytes so it can be compared with the source hash taken before transfer; a second hash and the stored size cover the whole fetched file. Bytes appended while a live log is being transferred are therefore preserved and still protected, and files are never truncated to force a match.

**Derived dataset design.** Each physical line (split on LF only) becomes one row carrying the case ID, evidence ID, artifact path, full artifact hash, line number, byte offset, byte length and the original bytes, alongside parsed fields. A `parse_report.json` records per-file byte coverage. The derived manifest is signed, links to the evidence manifest by SHA-256, and includes a canonical hash over every row.

## 2.4 Tools Used

| Category | Tool | Version / constraint | Role |
|:-----------|:----------------------|:-------------------|:--------------------------------------|
| Language | Python | 3.11 or later required; developed on 3.14; collector targets 3.8+ | Implementation |
| Remote automation | Ansible Core | 2.19.x (pinned below 2.20 for Python 3.11 support) | Preflight, collection, transfer over SSH |
| Cryptography | `cryptography` | 42 to 46 | Ed25519 signatures |
| CLI | Typer | 0.12 to below 1.0 | Command-line interface |
| Columnar storage | PyArrow | 26.0.1 | Parquet writing and reading |
| Query engine | DuckDB | 1.5.6 | SQL over Parquet |
| Configuration | PyYAML | 6.x | Test and configuration parsing |
| Quality | pytest, Ruff, mypy (strict) | pytest 8–9, Ruff 0.x | 153 unit tests, linting, static typing |
| CI | GitHub Actions | Python 3.11 | Lint, type-check, Compose validation, unit tests |
| Test target | Docker Compose | Compose v2 | Reproducible synthetic target |
| Target image | Debian 12, nginx, OpenSSH, cron, logrotate, supervisor | Debian 12-slim | Realistic log source, rotation and clock context |
| Demonstration | `jq`, `dd`, shell scripts | – | Readable output and byte-level trace |

## 2.5 Data Collection

### 2.5.1 Live acquisition (what is collected, and how)

**Access and authorisation.** The acquisition account (`forensic-acq`) authenticates by SSH key, is not root, and reads logs through membership of the `adm` group. The Ansible role fails if the account is root or lacks `adm` access.

**Artifacts.** Current and rotated nginx access and error logs, including gzip files, which are treated as opaque bytes and never discarded because they cannot be parsed. For each file the collector records inode and device, mode, ownership, timestamps, size when opened, bytes read for the source prefix, the source SHA-256, size after reading, growth, and whether the file changed during collection. Rotation, truncation and read failures are reported as collection errors rather than ignored.

**Context.** Needed to interpret the logs later:

- nginx configuration (`nginx -T`, with a direct-file fallback) and build information (`nginx -V`);
- logrotate configuration;
- kernel and operating system (`uname -a`, `/etc/os-release`);
- sorted statistics of the log directory;
- timezone: UTC offset and abbreviation, the resolved `/etc/localtime` target, and `/etc/timezone` where present;
- target clock readings in UTC before and after collection, bracketed by control-host timestamps to estimate the clock offset and its uncertainty.

Commands run without a shell, and failed commands keep their output and are marked unsuccessful.

### 2.5.2 Synthetic dataset for evaluation

Real attack data with known ground truth is rarely available and cannot be shared, so evaluation uses a synthetic lab.

- **Target.** A Debian 12 container running nginx and OpenSSH, bound to the loopback interface only (SSH on port 2222, HTTP on 8080), with a custom log format that adds `$msec`, `$request_time`, `$request_id`, `$connection` and the trace header.
- **Traffic generator.** Seeded (default seed 20261111) and confined to the Compose hostname of the target; arbitrary hosts, network-path URLs and redirects are rejected. A default run sends 74 requests: 49 benign requests, including one synthetic upstream outage that produces error-log content, and 25 labelled attacks.
- **Attack classes.** Path scanning (6), SQL-injection-like requests (3), directory traversal (3), login brute force (8 POSTs) and a low-and-slow numbered scan (5).
- **Ground truth.** Each request carries a unique `X-Elijah-Trace` header that nginx writes to the log. The generator saves a JSONL label file mapping each trace ID to its class. Labels are lab ground truth and are not signed evidence.
- **Recorded dataset.** The demonstration package (case C002) was acquired from this lab on 12 November 2026: 81 log lines (79 access, 2 error), 20,777 bytes, zero unparsed lines, full byte coverage, and a measured target/control clock offset of 0.054 s (±0.092 s).
- **Ethics and safety.** All traffic is synthetic and confined to the local lab; no real cloud account, service or user data is accessed. Signing keys for the manifests are separate from the lab's SSH keys.

## 2.6 System Flow

The pipeline has nine stages. The command named in each stage is the one a user runs; each automates the listed actions and, from stage 3 onward, begins with a verification gate.

| # | Stage (command) | Input | Actions | Output |
|:--|:----------------|:-----------|:--------------------------------------------|:--------------------|
| 1 | Key generation (`keygen`) | – | Create a non-overwriting Ed25519 key pair, private key mode 0600 | Signing keys |
| 2 | Acquisition (`acquire`) | Target over SSH | Preflight; record control time; run read-only collector; fetch files; compare source and destination hashes; build and sign manifest; write custody entry; store create-only | `evidence/<case>/<id>/` |
| 3 | Verification (`verify`) | `evidence/` | Check manifest, signature, custody chain and reference, and for every artifact its presence, size, prefix hash and full hash | Named pass/fail checks (44 on the recorded package) |
| 4 | Parsing (`parse`) | `evidence/` | Verify evidence; copy to private temporary directory; verify the copy; parse losslessly; write Parquet; sign derived manifest; publish atomically | `derived/<case>/<id>/` |
| 5 | Derived verification (`verify-derived`) | `derived/` | Check derived signature, file hashes, row counts, canonical row hash, link to evidence manifest | Named pass/fail checks (11) |
| 6 | Query (`sql`) | `derived/` | Run DuckDB SQL over `access` and `error` views; trace a row to its bytes by file, offset and length | Query results |
| 7 | Analysis (`analyze`, `detect`) | `derived/` | Verify derived data; run consistency checks; build timeline; extract features; run detectors | `analysis/` |
| 8 | Evaluation (`evaluate`) | `derived/`, labels | Verify derived data; join detections to labels by trace ID; compute metrics; account for unjoined rows | `bench/` |
| 9 | Report (`report`) | `evidence/`, `derived/` | Re-verify evidence and derived data; recompute checks, timeline and detections; render Markdown and JSON | `reports/` |

```text
keygen -> acquire -> verify -> parse -> verify-derived -> sql
                                              |
                                              +--> analyze / detect --> evaluate --> report
 (every stage after parse refuses to read unverified data and writes nothing on failure)
```

### 2.6.1 Analysis and evaluation methods

**Consistency checks.** Seven checks grade the dataset as pass, warn or fail:

| Check | Pass | Warn | Fail |
|:--------------------------|:----------------|:-----------------|:-----------------|
| Clock skew | under 5 s offset | 5 s or more, or timing missing | 30 s or more |
| Byte coverage | every stream byte maps to a row | field absent | coverage false |
| Unparsed ratio | 5% or fewer lines unparsed | above 5% | – |
| Line continuity (access, error) | gapless line numbers per artifact | – | gap or missing file |
| Timestamp monotonicity (access, error) | never decreasing within an artifact | retrograde jump | missing file |

**Timeline.** Access and error rows with a parsed UTC timestamp are merged and sorted deterministically, and silent intervals longer than a threshold (default 60 s) are reported as gaps. A gap is a lead, not a verdict: it may reflect an idle server or removed lines.

**Detectors.** Five transparent rules, with thresholds recorded in every output:

| Class | Rule |
|:-------------|:-----------------------------------------------------------------|
| Path scan | Probes of VCS metadata, `.env`, admin consoles, `server-status`, backup archives |
| SQL-injection-like | `UNION SELECT`, numeric tautologies, stacked statements, time-delay functions, `information_schema`, quoted comment terminators |
| Traversal | `../` or `..\` after one or two rounds of percent-decoding; requests for system secret files |
| Brute force | Five or more POSTs to one login-like path from one client within 60 s |
| Low and slow | Four or more distinct numbered resources returning 401, 403 or 404 from one client within one hour |

**Evaluation.** Detections are joined to labels by trace ID. Reported metrics are precision, recall, F1 and accuracy, both for attack versus benign and per class. Rows that cannot be joined are accounted for separately rather than folded into the scores: labels with no joined row, and rows logged without a trace ID (for example, requests nginx rejected with HTTP 400 before reading headers) together with how many of those a detector still flagged.

**Report.** Combines integrity status, acquisition facts, dataset coverage, consistency results, timeline summary, per-client summary, findings with row references, optional evaluation and a fixed limitations section.

## 2.7 Validation Strategy

| Method | What it validates |
|:--------------------|:----------------------------------------------------------------|
| 153 unit tests | Canonical JSON, signing, custody chain, manifest schemas (including a signed v1 fixture), local store, collector, orchestrator, Ansible role syntax, parser, derived datasets, consistency checks, timeline, detectors (including benign near-misses), evaluation, report and CLI behaviour |
| Opt-in integration test | Live acquisition from the Docker lab, followed by a one-byte mutation of every stored artifact, the manifest and the custody record, each expected to fail its named check, with original bytes and modes restored after each mutation |
| Tamper demonstration | One flipped bit in a copy of a stored log and in a copy of the derived parse report, with the analysis commands expected to refuse to run |
| Continuous integration | Ruff, strict mypy, Compose validation and the unit suite on Python 3.11 |
| Row-to-bytes trace | A parsed row's file, offset and length retrieve the identical bytes from the stored artifact |

**Threats to validity.** The evaluation uses one seeded synthetic workload, and the detector rules were written with knowledge of its attack types, so high scores demonstrate correct implementation rather than generalisation. The lab is a container, so clock and log-rotation behaviour on real virtual machines is untested. The ground-truth join depends on a header that nginx cannot log for requests it rejects early. These limits are carried into the results discussion rather than hidden.

---

### References to confirm before citing

1. ISO/IEC 27037:2012. *Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence.*
2. Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating Forensic Techniques into Incident Response* (NIST Special Publication 800-86).
3. Josefsson, S., & Liusvaara, I. (2017). *Edwards-Curve Digital Signature Algorithm (EdDSA)* (RFC 8032).
