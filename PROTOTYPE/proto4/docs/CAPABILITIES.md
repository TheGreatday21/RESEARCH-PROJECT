# LAPA Capabilities, Trust Boundaries, and Known Limits

LAPA's job is to connect to an existing nginx server over SSH, copy its logs read-only, preserve them with verifiable provenance, and analyse them locally. It does **not** provision servers, install software on targets, modify target permissions, or send traffic in real investigations. Every claim LAPA makes is backed by data it actually recorded; where something cannot be proven, LAPA says so.

## What LAPA can show

- **Byte-for-byte acquisition integrity:** The files analysed are byte-for-byte what the target collector read at acquisition time (the source SHA-256 prefix hash computed on the target matches the destination prefix hash computed on the analyst's machine, and the complete stored copy matches `sha256_full`).
- **Post-acquisition tamper detection:** Any change to stored log artifacts, context artifacts, `manifest.json`, or `custody.jsonl` after acquisition is detectable by `lapa verify`, provided the Ed25519 signing key was not compromised.
- **Exact row-level provenance:** Every parsed row in `access.parquet` and `error.parquet` carries `artifact_path`, `line_no`, `byte_offset`, `byte_length`, and `raw_bytes`, tracing back to an exact byte range in an original log file with 100% byte coverage.
- **Consistency issues and web-attack patterns:** Seven consistency checks (clock skew, byte coverage, unparsed ratio, access/error line continuity, access/error timestamp monotonicity), a merged UTC timeline with silence-gap detection, five rule-based web-attack detectors (`path_scan`, `sqli_like`, `traversal`, `brute_force`, `low_slow`), and an unsupervised Isolation Forest anomaly score — with every detection pointing to its source line and byte offset.
- **Dual-source cloud instance identity:** On AWS EC2, LAPA records the cloud identity reported by the server itself (IMDSv2) alongside the identity reported independently by the AWS API (`ec2:DescribeInstances` and `sts:GetCallerIdentity` when `--aws-instance-id` is supplied), cross-checking instance ID, region, account ID, and SSH IP address and flagging any mismatch without blocking acquisition.

## What LAPA cannot show

- **Pre-acquisition authenticity:** That the logs were genuine before acquisition. If an attacker edited or deleted log entries on the server before LAPA connected, LAPA faithfully preserves the altered files.
- **Target honesty during collection:** That the target reported its own clock, cloud identity, or source file hashes honestly. The collector (`phase1_acquire/collector.py`) executes on the target host. Comparing the collector's self-hash against local `collector.py` catches accidental or in-transit changes, not a compromised target kernel or runtime.
- **Activity outside nginx logs:** Anything not recorded in nginx access or error logs. LAPA is not full cloud or host forensics (it collects no disk or memory images, CloudTrail logs, VPC flow logs, or OS audit logs).
- **Legal admissibility:** Admissibility depends on jurisdiction, investigative procedure, witness testimony, and legal review — not software output alone.
- **Precision, recall, or F1 on real traffic by themselves:** Those metrics require ground-truth labels, and a real server log has none. Accuracy figures come from either:
  1. **Labelled test/lab traffic** (`lapa evaluate --labels <file>`), which yields exact scores **for that labelled set only**; or
  2. **Manual analyst review** of a sample of detections and unflagged rows on a real log, which yields an estimated precision and an approximate recall on that sample (see `docs/EVALUATION.md`).
  Every reported figure states which source it came from. The Isolation Forest model is unsupervised and is evaluated the same way.

## Known limits (documented, not hidden)

1. **Unencrypted local signing key:** The Ed25519 private key (`~/.lapa/keys/ed25519.pem`, mode `0600`) is stored unencrypted on the same workstation as the evidence store. Anyone with control over that machine could generate a new key pair and re-sign altered evidence.
   - **Mitigation:** `lapa show`, the GUI's **Show manifest** panel, and the **Trust boundaries and limitations** section of every report print the manifest's signing `key_id`. The investigator should record that `key_id` outside the workstation (for example in case notes or an external ticketing system) immediately after acquisition.
2. **Acquisition record vs. full chain of custody (`custody.jsonl`):**
   - Inspecting the codebase shows that `phase1_acquire/store.py` (`LocalStore`) is strictly create-only and sets every stored file to mode `0444`.
   - `build_entry` (`phase1_acquire/custody.py`) is called **once** during Phase 1 acquisition (`phase1_acquire/orchestrator.py`, `seq=1`, `action="acquire"`), and `append_entry` is not called anywhere outside `phase1_acquire/tests/test_custody.py`.
   - Phases 2, 3, and 4 verify stored evidence and derived manifests, but **do not append entries to `custody.jsonl`** (nor write a separate downstream custody log).
   - Therefore, LAPA describes `custody.jsonl` accurately as an **acquisition record (one signed, hash-chained entry)** rather than a full multi-phase chain of custody.
3. **Small, non-zero target footprint:** Acquisition leaves normal SSH login records on the target, runs read-only shell/nginx/date commands and link-local IMDSv2 HTTP requests, and briefly writes and removes an Ansible temporary script directory under `ansible_remote_tmp`. Every target action is documented in `docs/TARGET_FOOTPRINT.md` and recorded in `manifest.json` under `footprint`.
4. **Offline IMDSv2 signature verification not implemented:** When IMDSv2 succeeds, the collector optionally stores the raw identity document (`imds_identity_document`) and PKCS7 signature (`imds_identity_pkcs7`) as context artifacts marked `verified_offline: false` so an analyst can verify them externally against AWS's public certificate. LAPA does not claim those signatures were cryptographically verified.
