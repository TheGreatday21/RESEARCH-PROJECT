# Phase 1 assumptions

- **Ansible version:** The specification requests Python 3.11 and the current stable Ansible Core. Ansible Core 2.22.0 requires Python 3.13 or newer, so the project pins `ansible-core>=2.19.15,<2.20`, the newest Python 3.11-compatible release line identified from PyPI metadata on 11 November 2026.
- **Full-artifact verification:** `sha256_destination` is the required prefix hash over `size_at_open` bytes. An additional `sha256_full` field and `stored_size` cover the complete fetched file so changes after the source prefix are also detected during verification; fetched files are never truncated.
- **Custody hashing:** `entry_hash` is SHA-256 over the ASCII bytes of the 64-character `prev_hash`, followed immediately by the canonical JSON bytes of the entry without `entry_hash`.
- **Custody scope:** Phase 1 writes one `acquire` entry per evidence ID. Verification is read-only and does not append a `verify` entry because the local evidence files are read-only after storage.
- **Context bytes:** Captured text is decoded as UTF-8 with replacement for invalid sequences, then encoded as UTF-8 for hashing and storage. Command failures retain both stdout and stderr and are marked unsuccessful rather than silently omitted.
- **Target footprint:** Ansible does not expose every random temporary filename created by its script and module wrappers. The footprint records the configured remote temporary directory, the collector invocation, and the fact that Ansible-managed temporary files are removed after execution.
- **Local storage:** Read-only mode bits are an integrity aid, not true immutability. A user with sufficient privileges can change them; cryptographic verification detects later content changes.
- **Evidence discovery:** `verify CASE_ID` verifies every evidence ID below that case unless `--evidence-id` is supplied. `show CASE_ID` uses the same discovery rule.
- **Lab keys:** `make lab-up` generates a dedicated, ignored SSH key pair for the local container only. It is separate from the manifest-signing key pair.
- **Synthetic data:** The lab traffic generator only connects to the Compose service hostname `target`; arbitrary hosts and URLs are rejected.

# Phase 3 and 4 assumptions

- **Output roots:** Phase 3 and 4 write under `analysis/`, `bench/`, and `reports/` rather than inside `derived/`, which is published atomically and covered by a signed manifest. These outputs are regenerable and unsigned.
- **Report trust:** `report` re-verifies and recomputes everything; it does not read earlier files from `analysis/`.
- **Warn is not pass:** `analyze` exits 1 on any non-pass check so warnings reach automation.
- **Memory:** detectors load parsed access rows into memory. This suits lab-sized logs; very large logs need a streaming rewrite.
- **Labels:** lab labels are unsigned ground truth. Scores are for the synthetic lab only.
