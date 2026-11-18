# LAPA

LAPA acquires nginx access and error logs over SSH using Ansible, records their provenance, and turns verified evidence into queryable Parquet tables. The command-line tool is named `elijah`.

Phase 1 provides acquisition, local evidence storage, a signed Ed25519 manifest, a hash-chained custody record, and structured verification. Phase 2 adds verified working copies, lossless parsing, signed derivatives, and DuckDB queries. Phase 3 adds log consistency checks and timeline reconstruction. Phase 4 adds rule-based attack detectors, scoring against the lab's ground-truth labels, and a forensic report. Everything uses the local evidence store. Floci, S3 Object Lock, AWS metadata, and disk and block storage are outside the current scope.

## Setup

The control host needs Python 3.11 or later. The Docker lab needs Compose v2. A Linux target needs Python 3.8 or later and a key-based acquisition account with read access through the `adm` group.

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
elijah keygen
```

By default, signing keys live in `~/.elijah/keys`. The private key has mode `0600`. Use a trusted copy of the public key when verifying evidence or derived data.

## Run the local lab

From the project root, start the lab if needed and send requests to its loopback nginx service. The third request exercises the lab's unavailable upstream and returns HTTP 502, which gives the parser an error log entry.

```sh
make lab-up
curl -sS -H 'X-Elijah-Trace: lapa-phase2-demo' http://127.0.0.1:8080/ -o /dev/null
curl -sS http://127.0.0.1:8080/assets/site.css -o /dev/null
curl -sS http://127.0.0.1:8080/upstream/lapa-phase2-demo -o /dev/null

elijah acquire --inventory lab/inventory.ini --case-id C001 --store local
```

Set `EVIDENCE_ID` to the UUID printed by `acquire`. Its response also lists collection errors and unverified artifacts. `show` prints the signed manifest with the target, timing, source-prefix and full stored hashes, and custody reference. The corresponding acquisition entry is in `custody.jsonl` alongside the manifest.

```sh
elijah show C001 --evidence-id "$EVIDENCE_ID"
elijah verify C001 --evidence-id "$EVIDENCE_ID"
elijah parse C001 --evidence-id "$EVIDENCE_ID"
elijah verify-derived C001 --evidence-id "$EVIDENCE_ID"
```

Evidence lives under `evidence/<case>/<evidence-id>/`. `parse` verifies the package, copies its signed inputs to a private temporary directory, and verifies the copy before reading from it. A failed check in the default workflow exits with the check name and leaves no dataset for that acquisition. The explicit `--allow-unverified` option emits a warning and marks the derivative as unverified evidence. A successful parse publishes `access.parquet`, `error.parquet`, `parse_report.json`, and `derived_manifest.json` together under `derived/<case>/<evidence-id>/`. To repeat a successful parse, choose another output root with `--out`.

Use `verify` to check the evidence signature, custody chain and stored artifacts. Use `verify-derived` to check the derived signature, output hashes, row counts, canonical row hash, and reference to the parent manifest. A successful derived verification covers the derivative and its manifest link. Run evidence verification separately to check the current source package.

See [the query and verification walkthrough](docs/QUERIES.md) to trace a row and reproduce the tamper checks.

## Analyze, detect, evaluate, and report

These commands read only verified derived data and write under their own roots, never inside `evidence/` or `derived/`. Each re-verifies the derived dataset against its evidence manifest first and exits with status 1, writing nothing, if a check fails.

```sh
elijah analyze C001 --evidence-id "$EVIDENCE_ID"     # consistency checks and timeline -> analysis/
elijah detect C001 --evidence-id "$EVIDENCE_ID"      # attack detectors -> analysis/.../detections.json
elijah evaluate C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl   # -> bench/
elijah report C001 --evidence-id "$EVIDENCE_ID" --labels lab/out/labels.jsonl     # -> reports/
```

`report` also re-verifies the evidence package itself, then re-runs every analysis step instead of trusting earlier output files, and writes `report.md` and `report.json`. `--labels` is optional there. `make demo-live` is the narrated, press-Enter-per-step walkthrough of the whole pipeline (add `--live-lab` via `make demo-live-lab` to start Docker and acquire first; `bash scripts/demo_live.sh --auto` skips the pauses). `make demo-phase4` runs just the four analysis commands against the recorded demo package in `staging/phase2-demo/`, writing to `/tmp/elijah-demo`. See [the analysis guide](docs/ANALYSIS.md) for what each check and rule does and what it cannot show.

## Interpreting the dataset

Every physical line yields a row, including unparsed lines. Rows carry the case ID, evidence ID, relative artifact path, full artifact SHA-256, line number, byte offset and length, and original bytes. For gzip logs, offsets refer to the decompressed stream. The parse report records per-file byte coverage and parsed and unparsed counts. It also names the access log format source and any UTC assumption for error timestamps. The parser uses the captured nginx configuration when it can derive a format and labels use of the lab-compatible fallback.

The source-prefix check covers the bytes present when the collector opened the file. The full stored hash also covers bytes appended before transfer completed. `beyond_prefix` marks rows that extend past the source prefix where the boundary is mappable. A null value marks an unmappable boundary. The evidence signature covers what was collected. It cannot establish authenticity before acquisition. Local read-only permissions limit accidental writes and do not enforce immutability. SSH protects the transfer. Apply any required encryption at rest to the destination storage.

## Checks

```sh
make test
make lint
make integration
```

The unit suite includes a signed schema-v1 package. The integration suite is opt-in and uses the loopback Docker lab. Docker results describe a container run. Clock and log rotation behavior on a real VM require separate validation.
