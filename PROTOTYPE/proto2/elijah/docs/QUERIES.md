# Query and verify a lab acquisition

From the project root, set `CASE` and `EVIDENCE_ID` to values from a verified acquisition. The examples use the default `evidence/` and `derived/` roots. Run `elijah verify` and `elijah verify-derived` before querying. The SQL command registers `access` and `error` as DuckDB views.

## Five queries

```sh
# Requests per minute in UTC
elijah sql "$CASE" "$EVIDENCE_ID" "SELECT substr(ts_utc, 1, 16) AS minute_utc, count(*) AS requests FROM access WHERE parse_ok AND ts_utc IS NOT NULL GROUP BY 1 ORDER BY 1"

# Status distribution
elijah sql "$CASE" "$EVIDENCE_ID" "SELECT status, count(*) AS requests FROM access WHERE parse_ok GROUP BY 1 ORDER BY 1"

# Most frequent paths returning HTTP 404
elijah sql "$CASE" "$EVIDENCE_ID" "SELECT path, count(*) AS requests FROM access WHERE parse_ok AND status = 404 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10"

# Unparsed rows and their source offsets
elijah sql "$CASE" "$EVIDENCE_ID" "SELECT artifact_path, stream, line_no, byte_offset, byte_length, parse_error FROM (SELECT artifact_path, stream, line_no, byte_offset, byte_length, parse_error, parse_ok FROM access UNION ALL SELECT artifact_path, stream, line_no, byte_offset, byte_length, parse_error, parse_ok FROM error) WHERE NOT parse_ok ORDER BY artifact_path, line_no"

# Original bytes for one traced request
ROW_JSON=$(mktemp)
elijah sql "$CASE" "$EVIDENCE_ID" "SELECT case_id, evidence_id, artifact_path, artifact_sha256_full, stream, line_no, byte_offset, byte_length, raw_bytes FROM access WHERE trace_id = 'lapa-phase2-demo' AND parse_ok ORDER BY artifact_path, line_no DESC LIMIT 1" > "$ROW_JSON"
```

## Trace the row to the original bytes

The final query returns raw bytes as base64. The following reads the stored artifact or its decompressed stream and checks the file hash, line number, offset, and raw bytes.

```sh
python - "$ROW_JSON" evidence <<'PY'
import base64
import gzip
import hashlib
import json
import sys
from pathlib import Path

query = json.loads(Path(sys.argv[1]).read_text())
row = dict(zip(query["columns"], query["rows"][0]))
path = Path(sys.argv[2]) / row["case_id"] / row["evidence_id"] / row["artifact_path"]
with path.open("rb") as source:
    assert hashlib.file_digest(source, "sha256").hexdigest() == row["artifact_sha256_full"]
opener = gzip.open if row["stream"] == "decompressed" else open
with opener(path, "rb") as source:
    offset = sum(len(source.readline()) for _ in range(row["line_no"] - 1))
    assert offset == row["byte_offset"]
    original = source.readline()
    assert len(original) == row["byte_length"]
    assert original == base64.b64decode(row["raw_bytes"]["$bytes_base64"])
print(f"Matched {path}, line {row['line_no']}, byte offset {offset}")
PY
```

## Check the failure paths

Use the same key pair from the lab run. The following copies both packages into a new scratch directory and flips one byte in each copy. Each of the three CLI calls should exit with status 1. The evidence verification and parse commands should name the failed artifact check. The derived verification should name `derived_file:parse_report.json`. The blocked output path should be absent.

```sh
SCRATCH=$(mktemp -d)
python - "$CASE" "$EVIDENCE_ID" "$SCRATCH" "$ROW_JSON" <<'PY'
import json
import shutil
import sys
from pathlib import Path

case, evidence_id, scratch, row_json = sys.argv[1:]
suffix = Path(case) / evidence_id
scratch = Path(scratch)
query = json.loads(Path(row_json).read_text())
row = dict(zip(query["columns"], query["rows"][0]))
for root, relative_path in (
    ("evidence", row["artifact_path"]),
    ("derived", "parse_report.json"),
):
    copy = scratch / root / suffix
    shutil.copytree(Path(root) / suffix, copy)
    path = copy / relative_path
    path.chmod(0o600)
    with path.open("r+b") as output:
        byte = output.read(1)
        output.seek(0)
        output.write(bytes([byte[0] ^ 1]))
PY

elijah verify "$CASE" --evidence-id "$EVIDENCE_ID" --evidence-root "$SCRATCH/evidence"
elijah parse "$CASE" --evidence-id "$EVIDENCE_ID" --evidence-root "$SCRATCH/evidence" --out "$SCRATCH/blocked"
test ! -e "$SCRATCH/blocked/$CASE/$EVIDENCE_ID"
elijah verify-derived "$CASE" --evidence-id "$EVIDENCE_ID" --derived-root "$SCRATCH/derived"
```

## Recorded live run

On 12 November 2026, the existing Docker nginx lab produced a verified schema-v2 package for case `C002`, evidence `d13a92df-dbbf-48dc-9784-59758a4c3456`. Acquisition reported zero collection errors. Both verification commands passed. The parse report showed 81 parsed lines, zero unparsed lines, and full byte coverage. The trace matched 223 bytes at offset 20022, line 79 of `artifacts/0000-access.log`.

Flipping one byte in a copied access log failed `artifact_prefix:artifacts/0000-access.log` and `artifact_full:artifacts/0000-access.log`. Parsing that copy exited with an error and published no output. Flipping one byte in a copied parse report failed `derived_file:parse_report.json`. Both original packages passed verification again after the checks.

The workspace copy is under `staging/phase2-demo/`, alongside its public key. For that copy, pass `--evidence-root staging/phase2-demo/evidence`, `--derived-root staging/phase2-demo/derived`, and `--public-key staging/phase2-demo/ed25519.pub` to the commands that accept them. Pass `staging/phase2-demo/evidence` in place of `evidence` in the trace snippet.
