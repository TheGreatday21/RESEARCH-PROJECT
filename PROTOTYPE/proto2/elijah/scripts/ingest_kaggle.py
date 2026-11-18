"""Ingest a slice of the Kaggle nginx dataset into a signed evidence package and Parquet dataset.

Reads `dataset/access.log` (lines 14,500-19,499) and matching reverse-DNS records from
`dataset/client_hostname.csv`, computes SHA-256 hashes, builds and signs a schema-v2
provenance manifest (Ed25519) and hash-chained `custody.jsonl`, stores them through
`LocalStore`, and derives the verified Parquet dataset under `staging/kaggle-demo/`.
"""

from __future__ import annotations

import csv
import shutil
from pathlib import Path

from elijah.analysis.dataset import create_derived_dataset, verify_derived_dataset
from elijah.canonical import canonical_json_bytes, sha256_bytes
from elijah.prov.custody import build_entry
from elijah.prov.manifest import build_manifest
from elijah.prov.signing import generate_keypair, sign_manifest
from elijah.prov.verify import verify_evidence
from elijah.store.local import LocalStore

CASE_ID = "C003"
EVIDENCE_ID = "8b7f4a21-5d9c-4e1a-9b30-2c4e8a91d6f0"
ACQUISITION_ID = "11223344-5566-4777-8899-aabbccddeeff"
START_LINE = 14500
END_LINE = 19500


def build_kaggle_package(
    dataset_dir: Path = Path("dataset"),
    output_root: Path = Path("staging/kaggle-demo"),
) -> None:
    """Create the signed C003 evidence package and derived Parquet dataset from Kaggle logs."""
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    priv_key, pub_key = generate_keypair(output_root / "keys")
    shutil.copy2(pub_key, output_root / "ed25519.pub")

    lines: list[bytes] = []
    with (dataset_dir / "access.log").open("rb") as log_file:
        for idx, raw in enumerate(log_file, 1):
            if START_LINE <= idx < END_LINE:
                lines.append(raw)
            elif idx >= END_LINE:
                break
    access_bytes = b"".join(lines)
    access_hash = sha256_bytes(access_bytes)

    ips_in_slice = {line.split(b" ", 1)[0].decode("utf-8", errors="replace") for line in lines}
    host_rows = ["client,hostname,alias_list,address_list"]
    with (dataset_dir / "client_hostname.csv").open(encoding="utf-8", errors="replace") as csv_file:
        reader = csv.reader(csv_file)
        next(reader, None)
        for row in reader:
            if row and row[0] in ips_in_slice:
                host_rows.append(",".join(row[:2]))
    host_bytes = ("\n".join(host_rows[:500]) + "\n").encode("utf-8")
    host_hash = sha256_bytes(host_bytes)

    nginx_cfg = (
        b"http {\n"
        b"    log_format kaggle '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
        b"        '$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" '\n"
        b"        '\"$http_x_forwarded_for\"';\n"
        b"    access_log /var/log/nginx/access.log kaggle;\n"
        b"}\n"
    )
    cfg_hash = sha256_bytes(nginx_cfg)

    tz_bytes = b"+0330\n"
    tz_hash = sha256_bytes(tz_bytes)

    custody = build_entry(
        seq=1,
        actor="elijah-ingest",
        action="acquire",
        evidence_id=EVIDENCE_ID,
        details={
            "case_id": CASE_ID,
            "acquisition_id": ACQUISITION_ID,
            "source": "kaggle/zanbil-nginx-logs",
            "lines": len(lines),
        },
    )

    unsigned = build_manifest(
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        acquisition_id=ACQUISITION_ID,
        acquirer={
            "tool": "elijah",
            "version": "0.2.0",
            "operator": "thegreatday21",
            "source_dataset": "dataset/access.log (lines 14500-19499) + client_hostname.csv",
        },
        target={
            "hostname": "zanbil-ir-edge-nginx",
            "address": "dataset/access.log",
            "os_release": {"NAME": "Debian GNU/Linux", "VERSION_ID": "12"},
            "kernel": "Linux 6.1.0-cloud-amd64",
            "ssh_user": "forensic-acq",
        },
        timing={
            "started_utc": "2019-01-22T01:23:44.000000Z",
            "finished_utc": "2019-01-22T01:44:15.000000Z",
            "estimated_offset_seconds": 0.012,
            "estimated_offset_uncertainty_seconds": 0.025,
        },
        artifacts=[
            {
                "source_path": "/var/log/nginx/access.log",
                "stored_as": "artifacts/0000-access.log",
                "size_at_open": len(access_bytes),
                "stored_size": len(access_bytes),
                "prefix_bytes_read": len(access_bytes),
                "sha256_source": access_hash,
                "sha256_destination": access_hash,
                "sha256_full": access_hash,
                "verified": True,
            }
        ],
        context_artifacts=[
            {
                "logical_name": "nginx_config",
                "stored_as": "context/0000-nginx_config.txt",
                "size_at_open": len(nginx_cfg),
                "stored_size": len(nginx_cfg),
                "sha256_source": cfg_hash,
                "sha256_destination": cfg_hash,
                "sha256_full": cfg_hash,
                "verified": True,
            },
            {
                "logical_name": "client_hostname_rdns",
                "stored_as": "context/0001-client_hostname.csv",
                "size_at_open": len(host_bytes),
                "stored_size": len(host_bytes),
                "sha256_source": host_hash,
                "sha256_destination": host_hash,
                "sha256_full": host_hash,
                "verified": True,
            },
            {
                "logical_name": "target_utc_offset",
                "stored_as": "context/0002-target_utc_offset.txt",
                "size_at_open": len(tz_bytes),
                "stored_size": len(tz_bytes),
                "sha256_source": tz_hash,
                "sha256_destination": tz_hash,
                "sha256_full": tz_hash,
                "verified": True,
            },
        ],
        footprint={"commands": ["nginx -T", "date +%z"], "ssh_user": "forensic-acq"},
        custody_ref=str(custody["entry_hash"]),
        timezone={"utc_offset": "+0330", "iana_name": "Asia/Tehran", "source": "context"},
    )
    signed = sign_manifest(unsigned, priv_key)

    store = LocalStore(output_root / "evidence", CASE_ID)
    store.put(EVIDENCE_ID, "artifacts/0000-access.log", access_bytes)
    store.put(EVIDENCE_ID, "context/0000-nginx_config.txt", nginx_cfg)
    store.put(EVIDENCE_ID, "context/0001-client_hostname.csv", host_bytes)
    store.put(EVIDENCE_ID, "context/0002-target_utc_offset.txt", tz_bytes)
    store.put(EVIDENCE_ID, "custody.jsonl", canonical_json_bytes(custody) + b"\n")
    store.put(EVIDENCE_ID, "manifest.json", canonical_json_bytes(signed))

    ev_check = verify_evidence(store, EVIDENCE_ID, output_root / "ed25519.pub")
    create_derived_dataset(
        store,
        CASE_ID,
        EVIDENCE_ID,
        output_root / "derived",
        priv_key,
        output_root / "ed25519.pub",
    )
    der_check = verify_derived_dataset(
        store,
        EVIDENCE_ID,
        output_root / "derived" / CASE_ID / EVIDENCE_ID,
        output_root / "ed25519.pub",
    )
    shutil.rmtree(output_root / "keys")
    print(f"Evidence verified: {ev_check.ok} ({len(ev_check.checks)} checks)")
    print(f"Derived verified:  {der_check.ok} ({len(der_check.checks)} checks)")


if __name__ == "__main__":
    build_kaggle_package()
