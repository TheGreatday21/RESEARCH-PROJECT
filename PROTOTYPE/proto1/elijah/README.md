# Project Elijah — Phase 1

Project Elijah acquires nginx access and error logs from a Linux target through Ansible, records signed Ed25519 provenance, appends a hash-chained custody record, and stores the resulting evidence in a local read-only evidence directory. Phase 1 also provides a synthetic Docker lab. Parsing, analysis, reporting, S3 storage, and cloud metadata are reserved for later phases.

## Integrity boundary

Provenance demonstrates whether acquired bytes have changed **since acquisition**. It cannot establish that logs were untouched before acquisition; an attacker with root access could have altered them. Later consistency checks and control-plane corroboration are intended to address that separate risk. The local store's read-only permissions are not true immutability.

The collector reads files and executes only the configured description commands. It does not rotate logs, signal processes, change the target clock, or intentionally write to the target filesystem. Ansible can create temporary module files, which are recorded in the acquisition footprint.

## Requirements

- Control host: Python 3.11, Ansible Core 2.19, and the Python dependencies in `pyproject.toml`.
- Target: Linux, Python 3.8+, key-based SSH as `forensic-acq`, read access through the `adm` group, and no sudo requirement.
- Lab: Docker with Compose v2.

No component requires real AWS credentials or network access to AWS. Tests use local files and the optional Docker lab only.

## Install

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Create signing keys. The private key is written with mode `0600` under `~/.elijah/keys` by default. A production deployment should use a KMS or HSM instead of a local private-key file.

```sh
elijah keygen
```

## Run the synthetic lab

```sh
make lab-up
make traffic
```

The lab exposes SSH on `127.0.0.1:2222` and nginx on `127.0.0.1:8080`. Its SSH key is generated only for the container. Use your existing Floci instance at `http://127.0.0.1:4566` with its existing AWS CLI configuration; the lab does not start, stop, or reconfigure Floci. Phase 1 uses the local evidence store, with Floci reserved for the Phase 2 S3-compatible store without real AWS access. A container is not a VM: clock behavior, logrotate behavior, and cloud metadata must still be validated in a run on a real VM owned by the researcher.

## Acquire and verify

From the repository root:

```sh
elijah acquire --inventory lab/inventory.ini --case-id C001 --store local
elijah verify C001
elijah show C001
```

Evidence is stored below `evidence/<case_id>/<evidence_id>/`. Log files are under `artifacts/`, captured context is under `context/`, and `manifest.json` contains the inline signature and custody reference. `custody.jsonl` contains the acquisition entry.

To select one acquisition or use explicit keys:

```sh
elijah verify C001 --evidence-id <uuid> --public-key ~/.elijah/keys/ed25519.pub
```

`elijah parse`, `elijah analyze`, and `elijah report` intentionally print `not implemented in this phase`.

## Tests

```sh
pytest tests/unit
ruff check .
mypy src/elijah
make integration
```

The integration test is opt-in through `ELIJAH_RUN_LAB_TESTS=1`; ordinary unit tests never start containers or call AWS. See `docs/ASSUMPTIONS.md` for resolved ambiguities.
