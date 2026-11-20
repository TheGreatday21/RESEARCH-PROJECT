# Common Utilities (`common/`)

Shared helpers used across all four phases:

- `canonical.py` — Deterministic UTF-8 JSON serialization (`canonical_json_bytes`) and streaming/prefix SHA-256 hashing (`sha256_bytes`, `hash_stream`, `hash_file`).
- `config.py` — Control-host `Settings` (default evidence root and `~/.lapa/keys` paths) and `validate_case_id` (`C001`–`C999`).
- `tests/` — Unit tests for canonical serialization, stream hashing, and configuration validation.
