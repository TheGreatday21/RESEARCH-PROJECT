# External Test Server Dataset (`dataset/`)

Real-world nginx access logs from an external test server alongside reverse-DNS hostname mappings:

- `access.log` — Raw nginx access log lines.
- `client_hostname.csv` — Client IP to reverse-DNS hostname table.
- `ingest_dataset.py` — Helper script that packages a slice of `dataset/access.log` into a signed Phase 1 evidence package and Phase 2 derived Parquet dataset.
