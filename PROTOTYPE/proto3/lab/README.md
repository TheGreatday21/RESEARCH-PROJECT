# Docker Lab & Traffic Generator (`lab/`)

Local loopback Docker Compose environment for generating nginx access/error logs and ground-truth attack labels:

- `docker-compose.yml` — Defines the `target` (SSH + nginx container) and `traffic` generator service.
- `inventory.ini` — Ansible inventory targeting `127.0.0.1:2222` as `forensic-acq`.
- `target/` — Dockerfile, `nginx.conf`, and `sshd_lapa.conf` for the target container.
- `traffic/generate.py` — Deterministic seeded traffic generator producing benign traffic and 5 attack classes with `X-Lapa-Trace` headers, writing ground-truth labels to `lab/out/labels.jsonl`.
- `tests/test_lab.py` — Unit tests for URL confinement, traffic generation, and Compose/nginx config.
