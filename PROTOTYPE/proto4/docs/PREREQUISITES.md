# Preparing a server for acquisition

LAPA connects to an existing nginx server over SSH and copies its logs read-only. It never modifies permissions, installs packages, or runs `sudo` on the target. An administrator must ensure the prerequisites below are in place on the server before acquisition.

> **Important (incident-response warning):** Everything on this page is an **administrator action**, best done **before** an incident as part of routine server hardening and forensic readiness. Changing user groups, file permissions, or SSH keys on a server during or after an incident alters the target's state. If you must make any change during an incident, record the exact commands, timestamps, and administrator identity in your case notes.

## 1. Non-root SSH account in group `adm`

LAPA explicitly rejects direct `root` acquisition (`id -u` must not be `0`) and requires membership in group `adm` (`id -nG` must contain `adm`).

- **Recommended:** Create a dedicated read-only acquisition account (for example `forensic-acq`) with key-only SSH login and no `sudo` privileges:
  ```sh
  sudo groupadd -f adm
  sudo useradd --create-home --groups adm --shell /bin/bash forensic-acq
  ```
- **Alternative:** Add an existing non-root login account (`ubuntu`, `ec2-user`, `admin`) to `adm`:
  ```sh
  sudo groupadd -f adm
  sudo usermod -aG adm <ssh-user>
  ```
  Start a fresh SSH session after adding the user to `adm` so the new group membership takes effect.

## 2. Readable `/var/log/nginx` and log files

The acquisition account must be able to traverse `/var/log/nginx` and read at least one `access.log*` and `error.log*` file (active or rotated) without `sudo`.

- **Debian / Ubuntu (default):** Usually already ready — `/var/log/nginx` is typically `www-data:adm` (`0750`), logs are `0640` group `adm`, and `/etc/logrotate.d/nginx` already sets `create 0640 www-data adm`. Verify with `ls -ld /var/log/nginx /var/log/nginx/*.log*`.
- **Amazon Linux 2023 / RHEL / Rocky:** Group `adm` may not exist or own nginx logs by default, and `/var/log/nginx` is often owned by `nginx:nginx` (`0700` or `0750`). An administrator must configure group ownership and logrotate persistence:
  ```sh
  sudo groupadd -f adm
  sudo chgrp -R adm /var/log/nginx
  sudo chmod 0750 /var/log/nginx
  sudo chmod 0640 /var/log/nginx/*.log*
  ```
  In `/etc/logrotate.d/nginx`, ensure newly rotated files stay readable by `adm`, for example:
  `create 0640 nginx adm` (Amazon Linux / RHEL) or `create 0640 www-data adm` (Debian / Ubuntu).

## 3. Target software

- **`python3` 3.8 or newer** in the SSH user's `PATH`. LAPA's target collector (`phase1_acquire/collector.py`) uses only the Python 3.8 standard library; no pip packages are needed on the target.
- **`nginx`** installed (present in `PATH` or `/usr/sbin/nginx`). If `nginx -T` cannot run as the non-root user, the collector falls back to reading `/etc/nginx/nginx.conf`, `*.conf`, `conf.d/*`, and `sites-enabled/*` directly, so those configuration files should remain readable (`0644` is the default).

## 4. SSH key and network access

- Install the acquisition public key in `~/.ssh/authorized_keys` (`0600` inside `0700` `~/.ssh`) for the SSH user on the target.
- On the analyst workstation, protect the private `.pem` key with `chmod 0600 <key.pem>`.
- **EC2 Security Group:** Allow inbound **TCP port 22 (SSH) only from the analyst's IP address (`/32`)** — never `0.0.0.0/0`.

## 5. Analyst-side AWS permissions (optional cloud cross-check)

To record and cross-check AWS-reported instance identity (`--aws-instance-id`), the analyst's local AWS CLI profile needs only two read-only IAM actions:

- `ec2:DescribeInstances`
- `sts:GetCallerIdentity`

No write, modify, or delete permissions are needed or used by LAPA.

## 6. Verify readiness without writing evidence

Run the read-only preflight check before acquiring (or click **Check access** in the GUI):

```sh
lapa preflight --inventory <your-inventory.ini>
```

Preflight checks SSH connectivity, non-root UID, `adm` membership, `/var/log/nginx` readability, readable `access.log*` and `error.log*` matches, `python3 >= 3.8`, and `nginx` presence, printing remediation hints without modifying the server.
