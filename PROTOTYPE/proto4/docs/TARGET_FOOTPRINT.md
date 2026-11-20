# Target Footprint

This document lists every action LAPA performs on a remote target server during `lapa acquire` and `lapa preflight`. Every item below is derived directly from the code in:

- `phase1_acquire/ansible/ansible.cfg`
- `phase1_acquire/ansible/acquire.yml`
- `phase1_acquire/ansible/roles/acquire_nginx_logs/defaults/main.yml`
- `phase1_acquire/ansible/roles/acquire_nginx_logs/tasks/main.yml`
- `phase1_acquire/ansible/preflight.yml`
- `phase1_acquire/collector.py`

LAPA's acquisition footprint is **small but not zero**. It never requests privilege escalation (`become: false`), never gathers Ansible facts (`gather_facts: false`), never modifies log or nginx files, and never installs packages.

## 1. SSH connection and Ansible settings (`ansible.cfg`)

Both `lapa acquire` and `lapa preflight` invoke `ansible-playbook` with the packaged `phase1_acquire/ansible/ansible.cfg` and `ANSIBLE_PIPELINING=True`:

- `pipelining = True` (under `[defaults]` and `[ssh_connection]`)
- `usetty = False` (keeps stderr separate from JSON stdout; avoids allocating a remote PTY)
- `host_key_checking = True` (overridden only where an inventory explicitly sets `ansible_ssh_common_args`, e.g., `accept-new` for EC2 or `no` for the local Docker lab)
- `retry_files_enabled = False`, `timeout = 30`
- Connects as the non-root `ansible_user` configured in the inventory.

**OS-level SSH side effects (unavoidable for any SSH connection):** Connecting over SSH causes the target's `sshd` and PAM/systemd subsystems to record login/session entries in system logs such as `/var/log/auth.log`, `/var/log/secure`, `journald`, `utmp`/`wtmp`, or `lastlog`.

---

## 2. Actions during `lapa acquire`

### 2.1 Preflight checks (`ansible.builtin.raw` — no remote files created)

Before running the collector, `roles/acquire_nginx_logs/tasks/main.yml` executes five raw shell commands over SSH:

1. `true` — confirm SSH connectivity
2. `command -v python3` — confirm `python3` exists
3. `test -d '/var/log/nginx' && test -r '/var/log/nginx'` — confirm log directory exists and is readable (using `lapa_log_directory`)
4. `id -u` — confirm the SSH account is not `root` (UID != `0`)
5. `id -nG` — confirm the SSH account belongs to group `adm`

These five commands are recorded in `run_metadata.json` (`preflight_commands`) and merged into `manifest.json` under `footprint.commands`.

### 2.2 Temporary script upload and execution (`ansible.builtin.script`)

Ansible runs the local `phase1_acquire/collector.py` via `ansible.builtin.script`:

- **Files created on target:** Ansible creates a random temporary directory under `ansible_remote_tmp` (e.g., `/tmp` when the inventory sets `ansible_remote_tmp=/tmp`, or `~/.ansible/tmp` by default when unset), copies `collector.py` into it, marks it executable, runs it with `LAPA_LOG_GLOBS` and `LAPA_CONTEXT_COMMANDS` in the environment, and deletes the temporary directory after execution.
- `run_metadata.files_created` (and `manifest.json` `footprint.files_created`) reports these Ansible-managed temporary files below `{{ ansible_remote_tmp | default('~/.ansible/tmp') }}`.
- `collector.py` itself creates **zero files** (`footprint.files_created: []`).

### 2.3 Commands, file reads, and HTTP requests inside `collector.py`

In order, `collector.py` performs the following read-only actions (every subprocess command and IMDSv2 HTTP request is appended to `footprint.commands` in `collector.json` and `manifest.json`):

1. **Before-clock command:** `["date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"]`
2. **Log discovery & hashing (Python stdlib, no subprocess):**
   - `glob.glob(...)` on `/var/log/nginx/access.log*` and `/var/log/nginx/error.log*` (or configured `LAPA_LOG_GLOBS`).
   - For each matched regular file: `os.stat`, `open(path, "rb", buffering=0)`, `os.fstat`, sequential prefix read up to `size_at_open` (1 MiB chunks) to compute SHA-256, and a second `os.stat` to detect growth, truncation, or inode rotation. Compressed `.gz` logs are hashed as opaque bytes without decompression.
3. **Context commands:**
   - `["nginx", "-T"]` — if this returns non-zero (for example, when non-root users cannot run `nginx -T`), `collector.py` falls back to directly reading `/etc/nginx/nginx.conf`, `*.conf`, `conf.d/*`, and `sites-enabled/*`.
   - `["nginx", "-V"]`
   - `["uname", "-a"]`
4. **Context file reads (Python stdlib, no subprocess):**
   - `/etc/logrotate.d/nginx`
   - `/etc/os-release`
   - Symlink resolution of `/etc/localtime` (`Path.resolve(strict=True)`)
   - `/etc/timezone` (only if present as a regular file)
   - Directory listing via `os.scandir("/var/log/nginx")` and `stat(follow_symlinks=False)` on each entry
5. **Timezone commands:**
   - `["date", "+%z"]`
   - `["date", "+%Z"]`
6. **IMDSv2 cloud metadata probe (link-local HTTP, unless `--no-imds`):**
   - `["HTTP", "PUT", "http://169.254.169.254/latest/api/token"]` (header `X-aws-ec2-metadata-token-ttl-seconds: 60`, timeout `0.8s`, proxy disabled)
   - If token succeeds: `["HTTP", "GET", "http://169.254.169.254/latest/dynamic/instance-identity/document"]` (header `X-aws-ec2-metadata-token: <token>`)
   - If identity document succeeds: `["HTTP", "GET", "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"]` (optional raw AWS signature captured for offline verification; non-fatal if absent)
   - On non-AWS hosts, timeouts, or HTTP errors, the probe returns empty cloud fields plus a short error string and never fails collection.
7. **After-clock command:** `["date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"]`
8. **Self-hash read:** Reads its own script file (`Path(__file__).read_bytes()`) to compute `collector_sha256`.

### 2.4 Log file transfer (`ansible.builtin.fetch`)

For each log artifact that did not produce a `collection_error`, `roles/acquire_nginx_logs/tasks/main.yml` runs `ansible.builtin.fetch` (`flat: true`) to copy the file from the target into the control host's staging directory (`<staging>/artifacts/<index>/<basename>`):

- Under `pipelining = True`, Ansible executes the underlying `slurp` module over SSH stdin without writing remote module files (if pipelining is unavailable for any reason, Ansible creates and removes temporary module files under `ansible_remote_tmp`, which is noted in `footprint.files_created`).
- Note that `ansible.builtin.fetch` reads the file a second time after `collector.py` finishes; any bytes appended by nginx between `collector.py` opening the file and `fetch` reading it are preserved in the stored copy, verified up to `size_at_open` against `sha256_source`, and hashed in full as `sha256_full`.

### 2.5 Control-host-only tasks (zero target footprint)

The remaining tasks (`Create staging directories`, `Save collector JSON`, `Save acquisition run metadata`, and optional AWS CLI `ec2 describe-instances` / `sts get-caller-identity` queries) run strictly on `localhost` (the analyst's machine).

---

## 3. Actions during `lapa preflight`

`lapa preflight --inventory <file>` runs `phase1_acquire/ansible/preflight.yml` with the exact same `ansible.cfg` (`pipelining = True`, `usetty = False`, `gather_facts: false`, `become: false`).

- **Files created on target:** **None** (all remote checks use `ansible.builtin.raw`; `collector.py` is not uploaded and no log files are fetched). Only normal OS-level SSH session logging occurs.
- **Commands run on target:**
  1. `true` (SSH connectivity)
  2. `id -u` (non-root check)
  3. `id -nG` (`adm` group check)
  4. `test -d '<log_dir>' && test -r '<log_dir>'` (log directory check)
  5. `sh -c '...' _ '<log_dir>'` counting total and readable `access.log*` files via POSIX `[ -f ]` / `[ -r ]`
  6. `sh -c '...' _ '<log_dir>'` counting total and readable `error.log*` files via POSIX `[ -f ]` / `[ -r ]`
  7. `sh -c '...'` locating `python3` via `command -v python3` and printing `sys.version_info >= (3, 8)`
  8. `sh -c 'PATH="$PATH:/usr/sbin:/sbin" command -v nginx'` (nginx binary check)
- **Files created on control host:** One temporary JSON probe file inside a `tempfile.TemporaryDirectory`, deleted immediately after `lapa preflight` prints its JSON output. Zero evidence is written.
