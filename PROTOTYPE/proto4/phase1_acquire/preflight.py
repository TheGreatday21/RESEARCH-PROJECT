"""Read-only target preflight checks using the same Ansible config as acquire."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.canonical import canonical_json_bytes


@dataclass(frozen=True)
class PreflightCheck:
    """Describe one read-only preflight check, its result, and any admin hint."""

    name: str
    passed: bool
    message: str
    hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable check entry."""
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "hint": self.hint,
        }


@dataclass(frozen=True)
class PreflightResult:
    """Aggregate all read-only preflight checks without writing evidence."""

    checks: tuple[PreflightCheck, ...]

    @property
    def ok(self) -> bool:
        """Return True only when every preflight check passed."""
        return bool(self.checks) and all(check.passed for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-serializable preflight summary."""
        return {
            "ok": self.ok,
            "checks": [check.to_dict() for check in self.checks],
        }


def _probe_rc(probes: Mapping[str, Any], key: str) -> int:
    entry = probes.get(key)
    if not isinstance(entry, Mapping):
        return 1
    raw = entry.get("rc", 1)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 1


def _probe_stdout(probes: Mapping[str, Any], key: str) -> str:
    entry = probes.get(key)
    if not isinstance(entry, Mapping):
        return ""
    return str(entry.get("stdout", "")).strip()


def _parse_count_pair(stdout: str) -> tuple[int, int]:
    parts = stdout.split()
    if len(parts) < 2:
        return 0, 0
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return 0, 0


def _evaluate_log_glob(
    probes: Mapping[str, Any],
    *,
    probe_key: str,
    check_name: str,
    glob_label: str,
    log_directory: str,
) -> PreflightCheck:
    rc = _probe_rc(probes, probe_key)
    found, readable = _parse_count_pair(_probe_stdout(probes, probe_key))
    pattern = f"{log_directory}/{glob_label}"
    if rc == 0 and readable > 0:
        return PreflightCheck(
            name=check_name,
            passed=True,
            message=f"{readable} of {found} matched {glob_label} file(s) readable",
            hint="",
        )
    if found == 0:
        return PreflightCheck(
            name=check_name,
            passed=False,
            message=f"no files matched {pattern}",
            hint=(
                f"Confirm nginx is configured to write {glob_label} under {log_directory} "
                "and that the directory is readable by group adm."
            ),
        )
    return PreflightCheck(
        name=check_name,
        passed=False,
        message=f"found {found} file(s) matching {pattern}, but 0 are readable by this user",
        hint=(
            f"Have an administrator ensure {pattern} is owned by group adm with mode 0640 "
            "(and update /etc/logrotate.d/nginx to use 'create 0640 ... adm')."
        ),
    )


def evaluate_preflight_probes(
    probes: Mapping[str, Any],
    *,
    log_directory: str = "/var/log/nginx",
) -> PreflightResult:
    """Convert raw Ansible probe outputs into structured checks with admin hints."""
    checks: list[PreflightCheck] = []

    # 1. SSH connectivity
    ssh_ok = _probe_rc(probes, "ssh_connect") == 0
    checks.append(
        PreflightCheck(
            name="ssh_connect",
            passed=ssh_ok,
            message="SSH connection succeeded" if ssh_ok else "SSH connection failed",
            hint=""
            if ssh_ok
            else (
                "Check the host IP/port, security group inbound rule for port 22, "
                "SSH username, and .pem key permissions (chmod 0600)."
            ),
        )
    )

    # 2. Non-root account
    uid_rc = _probe_rc(probes, "uid")
    uid_text = _probe_stdout(probes, "uid")
    non_root_ok = uid_rc == 0 and bool(uid_text) and uid_text != "0"
    checks.append(
        PreflightCheck(
            name="non_root_user",
            passed=non_root_ok,
            message=(
                f"Connected as non-root user (uid={uid_text})"
                if non_root_ok
                else f"Connected as root (uid={uid_text or 'unknown'}); direct root is disallowed"
            ),
            hint=""
            if non_root_ok
            else (
                "Connect with a non-root SSH account (such as a dedicated forensic-acq user, "
                "ubuntu, or ec2-user) rather than root."
            ),
        )
    )

    # 3. adm group membership
    groups_rc = _probe_rc(probes, "groups")
    groups = _probe_stdout(probes, "groups").split()
    adm_ok = groups_rc == 0 and "adm" in groups
    checks.append(
        PreflightCheck(
            name="adm_group",
            passed=adm_ok,
            message=(
                "Account belongs to the adm group"
                if adm_ok
                else f"Account is not in group adm (groups: {', '.join(groups) or 'none'})"
            ),
            hint=""
            if adm_ok
            else (
                "Have an administrator add the acquisition user to group adm "
                "(e.g. 'sudo groupadd -f adm && sudo usermod -aG adm <user>'), "
                "then start a fresh SSH session."
            ),
        )
    )

    # 4. Log directory exists and is readable
    dir_ok = _probe_rc(probes, "log_directory") == 0
    checks.append(
        PreflightCheck(
            name="log_directory_readable",
            passed=dir_ok,
            message=(
                f"{log_directory} exists and is readable"
                if dir_ok
                else f"{log_directory} is missing or not readable by this user"
            ),
            hint=""
            if dir_ok
            else (
                f"Have an administrator verify {log_directory} exists and grant group adm "
                f"read/traverse access (e.g. 'sudo chgrp adm {log_directory} && "
                f"sudo chmod 0750 {log_directory}')."
            ),
        )
    )

    # 5. access.log* readability
    checks.append(
        _evaluate_log_glob(
            probes,
            probe_key="access_logs",
            check_name="access_logs_readable",
            glob_label="access.log*",
            log_directory=log_directory,
        )
    )

    # 6. error.log* readability
    checks.append(
        _evaluate_log_glob(
            probes,
            probe_key="error_logs",
            check_name="error_logs_readable",
            glob_label="error.log*",
            log_directory=log_directory,
        )
    )

    # 7. Python 3.8+
    py_rc = _probe_rc(probes, "python3")
    py_lines = [line.strip() for line in _probe_stdout(probes, "python3").splitlines() if line]
    py_path = py_lines[0] if py_lines else ""
    py_version = py_lines[1] if len(py_lines) > 1 else ""
    py_ok = py_rc == 0 and bool(py_path)
    if py_ok:
        py_msg = f"Found {py_path} ({py_version or '3.8+'})"
        py_hint = ""
    elif py_rc == 2:
        py_msg = f"Found {py_path or 'python3'} version {py_version or 'below 3.8'} (need >= 3.8)"
        py_hint = "Have an administrator install Python 3.8 or newer on the target host."
    else:
        py_msg = "python3 was not found in PATH on the target"
        py_hint = (
            "Have an administrator install Python 3.8+ (e.g. 'python3') on the target host."
        )
    checks.append(
        PreflightCheck(
            name="python3_version",
            passed=py_ok,
            message=py_msg,
            hint=py_hint,
        )
    )

    # 8. nginx presence
    nginx_rc = _probe_rc(probes, "nginx")
    nginx_path = _probe_stdout(probes, "nginx")
    nginx_ok = nginx_rc == 0 and bool(nginx_path)
    checks.append(
        PreflightCheck(
            name="nginx_present",
            passed=nginx_ok,
            message=(
                f"Found nginx at {nginx_path}"
                if nginx_ok
                else "nginx binary not found in PATH or /usr/sbin"
            ),
            hint=""
            if nginx_ok
            else "Verify nginx is installed on this target host before attempting log acquisition.",
        )
    )

    return PreflightResult(tuple(checks))


def evaluate_ssh_failure(error_output: str) -> PreflightResult:
    """Build a structured failure result when Ansible cannot connect over SSH."""
    lines = [line.strip() for line in error_output.splitlines() if line.strip()]
    summary = lines[-1] if lines else "unable to connect over SSH"
    return PreflightResult(
        (
            PreflightCheck(
                name="ssh_connect",
                passed=False,
                message=f"SSH connection failed: {summary}",
                hint=(
                    "Verify the target IP/hostname, security group inbound rule for port 22, "
                    "SSH username, host key acceptance, and .pem key permissions (chmod 0600)."
                ),
            ),
        )
    )


def _find_ansible_playbook() -> str:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        sibling = Path(sys.executable).with_name("ansible-playbook")
        executable = str(sibling) if sibling.is_file() else None
    if executable is None:
        raise RuntimeError("ansible-playbook is not installed or not on PATH")
    return executable


def run_preflight(
    inventory: Path,
    *,
    log_directory: str = "/var/log/nginx",
) -> PreflightResult:
    """Run read-only preflight checks against an Ansible inventory without writing evidence."""
    resolved_inventory = inventory.resolve()
    if not resolved_inventory.is_file():
        raise FileNotFoundError(f"inventory does not exist: {resolved_inventory}")

    ansible_dir = Path(__file__).resolve().parent / "ansible"
    playbook = ansible_dir / "preflight.yml"
    executable = _find_ansible_playbook()

    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(ansible_dir / "ansible.cfg")
    environment["ANSIBLE_PIPELINING"] = "True"

    with tempfile.TemporaryDirectory(prefix="lapa-preflight-") as tmp_dir:
        output_path = Path(tmp_dir) / "preflight.json"
        extra_vars = canonical_json_bytes(
            {
                "lapa_log_directory": log_directory,
                "lapa_preflight_output": str(output_path),
            }
        ).decode("utf-8")
        command = [
            executable,
            "-i",
            str(resolved_inventory),
            str(playbook),
            "--extra-vars",
            extra_vars,
        ]
        completed = subprocess.run(
            command,
            cwd=ansible_dir,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if output_path.is_file():
            try:
                probes = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                return evaluate_ssh_failure(f"invalid preflight output JSON: {error}")
            if isinstance(probes, Mapping):
                return evaluate_preflight_probes(probes, log_directory=log_directory)
        combined = (completed.stdout + "\n" + completed.stderr).strip()
        return evaluate_ssh_failure(combined)
