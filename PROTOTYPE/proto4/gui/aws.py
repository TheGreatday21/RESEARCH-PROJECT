"""AWS EC2 temporary Ansible inventory writer and SSH/CLI command builders (no tkinter imports)."""

from __future__ import annotations

import os
import shlex
import stat
import tempfile
from pathlib import Path


## creating a function that checks whether an SSH .pem key has mode 0600 on POSIX systems
def check_pem_permissions(pem_path: Path) -> str | None:
    if not pem_path.is_file():
        raise FileNotFoundError(f"SSH key (.pem) not found: {pem_path}")
    if os.name != "posix":
        return None
    mode = stat.S_IMODE(pem_path.stat().st_mode)
    if mode != 0o600:
        return (
            f"Warning: SSH key ({pem_path.name}) has mode {mode:04o}; "
            f"OpenSSH requires 0600 (run: chmod 0600 {shlex.quote(str(pem_path))})."
        )
    return None


## creating a function that builds the temporary EC2 Ansible inventory text with an absolute key
## path
def format_ec2_inventory_line(
    host: str,
    ssh_user: str = "ec2-user",
    pem_path: Path | str = "",
    python_interpreter: str = "/usr/bin/python3",
) -> str:
    cleaned_host = host.strip()
    cleaned_user = ssh_user.strip() or "ec2-user"
    cleaned_python = python_interpreter.strip() or "/usr/bin/python3"
    if not cleaned_host:
        raise ValueError("EC2 public IP or hostname is required.")
    if any(ch.isspace() for ch in cleaned_host):
        raise ValueError("EC2 host must not contain spaces.")
    if any(ch.isspace() for ch in cleaned_user):
        raise ValueError("SSH user must not contain spaces.")

    pem = Path(str(pem_path)).expanduser()
    if not str(pem_path).strip() or not pem.is_file():
        raise FileNotFoundError(f"SSH key (.pem) file does not exist: {pem_path}")

    abs_pem = str(pem.resolve())
    quoted_pem = shlex.quote(abs_pem)
    quoted_py = shlex.quote(cleaned_python)

    return (
        "[target]\n"
        f"ec2-target ansible_host={cleaned_host} ansible_port=22 "
        f"ansible_user={cleaned_user} "
        f"ansible_python_interpreter={quoted_py} "
        "ansible_remote_tmp=/tmp "
        f"ansible_ssh_private_key_file={quoted_pem} "
        "ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new' "
        "ansible_connect_timeout=10\n"
    )


## creating a function that writes the temporary EC2 inventory file to disk for one acquisition run
def write_ec2_inventory(
    host: str,
    ssh_user: str = "ec2-user",
    pem_path: Path | str = "",
    python_interpreter: str = "/usr/bin/python3",
    directory: Path | None = None,
) -> Path:
    content = format_ec2_inventory_line(
        host=host,
        ssh_user=ssh_user,
        pem_path=pem_path,
        python_interpreter=python_interpreter,
    )
    fd, temp_path = tempfile.mkstemp(
        prefix="lapa-ec2-inventory-",
        suffix=".ini",
        dir=str(directory) if directory is not None else None,
    )
    try:
        os.chmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise
    return Path(temp_path)


## creating a function that builds the AWS CLI command to look up an EC2 instance's public IP
def build_lookup_ip_command(
    instance_id: str,
    profile: str = "",
    region: str = "",
) -> list[str]:
    cleaned_id = instance_id.strip()
    if not cleaned_id or not cleaned_id.startswith("i-"):
        raise ValueError(
            "Enter a valid EC2 instance ID starting with 'i-' (e.g. i-0123456789abcdef0)."
        )
    command = [
        "aws",
        "ec2",
        "describe-instances",
        "--instance-ids",
        cleaned_id,
        "--query",
        "Reservations[0].Instances[0].PublicIpAddress",
        "--output",
        "text",
    ]
    if profile.strip():
        command.extend(["--profile", profile.strip()])
    if region.strip():
        command.extend(["--region", region.strip()])
    return command


## creating a function that builds the SSH connectivity test command for EC2 targets
def build_test_ssh_command(
    host: str,
    ssh_user: str,
    pem_path: Path | str,
) -> list[str]:
    cleaned_host = host.strip()
    cleaned_user = ssh_user.strip() or "ec2-user"
    if not cleaned_host:
        raise ValueError("EC2 public IP or hostname is required before testing SSH.")
    pem = Path(str(pem_path)).expanduser()
    if not str(pem_path).strip() or not pem.is_file():
        raise FileNotFoundError(f"SSH key (.pem) file does not exist: {pem_path}")
    return [
        "ssh",
        "-i",
        str(pem.resolve()),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{cleaned_user}@{cleaned_host}",
        "true",
    ]


## creating a function that builds the read-only lapa preflight command for a target inventory
def build_preflight_command(lapa_cmd: list[str], inventory_path: Path) -> list[str]:
    return [*lapa_cmd, "preflight", "--inventory", str(inventory_path)]


## creating a function that builds optional AWS CLI flags passed through to lapa acquire
def build_acquire_aws_args(
    instance_id: str = "",
    profile: str = "",
    region: str = "",
) -> list[str]:
    args: list[str] = []
    if instance_id.strip():
        args.extend(["--aws-instance-id", instance_id.strip()])
    if profile.strip():
        args.extend(["--aws-profile", profile.strip()])
    if region.strip():
        args.extend(["--aws-region", region.strip()])
    return args
