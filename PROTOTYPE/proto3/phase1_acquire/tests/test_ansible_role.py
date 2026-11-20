"""Static and syntax checks for the packaged Ansible acquisition role."""

import configparser
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def _ansible_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "ansible"


def test_role_orders_collection_before_flat_fetch() -> None:
    """The role parses collector JSON before fetching every available artifact."""
    tasks_path = _ansible_dir() / "roles" / "acquire_nginx_logs" / "tasks" / "main.yml"
    tasks = yaml.safe_load(tasks_path.read_text(encoding="utf-8"))
    names = [task["name"] for task in tasks]
    assert names.index("Run the read-only collector") < names.index("Parse collector JSON")
    assert names.index("Parse collector JSON") < names.index(
        "Fetch each collected log to a collision-free flat staging path"
    )
    fetch = next(task for task in tasks if "ansible.builtin.fetch" in task)
    assert fetch["ansible.builtin.fetch"]["flat"] is True
    assert "artifact_index" in fetch["ansible.builtin.fetch"]["dest"]


def test_ansible_configuration_enables_pipelining() -> None:
    """Pipelining is enabled in both relevant configuration sections."""
    config = configparser.ConfigParser()
    config.read(_ansible_dir() / "ansible.cfg")
    assert config.getboolean("defaults", "pipelining") is True
    assert config.getboolean("ssh_connection", "pipelining") is True


def _isolated_environment(tmp_path: Path) -> dict[str, str]:
    """Keep Ansible's scratch files out of the user's home directory."""
    environment = os.environ.copy()
    environment["ANSIBLE_HOME"] = str(tmp_path / "ansible-home")
    environment["ANSIBLE_LOCAL_TEMP"] = str(tmp_path / "ansible-tmp")
    return environment


def test_lab_inventory_contains_the_target_host(tmp_path: Path) -> None:
    """The INI inventory parses the lab target instead of silently matching no hosts."""
    executable = shutil.which("ansible-inventory")
    if executable is None:
        executable = str(Path(sys.executable).with_name("ansible-inventory"))
    assert Path(executable).is_file()
    inventory = Path(__file__).parents[2] / "lab" / "inventory.ini"
    completed = subprocess.run(
        [executable, "-i", str(inventory), "--list"],
        env=_isolated_environment(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    parsed = json.loads(completed.stdout)
    assert parsed["target"]["hosts"] == ["lab-target"]


def test_playbook_passes_ansible_syntax_check(tmp_path: Path) -> None:
    """Ansible parses the complete role without initiating SSH connectivity."""
    executable = shutil.which("ansible-playbook")
    if executable is None:
        executable = str(Path(sys.executable).with_name("ansible-playbook"))
    assert Path(executable).is_file()
    ansible_dir = _ansible_dir()
    environment = _isolated_environment(tmp_path)
    environment["ANSIBLE_CONFIG"] = str(ansible_dir / "ansible.cfg")
    completed = subprocess.run(
        [
            executable,
            "-i",
            "target,",
            str(ansible_dir / "acquire.yml"),
            "--syntax-check",
        ],
        cwd=ansible_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
