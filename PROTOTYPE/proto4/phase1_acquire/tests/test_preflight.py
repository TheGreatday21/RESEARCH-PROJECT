"""Unit tests for read-only preflight probe evaluation, runner, and CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.app import app
from phase1_acquire.preflight import (
    PreflightCheck,
    PreflightResult,
    evaluate_preflight_probes,
    evaluate_ssh_failure,
    run_preflight,
)


def _passing_probes() -> dict[str, dict[str, Any]]:
    return {
        "ssh_connect": {"rc": 0, "stdout": "", "stderr": ""},
        "uid": {"rc": 0, "stdout": "1000\n", "stderr": ""},
        "groups": {"rc": 0, "stdout": "ubuntu adm sudo\n", "stderr": ""},
        "log_directory": {"rc": 0, "stdout": "", "stderr": ""},
        "access_logs": {"rc": 0, "stdout": "2 2\n", "stderr": ""},
        "error_logs": {"rc": 0, "stdout": "1 1\n", "stderr": ""},
        "python3": {"rc": 0, "stdout": "/usr/bin/python3\n3.12.3\n", "stderr": ""},
        "nginx": {"rc": 0, "stdout": "/usr/sbin/nginx\n", "stderr": ""},
    }


def test_preflight_all_checks_pass() -> None:
    """When every probe succeeds, ok is True and every check has an empty hint."""
    result = evaluate_preflight_probes(_passing_probes())
    assert result.ok is True
    assert len(result.checks) == 8
    assert all(check.passed and check.hint == "" for check in result.checks)


@pytest.mark.parametrize(
    ("probe_key", "override", "expected_check", "hint_fragment"),
    [
        ("uid", {"rc": 0, "stdout": "0\n", "stderr": ""}, "non_root_user", "non-root"),
        ("groups", {"rc": 0, "stdout": "ec2-user wheel\n", "stderr": ""}, "adm_group", "adm"),
        (
            "log_directory",
            {"rc": 1, "stdout": "", "stderr": ""},
            "log_directory_readable",
            "0750",
        ),
        (
            "access_logs",
            {"rc": 0, "stdout": "0 0\n", "stderr": ""},
            "access_logs_readable",
            "access.log*",
        ),
        (
            "access_logs",
            {"rc": 0, "stdout": "2 0\n", "stderr": ""},
            "access_logs_readable",
            "0640",
        ),
        (
            "error_logs",
            {"rc": 0, "stdout": "0 0\n", "stderr": ""},
            "error_logs_readable",
            "error.log*",
        ),
        (
            "error_logs",
            {"rc": 0, "stdout": "1 0\n", "stderr": ""},
            "error_logs_readable",
            "0640",
        ),
        (
            "python3",
            {"rc": 127, "stdout": "", "stderr": ""},
            "python3_version",
            "3.8",
        ),
        (
            "python3",
            {"rc": 2, "stdout": "/usr/bin/python3\n3.6.9\n", "stderr": ""},
            "python3_version",
            "3.8",
        ),
        (
            "nginx",
            {"rc": 1, "stdout": "", "stderr": ""},
            "nginx_present",
            "nginx",
        ),
    ],
)
def test_preflight_each_failing_check_returns_hint(
    probe_key: str,
    override: dict[str, Any],
    expected_check: str,
    hint_fragment: str,
) -> None:
    """Every individual prerequisite failure marks ok=False and provides a remediation hint."""
    probes = _passing_probes()
    probes[probe_key] = override
    result = evaluate_preflight_probes(probes)
    assert result.ok is False
    failed = {check.name: check for check in result.checks if not check.passed}
    assert expected_check in failed
    assert hint_fragment in failed[expected_check].hint


def test_evaluate_ssh_failure_produces_structured_hint() -> None:
    """Unreachable SSH targets produce a clean failed ssh_connect check with guidance."""
    result = evaluate_ssh_failure("fatal: UNREACHABLE! => Permission denied (publickey)")
    assert result.ok is False
    assert len(result.checks) == 1
    assert result.checks[0].name == "ssh_connect"
    assert "Permission denied" in result.checks[0].message
    assert "0600" in result.checks[0].hint


def test_run_preflight_uses_packaged_ansible_cfg_and_writes_no_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_preflight invokes preflight.yml with ansible.cfg and cleans up its temp JSON."""
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")
    recorded_env: dict[str, str] = {}
    recorded_cmd: list[str] = []

    def fake_run(
        command: list[str], *, env: dict[str, str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        recorded_cmd.extend(command)
        recorded_env.update(env)
        extra_idx = command.index("--extra-vars") + 1
        extra = json.loads(command[extra_idx])
        Path(extra["lapa_preflight_output"]).write_text(
            json.dumps(_passing_probes()), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_preflight(inventory)
    assert result.ok is True
    assert recorded_env["ANSIBLE_CONFIG"].endswith("phase1_acquire/ansible/ansible.cfg")
    assert recorded_env["ANSIBLE_PIPELINING"] == "True"
    assert any(arg.endswith("preflight.yml") for arg in recorded_cmd)
    assert not (tmp_path / "evidence").exists()


def test_cli_preflight_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lapa preflight exits 0 when all checks pass and 1 when any check fails."""
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")
    runner = CliRunner()

    pass_result = PreflightResult(
        (PreflightCheck("ssh_connect", True, "SSH connection succeeded", ""),)
    )
    monkeypatch.setattr(
        "cli.app.run_preflight",
        lambda inv, log_directory="/var/log/nginx": pass_result,
    )
    ok_out = runner.invoke(app, ["preflight", "--inventory", str(inventory)])
    assert ok_out.exit_code == 0, ok_out.output
    assert json.loads(ok_out.output)["ok"] is True

    fail_result = PreflightResult(
        (PreflightCheck("adm_group", False, "not in adm", "Add user to adm group"),)
    )
    monkeypatch.setattr(
        "cli.app.run_preflight",
        lambda inv, log_directory="/var/log/nginx": fail_result,
    )
    fail_out = runner.invoke(app, ["preflight", "--inventory", str(inventory)])
    assert fail_out.exit_code == 1
    parsed = json.loads(fail_out.output)
    assert parsed["ok"] is False
    assert parsed["checks"][0]["hint"] == "Add user to adm group"
