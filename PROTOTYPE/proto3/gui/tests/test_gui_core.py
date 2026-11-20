"""Unit tests for gui/runner.py and gui/aws.py (subprocess runner, inventory
writer, SQL guard, JSON parsers)."""

from __future__ import annotations

import os
import queue
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from gui.aws import (
    build_lookup_ip_command,
    build_test_ssh_command,
    check_pem_permissions,
    format_ec2_inventory_line,
    write_ec2_inventory,
)
from gui.runner import (
    CommandRunner,
    RunOutcome,
    format_cell_value,
    format_command_for_log,
    format_verify_derived_checks,
    friendly_consistency_label,
    group_verify_checks,
    list_case_evidence_ids,
    parse_json_stdout,
    validate_and_wrap_sql,
)


def test_write_ec2_inventory_creates_valid_ini_with_absolute_pem(tmp_path: Path) -> None:
    """EC2 inventory uses an absolute key path, accept-new host key checking, and mode 0600."""
    pem = tmp_path / "my-key.pem"
    pem.write_text("DUMMY KEY\n", encoding="utf-8")
    pem.chmod(0o600)

    inv_path = write_ec2_inventory(
        host="203.0.113.25",
        ssh_user="ubuntu",
        pem_path=pem,
        python_interpreter="/usr/bin/python3.11",
        directory=tmp_path,
    )
    try:
        text = inv_path.read_text(encoding="utf-8")
        assert text.startswith("[target]\nec2-target ")
        assert "ansible_host=203.0.113.25" in text
        assert "ansible_user=ubuntu" in text
        assert "ansible_python_interpreter=/usr/bin/python3.11" in text
        assert f"ansible_ssh_private_key_file={pem.resolve()}" in text
        assert "StrictHostKeyChecking=accept-new" in text
        assert "UserKnownHostsFile=/dev/null" not in text
    finally:
        inv_path.unlink(missing_ok=True)


def test_ec2_inventory_rejects_missing_host_or_pem(tmp_path: Path) -> None:
    """Form validation rejects empty hosts, whitespace in hosts, and missing .pem files."""
    pem = tmp_path / "key.pem"
    pem.write_text("KEY", encoding="utf-8")
    with pytest.raises(ValueError, match="public IP"):
        format_ec2_inventory_line("", "ec2-user", pem)
    with pytest.raises(ValueError, match="spaces"):
        format_ec2_inventory_line("1.2.3.4 --inject", "ec2-user", pem)
    with pytest.raises(FileNotFoundError):
        format_ec2_inventory_line("1.2.3.4", "ec2-user", tmp_path / "missing.pem")


def test_check_pem_permissions_warns_when_not_0600(tmp_path: Path) -> None:
    """On POSIX systems, a .pem file with mode 0644 returns a warning message."""
    pem = tmp_path / "open.pem"
    pem.write_text("KEY", encoding="utf-8")
    pem.chmod(0o644)
    if os.name == "posix":
        warning = check_pem_permissions(pem)
        assert warning is not None
        assert "0600" in warning
    pem.chmod(0o600)
    assert check_pem_permissions(pem) is None


def test_aws_lookup_and_ssh_test_command_builders(tmp_path: Path) -> None:
    """AWS CLI and SSH command builders return argument lists without shell interpolation."""
    cmd = build_lookup_ip_command("i-0abc12345def67890", profile=" forensic ", region="eu-west-1")
    assert cmd[:5] == ["aws", "ec2", "describe-instances", "--instance-ids", "i-0abc12345def67890"]
    assert "--profile" in cmd and "forensic" in cmd
    assert "--region" in cmd and "eu-west-1" in cmd

    with pytest.raises(ValueError, match="i-"):
        build_lookup_ip_command("not-an-instance")

    pem = tmp_path / "ec2.pem"
    pem.write_text("KEY", encoding="utf-8")
    ssh_cmd = build_test_ssh_command("198.51.100.10", "ec2-user", pem)
    assert ssh_cmd[0] == "ssh"
    assert str(pem.resolve()) in ssh_cmd
    assert "ec2-user@198.51.100.10" in ssh_cmd


def test_sql_guard_accepts_select_and_with_and_rejects_multi_or_mutating() -> None:
    """The SQL guard allows SELECT/WITH single statements and wraps them in LIMIT 1001."""
    wrapped = validate_and_wrap_sql("SELECT status, count(*) FROM access GROUP BY status;")
    assert wrapped == (
        "SELECT * FROM (SELECT status, count(*) FROM access GROUP BY status) "
        "AS _lapa_gui_q LIMIT 1001"
    )
    cte = validate_and_wrap_sql("  with t as (select 1) select * from t ")
    assert cte.endswith("LIMIT 1001")

    for invalid in (
        "",
        "   ",
        "DROP TABLE access",
        "COPY access TO '/tmp/out.csv'",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE access;",
    ):
        with pytest.raises(ValueError):
            validate_and_wrap_sql(invalid)


def test_format_cell_value_masks_binary_bytes_objects() -> None:
    """Binary fields returned by lapa sql as $bytes_base64 are displayed as <bytes>."""
    assert format_cell_value({"$bytes_base64": "YWJj"}) == "<bytes>"
    assert format_cell_value({"$bytes": "YWJj"}) == "<bytes>"
    assert format_cell_value(None) == ""
    assert format_cell_value(404) == "404"


def test_format_command_for_log_shortens_pem_paths() -> None:
    """Long .pem paths are shortened in the command log line."""
    logged = format_command_for_log(
        [
            "ssh",
            "-i",
            "/Users/alice/secrets/keys/prod-server.pem",
            "ec2-user@1.2.3.4",
            "true",
        ]
    )
    assert ".../prod-server.pem" in logged
    assert "/Users/alice/secrets/keys" not in logged


def test_group_verify_checks_organizes_manifest_custody_and_files() -> None:
    """Verify results group into Manifest, Custody, and one row per collected file."""
    sample_entry = {
        "evidence_id": "3ea4c29b-1c31-4f4d-9482-58df13506bc5",
        "ok": False,
        "failed_checks": ["artifact_full:artifacts/0000-access.log"],
        "checks": [
            {"name": "manifest_present", "passed": True, "message": "ok"},
            {"name": "manifest_json", "passed": True, "message": "ok"},
            {"name": "manifest_schema", "passed": True, "message": "ok"},
            {"name": "manifest_signature", "passed": True, "message": "ok"},
            {"name": "custody_present", "passed": True, "message": "ok"},
            {"name": "custody_json", "passed": True, "message": "ok"},
            {"name": "custody_chain", "passed": True, "message": "ok"},
            {"name": "custody_reference", "passed": True, "message": "ok"},
            {"name": "artifact_present:artifacts/0000-access.log", "passed": True, "message": "ok"},
            {"name": "artifact_prefix:artifacts/0000-access.log", "passed": True, "message": "ok"},
            {
                "name": "artifact_full:artifacts/0000-access.log",
                "passed": False,
                "message": "hash mismatch",
            },
        ],
    }
    rows = group_verify_checks(sample_entry)
    assert [r["group"] for r in rows] == ["Manifest", "Custody", "Files"]
    assert rows[0]["passed"] is True
    assert rows[1]["passed"] is True
    assert rows[2]["passed"] is False
    assert "hash mismatch" in rows[2]["detail"]


def test_verify_derived_and_consistency_labels_and_json_parser() -> None:
    """Verify-derived formatter, consistency labels, and stdout JSON parser
    handle valid and failing outputs."""
    parsed = parse_json_stdout('{"case_id":"C001","ok":false,"error":"no evidence found"}\n')
    assert parsed is not None
    assert parsed["ok"] is False

    derived_rows = format_verify_derived_checks(
        {
            "checks": [
                {"name": "derived_manifest_signature", "passed": True, "message": "valid"},
                {"name": "derived_content_hash", "passed": False, "message": "row hash differs"},
            ]
        }
    )
    assert len(derived_rows) == 2
    assert "Ed25519" in derived_rows[0]["label"]
    assert derived_rows[1]["passed"] is False

    assert "Clock difference" in friendly_consistency_label("clock_skew")


def test_list_case_evidence_ids_filters_uuid4_directories(tmp_path: Path) -> None:
    """Only canonical UUIDv4 subfolders under evidence/<case_id>/ are returned."""
    valid_id = "d13a92df-dbbf-48dc-9784-59758a4c3456"
    (tmp_path / "evidence" / "C001" / valid_id).mkdir(parents=True)
    (tmp_path / "evidence" / "C001" / "not-a-uuid").mkdir(parents=True)
    assert list_case_evidence_ids(tmp_path, "C001") == [valid_id]


def test_command_runner_streams_output_and_supports_cancel(tmp_path: Path) -> None:
    """CommandRunner runs subprocesses asynchronously, parses JSON stdout, and cancels cleanly."""
    q: queue.Queue[tuple[str, Any]] = queue.Queue()
    runner = CommandRunner(q)

    # 1. Fast JSON-emitting command
    runner.start(
        "Test JSON",
        [
            sys.executable,
            "-c",
            'import sys; print(\'{"ok": true, "count": 3}\'); sys.stderr.write("warn line\\n")',
        ],
        tmp_path,
    )
    outcome: RunOutcome | None = None
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            kind, payload = q.get(timeout=0.1)
            if kind == "done":
                outcome, _ = payload
                break
        except queue.Empty:
            continue

    assert outcome is not None
    assert outcome.returncode == 0
    assert outcome.parsed_json == {"ok": True, "count": 3}
    assert outcome.last_stderr_line == "warn line"

    # 2. Long command cancelled mid-run
    temp_file = tmp_path / "temp_inv.ini"
    temp_file.write_text("[target]\n", encoding="utf-8")
    runner.start(
        "Sleep test",
        [sys.executable, "-c", "import time; time.sleep(30)"],
        tmp_path,
        cleanup_path=temp_file,
    )
    time.sleep(0.15)
    runner.cancel()

    cancelled_outcome: RunOutcome | None = None
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            kind, payload = q.get(timeout=0.1)
            if kind == "done":
                cancelled_outcome, _ = payload
                break
        except queue.Empty:
            continue

    assert cancelled_outcome is not None
    assert cancelled_outcome.cancelled is True
    assert not temp_file.exists()
