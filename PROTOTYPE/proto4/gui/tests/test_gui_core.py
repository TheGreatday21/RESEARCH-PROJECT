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
    build_acquire_aws_args,
    build_lookup_ip_command,
    build_preflight_command,
    build_test_ssh_command,
    check_pem_permissions,
    format_ec2_inventory_line,
    write_ec2_inventory,
)
from gui.runner import (
    CommandRunner,
    RunOutcome,
    extract_manifest_display,
    format_acquire_outcome,
    format_cell_value,
    format_command_for_log,
    format_preflight_checks,
    format_verify_derived_checks,
    friendly_consistency_label,
    group_verify_checks,
    list_case_evidence_ids,
    parse_json_stdout,
    validate_and_wrap_sql,
)
from gui.targets import (
    EC2_UNTESTED_SUFFIX,
    EVALUATE_NEEDS_LABELS_TEXT,
    LAB_ONLY_ACTIONS,
    TARGET_DESCRIPTIONS,
    TARGET_EC2,
    TARGET_LAB,
    TARGET_LABELS,
    allowed_actions_for_target,
    can_run_evaluate,
    default_labels_path_for_target,
    evaluate_idle_status,
    is_action_allowed,
    report_labels_path,
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


def test_group_verify_checks_includes_completeness_group() -> None:
    """acquisition_complete appears in its own Completeness group with its message."""
    entry = {
        "checks": [
            {"name": "manifest_signature", "passed": True, "message": "ok"},
            {
                "name": "acquisition_complete",
                "passed": False,
                "message": "no files matched glob: /var/log/nginx/error.log*",
            },
            {"name": "custody_chain", "passed": True, "message": "ok"},
        ]
    }
    rows = group_verify_checks(entry)
    assert [r["group"] for r in rows] == ["Manifest", "Custody", "Completeness"]
    assert rows[2]["passed"] is False
    assert "no files matched glob" in rows[2]["detail"]


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


def test_target_action_rules_exclude_lab_actions_from_ec2() -> None:
    """My server (AWS EC2) excludes all lab/traffic actions while Docker lab keeps them."""
    lab_actions = allowed_actions_for_target(TARGET_LAB)
    ec2_actions = allowed_actions_for_target(TARGET_EC2)

    assert lab_actions >= LAB_ONLY_ACTIONS
    assert ec2_actions.isdisjoint(LAB_ONLY_ACTIONS)
    assert is_action_allowed(TARGET_EC2, "preflight") is True
    assert is_action_allowed(TARGET_EC2, "start_lab") is False
    assert is_action_allowed(TARGET_EC2, "generate_traffic") is False
    assert is_action_allowed(TARGET_LAB, "start_lab") is True
    assert is_action_allowed(TARGET_LAB, "generate_traffic") is True

    assert EC2_UNTESTED_SUFFIX in TARGET_LABELS[TARGET_EC2]
    assert "Start lab and Generate traffic" in TARGET_DESCRIPTIONS[TARGET_LAB]
    assert "only reads from it" in TARGET_DESCRIPTIONS[TARGET_EC2]

    # Static module boundary check: EC2 modules must never reference lab/traffic commands
    gui_dir = Path(__file__).resolve().parents[1]
    for filename in ("aws.py", "ec2_panel.py"):
        source = (gui_dir / filename).read_text(encoding="utf-8")
        for forbidden in ("lab_tools", "lab-up", "make traffic", "lab.traffic"):
            assert forbidden not in source, f"{filename} must not reference {forbidden!r}"


def test_evaluate_depends_on_labels_file_not_target(tmp_path: Path) -> None:
    """Evaluate is enabled whenever a labels file is chosen, regardless of target."""
    assert can_run_evaluate(locked=False, labels_path="") is False
    assert can_run_evaluate(locked=False, labels_path="   ") is False
    assert can_run_evaluate(locked=True, labels_path="custom_labels.jsonl") is False
    assert can_run_evaluate(locked=False, labels_path="custom_labels.jsonl") is True
    assert evaluate_idle_status("") == EVALUATE_NEEDS_LABELS_TEXT
    assert evaluate_idle_status("labels.jsonl") == "○ Not run"

    # Pre-fill lab/out/labels.jsonl only for Docker lab when the file exists
    lab_labels = tmp_path / "lab" / "out" / "labels.jsonl"
    lab_labels.parent.mkdir(parents=True)
    lab_labels.write_text('{"trace_id":"t1","class":"benign"}\n', encoding="utf-8")
    assert default_labels_path_for_target(TARGET_LAB, tmp_path, tmp_path) == "lab/out/labels.jsonl"
    assert default_labels_path_for_target(TARGET_EC2, tmp_path, tmp_path) == ""
    assert report_labels_path("", tmp_path, tmp_path) is None
    assert report_labels_path(str(lab_labels), tmp_path, tmp_path) == lab_labels


def test_preflight_and_acquire_aws_command_builders(tmp_path: Path) -> None:
    """Preflight and EC2 acquire argument builders produce exact argv lists."""
    inv = tmp_path / "inv.ini"
    assert build_preflight_command(["lapa"], inv) == ["lapa", "preflight", "--inventory", str(inv)]
    assert build_acquire_aws_args() == []
    assert build_acquire_aws_args(
        instance_id=" i-0123 ", profile=" sec ", region=" eu-west-1 "
    ) == [
        "--aws-instance-id",
        "i-0123",
        "--aws-profile",
        "sec",
        "--aws-region",
        "eu-west-1",
    ]


def test_preflight_and_manifest_and_acquire_display_formatters() -> None:
    """Preflight checks, dual-source cloud manifest, and exit-2 acquire warnings format cleanly."""
    pf_rows = format_preflight_checks(
        {
            "ok": False,
            "checks": [
                {"name": "ssh_connect", "passed": True, "message": "ok", "hint": ""},
                {
                    "name": "adm_group",
                    "passed": False,
                    "message": "not in adm",
                    "hint": "sudo usermod -aG adm ubuntu",
                },
            ],
        }
    )
    assert len(pf_rows) == 2
    assert pf_rows[1]["passed"] is False
    assert "usermod" in pf_rows[1]["hint"]

    manifest = {
        "schema_version": 2,
        "case_id": "C001",
        "evidence_id": "3ea4c29b-1c31-4f4d-9482-58df13506bc5",
        "acquirer": {
            "tool": "lapa",
            "version": "0.2.0",
            "operator": "analyst",
            "collector": {"match": True, "sha256_local": "a", "sha256_reported_by_target": "a"},
        },
        "target": {
            "hostname": "web-01",
            "address": "203.0.113.10",
            "ssh_user": "ubuntu",
            "kernel": "6.8",
            "cloud": {
                "provider": "aws",
                "instance_id": "i-target",
                "region": "eu-west-1",
                "account_id": "111122223333",
                "reported_by_target": {
                    "source": "imdsv2",
                    "instance_id": "i-target",
                    "region": "eu-west-1",
                    "availability_zone": "eu-west-1a",
                    "account_id": "111122223333",
                    "error": "",
                },
                "reported_by_aws_api": {
                    "status": "ok",
                    "source": "aws ec2 describe-instances",
                    "caller_arn": "arn:aws:iam::111122223333:user/me",
                    "instance_id": "i-aws",
                    "region": "eu-west-1",
                    "availability_zone": "eu-west-1a",
                    "account_id": "111122223333",
                    "public_ip": "203.0.113.10",
                    "private_ip": "10.0.0.5",
                },
                "cross_check": {
                    "status": "mismatch",
                    "details": ["instance_id mismatch: target reported 'i-target'"],
                },
            },
        },
        "timing": {"started_utc": "2026-11-20T00:00:00Z", "finished_utc": "2026-11-20T00:00:05Z"},
        "timezone": {"iana_name": "UTC", "utc_offset": "+0000"},
        "signature": {"key_id": "deadbeef12345678"},
        "footprint": {"commands": ["true", "id -u", ["nginx", "-T"]], "files_created": []},
        "artifacts": [
            {
                "stored_as": "artifacts/0000-access.log",
                "logical_name": "access.log",
                "size_at_open": 1024,
                "grew_during_read": True,
                "changed_during_read": False,
                "verified": True,
            }
        ],
        "context_artifacts": [],
        "collection_errors": [],
    }
    display = extract_manifest_display(manifest)
    assert display["signing_key_id"] == "deadbeef12345678"
    assert display["footprint_command_count"] == 3
    assert display["file_rows"][0]["grew_during_read"] is True
    assert "normal on a live server" in display["grew_note"]
    assert display["cloud_comparison"]["status"] == "mismatch"
    assert any(
        r[0] == "Instance ID" and r[1] == "i-target" and r[2] == "i-aws"
        for r in display["cloud_comparison"]["rows"]
    )

    exit2 = RunOutcome(
        step_name="Acquire",
        command=["lapa", "acquire"],
        returncode=2,
        stdout="",
        stderr="",
        parsed_json={
            "evidence_id": "3ea4c29b-1c31-4f4d-9482-58df13506bc5",
            "ok": False,
            "unverified_artifacts": ["/var/log/nginx/access.log"],
            "collection_errors": ["no files matched glob: /var/log/nginx/error.log*"],
            "cloud_cross_check": {"status": "not_checked", "details": []},
        },
    )
    fmt_exit2 = format_acquire_outcome(exit2)
    assert fmt_exit2["ok"] is False
    assert fmt_exit2["banner_kind"] == "warn"
    assert fmt_exit2["chip_state"] == "warn"
    assert "error.log*" in fmt_exit2["banner_text"]
    assert "access.log" in fmt_exit2["banner_text"]

    mismatch_ok = RunOutcome(
        step_name="Acquire",
        command=["lapa", "acquire"],
        returncode=0,
        stdout="",
        stderr="",
        parsed_json={
            "evidence_id": "3ea4c29b-1c31-4f4d-9482-58df13506bc5",
            "ok": True,
            "unverified_artifacts": [],
            "collection_errors": [],
            "cloud_cross_check": {"status": "mismatch", "details": ["region mismatch"]},
        },
    )
    fmt_mismatch = format_acquire_outcome(mismatch_ok)
    assert fmt_mismatch["ok"] is True
    assert fmt_mismatch["banner_kind"] == "warn"
    assert "region mismatch" in fmt_mismatch["banner_text"]
