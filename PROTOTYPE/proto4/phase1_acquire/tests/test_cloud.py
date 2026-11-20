"""Unit tests for analyst-side AWS identity lookup and dual-source cloud cross-checking."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from common.canonical import sha256_bytes
from phase1_acquire.cloud import (
    build_aws_caller_identity_command,
    build_aws_describe_instance_command,
    build_target_cloud,
    cross_check_cloud_identity,
    derive_region_from_az,
    query_aws_instance,
)
from phase1_acquire.orchestrator import acquire_evidence, local_collector_sha256
from phase1_acquire.signing import generate_keypair
from phase1_acquire.tests.test_orchestrator import MemoryStore
from phase1_acquire.verify import verify_evidence


def _target_identity(**overrides: str) -> dict[str, str]:
    base = {
        "provider": "aws",
        "instance_id": "i-0123456789abcdef0",
        "region": "eu-west-1",
        "account_id": "123456789012",
        "availability_zone": "eu-west-1a",
        "source": "imdsv2",
        "error": "",
    }
    base.update(overrides)
    return base


def _aws_identity(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "ok",
        "source": "aws ec2 describe-instances",
        "queried_utc": "2026-11-20T12:00:00.000000Z",
        "caller_arn": "arn:aws:iam::123456789012:user/analyst",
        "instance_id": "i-0123456789abcdef0",
        "account_id": "123456789012",
        "availability_zone": "eu-west-1a",
        "region": "eu-west-1",
        "state": "running",
        "public_ip": "203.0.113.25",
        "private_ip": "10.0.1.15",
        "launch_time": "2026-11-20T08:00:00+00:00",
        "error": "",
    }
    base.update(overrides)
    return base


def test_derive_region_from_availability_zone() -> None:
    """Availability zones map deterministically to their AWS region."""
    assert derive_region_from_az("us-east-1a") == "us-east-1"
    assert derive_region_from_az("eu-central-2b") == "eu-central-2"
    assert derive_region_from_az("ap-southeast-3c") == "ap-southeast-3"
    assert derive_region_from_az("") == ""


def test_aws_command_builders_include_profile_and_region_when_set() -> None:
    """Command builders emit read-only AWS CLI argv lists without shell syntax."""
    ec2 = build_aws_describe_instance_command(
        "i-0abc", profile="forensics", region="us-west-2"
    )
    assert ec2 == [
        "aws",
        "ec2",
        "describe-instances",
        "--instance-ids",
        "i-0abc",
        "--output",
        "json",
        "--profile",
        "forensics",
        "--region",
        "us-west-2",
    ]
    sts = build_aws_caller_identity_command(profile="forensics", region="us-west-2")
    assert sts == [
        "aws",
        "sts",
        "get-caller-identity",
        "--output",
        "json",
        "--profile",
        "forensics",
        "--region",
        "us-west-2",
    ]


def test_query_aws_instance_parses_ec2_and_sts_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful AWS CLI responses populate every instance and caller field."""
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        payload: dict[str, Any]
        if command[1] == "sts":
            payload = {"Arn": "arn:aws:iam::123456789012:user/investigator"}
        else:
            payload = {
                "Reservations": [
                    {
                        "OwnerId": "123456789012",
                        "Instances": [
                            {
                                "InstanceId": "i-0123456789abcdef0",
                                "Placement": {"AvailabilityZone": "af-south-1b"},
                                "State": {"Name": "running"},
                                "PublicIpAddress": "198.51.100.44",
                                "PrivateIpAddress": "172.31.10.5",
                                "LaunchTime": "2026-11-20T09:00:00Z",
                            }
                        ],
                    }
                ]
            }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    info = query_aws_instance("i-0123456789abcdef0", profile="lab", region="af-south-1")
    assert info["status"] == "ok"
    assert info["account_id"] == "123456789012"
    assert info["region"] == "af-south-1"
    assert info["availability_zone"] == "af-south-1b"
    assert info["state"] == "running"
    assert info["public_ip"] == "198.51.100.44"
    assert info["private_ip"] == "172.31.10.5"
    assert info["launch_time"] == "2026-11-20T09:00:00Z"
    assert info["caller_arn"] == "arn:aws:iam::123456789012:user/investigator"
    assert info["queried_utc"].endswith("Z")
    assert len(calls) == 2


def test_query_aws_instance_handles_missing_cli_and_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing aws binary or credential failures return unavailable without raising."""

    def raise_not_found(command: list[str], **_kwargs: Any) -> Any:
        raise FileNotFoundError("aws")

    monkeypatch.setattr(subprocess, "run", raise_not_found)
    missing = query_aws_instance("i-0123")
    assert missing["status"] == "unavailable"
    assert "not installed" in missing["error"]

    def auth_error(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 255, "", "Unable to locate credentials")

    monkeypatch.setattr(subprocess, "run", auth_error)
    denied = query_aws_instance("i-0123")
    assert denied["status"] == "unavailable"
    assert "credentials" in denied["error"]


def test_cross_check_match_public_and_private_ip() -> None:
    """Matching instance, region, account, and either public or private IP returns match."""
    pub = cross_check_cloud_identity(_target_identity(), _aws_identity(), "203.0.113.25")
    assert pub["status"] == "match"
    priv = cross_check_cloud_identity(_target_identity(), _aws_identity(), "10.0.1.15")
    assert priv["status"] == "match"


@pytest.mark.parametrize(
    ("target_override", "address", "expected_fragment"),
    [
        ({"instance_id": "i-99999999999999999"}, "203.0.113.25", "instance_id mismatch"),
        ({"region": "us-east-1"}, "203.0.113.25", "region mismatch"),
        ({"account_id": "999999999999"}, "203.0.113.25", "account_id mismatch"),
        ({}, "198.51.100.99", "SSH address"),
    ],
)
def test_cross_check_detects_each_mismatch_kind(
    target_override: dict[str, str],
    address: str,
    expected_fragment: str,
) -> None:
    """Each single-field divergence produces status='mismatch' with an explicit detail."""
    result = cross_check_cloud_identity(
        _target_identity(**target_override),
        _aws_identity(),
        address,
    )
    assert result["status"] == "mismatch"
    assert any(expected_fragment in item for item in result["details"])


def test_cross_check_not_checked_and_unavailable() -> None:
    """Missing AWS query is not_checked; AWS or target failure is unavailable."""
    not_checked = cross_check_cloud_identity(_target_identity(), None, "203.0.113.25")
    assert not_checked["status"] == "not_checked"

    aws_down = cross_check_cloud_identity(
        _target_identity(),
        {"status": "unavailable", "error": "expired token"},
        "203.0.113.25",
    )
    assert aws_down["status"] == "unavailable"
    assert any("expired token" in item for item in aws_down["details"])

    target_down = cross_check_cloud_identity(
        _target_identity(provider="", instance_id="", region="", account_id="", error="timed out"),
        _aws_identity(),
        "203.0.113.25",
    )
    assert target_down["status"] == "unavailable"
    assert any("timed out" in item for item in target_down["details"])


def test_build_target_cloud_keeps_flat_keys_and_adds_both_sources() -> None:
    """target.cloud retains the four flat target-reported keys plus nested dual sources."""
    block = build_target_cloud(_target_identity(), _aws_identity(), "203.0.113.25")
    assert block["provider"] == "aws"
    assert block["instance_id"] == "i-0123456789abcdef0"
    assert block["region"] == "eu-west-1"
    assert block["account_id"] == "123456789012"
    assert block["reported_by_target"]["source"] == "imdsv2"
    assert block["reported_by_aws_api"]["caller_arn"] == "arn:aws:iam::123456789012:user/analyst"
    assert block["cross_check"]["status"] == "match"


def test_cloud_mismatch_does_not_block_acquisition_or_fail_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cloud cross-check mismatch is recorded in manifest/result without failing Verify."""
    private_path, public_path = generate_keypair(tmp_path / "keys")
    content = b"one\n"
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[target]\ntarget\n", encoding="utf-8")

    def fake_ansible(inv: Path, case_id: str, staging: Path) -> None:
        art_dir = staging / "artifacts" / "0000"
        art_dir.mkdir(parents=True)
        (art_dir / "access.log").write_bytes(content)
        collector_doc = {
            "collector_sha256": local_collector_sha256(),
            "hostname": "ec2-host",
            "kernel": "6.8",
            "os_release": {"ID": "ubuntu"},
            "cloud": _target_identity(instance_id="i-target-mismatch"),
            "target_time_before": {"utc": "2026-11-20T12:00:00Z", "original": "x"},
            "target_time_after": {"utc": "2026-11-20T12:00:01Z", "original": "x"},
            "artifacts": [
                {
                    "logical_name": "access.log",
                    "source_path": "/var/log/nginx/access.log",
                    "size_at_open": len(content),
                    "prefix_bytes_read": len(content),
                    "sha256_source": sha256_bytes(content),
                    "changed_during_read": False,
                }
            ],
            "context_artifacts": [],
            "collection_errors": [],
            "footprint": {"commands": [], "files_created": []},
        }
        (staging / "collector.json").write_text(json.dumps(collector_doc), encoding="utf-8")
        (staging / "run_metadata.json").write_text(
            json.dumps(
                {
                    "control_started_utc": "2026-11-20T12:00:00Z",
                    "control_probe_finished_utc": "2026-11-20T12:00:01Z",
                    "control_finished_utc": "2026-11-20T12:00:02Z",
                    "target_address": "203.0.113.25",
                    "ssh_user": "ubuntu",
                    "files_created": [],
                    "preflight_commands": [],
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr("phase1_acquire.orchestrator._run_ansible", fake_ansible)
    monkeypatch.setattr(
        "phase1_acquire.orchestrator.query_aws_instance",
        lambda instance_id, profile=None, region=None: _aws_identity(),
    )

    store = MemoryStore()
    result = acquire_evidence(
        store=store,
        inventory=inventory,
        case_id="C001",
        staging_dir=tmp_path / "staging",
        private_key_path=private_path,
        aws_instance_id="i-0123456789abcdef0",
    )
    assert result.ok is True
    assert result.cloud_cross_check["status"] == "mismatch"
    assert result.manifest["target"]["cloud"]["instance_id"] == "i-target-mismatch"
    assert result.manifest["target"]["cloud"]["reported_by_aws_api"]["status"] == "ok"

    verification = verify_evidence(store, result.evidence_id, public_path)
    assert verification.ok is True, verification.to_dict()
