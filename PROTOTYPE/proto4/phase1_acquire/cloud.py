"""Analyst-side AWS identity lookup (read-only CLI) and dual-source cross-check."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

_AZ_PATTERN = re.compile(r"^([a-z]{2}(?:-[a-z]+)+-\d+)[a-z]$")


def _utc_now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def derive_region_from_az(availability_zone: str) -> str:
    """Derive an AWS region name (e.g. us-east-1) from an availability zone (us-east-1a)."""
    cleaned = availability_zone.strip()
    if not cleaned:
        return ""
    match = _AZ_PATTERN.match(cleaned)
    if match:
        return match.group(1)
    if len(cleaned) > 1 and cleaned[-1].isalpha() and cleaned[-2].isdigit():
        return cleaned[:-1]
    return ""


def build_aws_describe_instance_command(
    instance_id: str,
    *,
    profile: str | None = None,
    region: str | None = None,
) -> list[str]:
    """Build the read-only aws ec2 describe-instances argv without a shell."""
    command = [
        "aws",
        "ec2",
        "describe-instances",
        "--instance-ids",
        instance_id.strip(),
        "--output",
        "json",
    ]
    if profile and profile.strip():
        command.extend(["--profile", profile.strip()])
    if region and region.strip():
        command.extend(["--region", region.strip()])
    return command


def build_aws_caller_identity_command(
    *,
    profile: str | None = None,
    region: str | None = None,
) -> list[str]:
    """Build the read-only aws sts get-caller-identity argv without a shell."""
    command = ["aws", "sts", "get-caller-identity", "--output", "json"]
    if profile and profile.strip():
        command.extend(["--profile", profile.strip()])
    if region and region.strip():
        command.extend(["--region", region.strip()])
    return command


def _run_json_cli(command: list[str], timeout: float) -> tuple[dict[str, Any] | None, str]:
    """Execute one read-only AWS CLI command without a shell and parse JSON output."""
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None, "aws CLI is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return None, f"aws CLI timed out after {timeout}s"
    except OSError as error:
        return None, str(error)

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        return None, detail or f"aws CLI exited with code {completed.returncode}"
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return None, f"aws CLI returned invalid JSON: {error}"
    if not isinstance(parsed, dict):
        return None, "aws CLI JSON output is not an object"
    return parsed, ""


def query_aws_instance(
    instance_id: str,
    *,
    profile: str | None = None,
    region: str | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Query AWS EC2 and STS for read-only analyst-side instance identity.

    Never raises on missing CLI, expired credentials, or AWS errors; instead
    returns status='unavailable' with the error message.
    """
    cleaned_id = instance_id.strip()
    queried_utc = _utc_now()

    sts_cmd = build_aws_caller_identity_command(profile=profile, region=region)
    sts_data, sts_error = _run_json_cli(sts_cmd, timeout=timeout)
    caller_arn = str(sts_data.get("Arn") or "") if sts_data is not None else ""

    ec2_cmd = build_aws_describe_instance_command(
        cleaned_id, profile=profile, region=region
    )
    ec2_data, ec2_error = _run_json_cli(ec2_cmd, timeout=timeout)

    def _unavailable(error_message: str) -> dict[str, Any]:
        record: dict[str, Any] = {
            "status": "unavailable",
            "source": "aws ec2 describe-instances",
            "queried_utc": queried_utc,
            "caller_arn": caller_arn,
            "instance_id": cleaned_id,
            "account_id": "",
            "availability_zone": "",
            "region": "",
            "state": "",
            "public_ip": "",
            "private_ip": "",
            "launch_time": "",
            "error": error_message,
        }
        if sts_error:
            record["caller_identity_error"] = sts_error
        return record

    if ec2_data is None:
        return _unavailable(ec2_error)

    reservations = ec2_data.get("Reservations")
    if not isinstance(reservations, list) or not reservations:
        return _unavailable(f"no EC2 reservation returned for {cleaned_id}")
    reservation = reservations[0]
    if not isinstance(reservation, dict):
        return _unavailable("unexpected EC2 reservation shape")
    instances = reservation.get("Instances")
    if not isinstance(instances, list) or not instances or not isinstance(instances[0], dict):
        return _unavailable(f"no EC2 instance returned for {cleaned_id}")

    instance = instances[0]
    placement = instance.get("Placement")
    az = (
        str(placement.get("AvailabilityZone") or "")
        if isinstance(placement, dict)
        else ""
    )
    state = instance.get("State")
    state_name = str(state.get("Name") or "") if isinstance(state, dict) else ""
    derived_region = derive_region_from_az(az) or (region.strip() if region else "")

    record: dict[str, Any] = {
        "status": "ok",
        "source": "aws ec2 describe-instances",
        "queried_utc": queried_utc,
        "caller_arn": caller_arn,
        "instance_id": str(instance.get("InstanceId") or cleaned_id),
        "account_id": str(reservation.get("OwnerId") or ""),
        "availability_zone": az,
        "region": derived_region,
        "state": state_name,
        "public_ip": str(instance.get("PublicIpAddress") or ""),
        "private_ip": str(instance.get("PrivateIpAddress") or ""),
        "launch_time": str(instance.get("LaunchTime") or ""),
        "error": "",
    }
    if sts_error:
        record["caller_identity_error"] = sts_error
    return record


def normalize_target_cloud(raw: Any) -> dict[str, str]:
    """Extract the target-reported cloud identity dict cleanly from collector output."""
    source_dict = raw if isinstance(raw, Mapping) else {}
    return {
        "provider": str(source_dict.get("provider") or ""),
        "instance_id": str(source_dict.get("instance_id") or ""),
        "region": str(source_dict.get("region") or ""),
        "account_id": str(source_dict.get("account_id") or ""),
        "availability_zone": str(source_dict.get("availability_zone") or ""),
        "source": str(source_dict.get("source") or "not_reported"),
        "error": str(source_dict.get("error") or ""),
    }


def cross_check_cloud_identity(
    reported_by_target: Mapping[str, Any],
    reported_by_aws_api: Mapping[str, Any] | None,
    target_address: str,
) -> dict[str, Any]:
    """Compare target-reported IMDSv2 identity against AWS API identity and SSH address.

    Pure function returning {status, details} where status is one of:
    'match', 'mismatch', 'not_checked', 'unavailable'.
    """
    if not reported_by_aws_api or reported_by_aws_api.get("status") == "not_queried":
        return {
            "status": "not_checked",
            "details": ["AWS API query was not requested (no --aws-instance-id provided)."],
        }

    aws_status = str(reported_by_aws_api.get("status") or "")
    if aws_status != "ok":
        aws_error = str(reported_by_aws_api.get("error") or "AWS API lookup unavailable")
        return {
            "status": "unavailable",
            "details": [f"AWS API lookup unavailable: {aws_error}"],
        }

    target_id = str(reported_by_target.get("instance_id") or "").strip()
    target_region = str(reported_by_target.get("region") or "").strip()
    target_account = str(reported_by_target.get("account_id") or "").strip()
    target_error = str(reported_by_target.get("error") or "").strip()

    aws_id = str(reported_by_aws_api.get("instance_id") or "").strip()
    aws_region = str(reported_by_aws_api.get("region") or "").strip()
    aws_account = str(reported_by_aws_api.get("account_id") or "").strip()
    aws_public_ip = str(reported_by_aws_api.get("public_ip") or "").strip()
    aws_private_ip = str(reported_by_aws_api.get("private_ip") or "").strip()
    ssh_address = target_address.strip()

    if not target_id:
        reason = target_error or "target did not report an AWS IMDSv2 instance ID"
        return {
            "status": "unavailable",
            "details": [f"Target-reported cloud identity unavailable: {reason}"],
        }

    mismatches: list[str] = []
    if target_id != aws_id:
        mismatches.append(
            f"instance_id mismatch: target reported {target_id!r}, AWS reported {aws_id!r}"
        )
    if target_region != aws_region:
        mismatches.append(
            f"region mismatch: target reported {target_region!r}, AWS reported {aws_region!r}"
        )
    if target_account != aws_account:
        mismatches.append(
            f"account_id mismatch: target reported {target_account!r}, AWS reported {aws_account!r}"
        )

    aws_ips = {ip for ip in (aws_public_ip, aws_private_ip) if ip}
    if ssh_address:
        if not aws_ips:
            mismatches.append(
                f"SSH address {ssh_address!r} could not be matched: AWS reported no IP address"
            )
        elif ssh_address not in aws_ips:
            mismatches.append(
                f"SSH address {ssh_address!r} does not match AWS public/private IP(s) "
                f"{sorted(aws_ips)}"
            )

    if mismatches:
        return {"status": "mismatch", "details": mismatches}
    return {
        "status": "match",
        "details": ["instance_id, region, account_id, and SSH address match AWS API records."],
    }


def build_target_cloud(
    collector_cloud: Any,
    aws_api_cloud: Mapping[str, Any] | None,
    target_address: str,
) -> dict[str, Any]:
    """Build the additive signed target.cloud manifest object keeping the four flat keys."""
    target_reported = normalize_target_cloud(collector_cloud)
    aws_reported: dict[str, Any] = (
        dict(aws_api_cloud)
        if aws_api_cloud is not None
        else {"status": "not_queried", "source": "aws ec2 describe-instances"}
    )
    check = cross_check_cloud_identity(target_reported, aws_api_cloud, target_address)
    return {
        "provider": target_reported["provider"],
        "instance_id": target_reported["instance_id"],
        "region": target_reported["region"],
        "account_id": target_reported["account_id"],
        "reported_by_target": target_reported,
        "reported_by_aws_api": aws_reported,
        "cross_check": check,
    }
