"""Tests for lab confinement, seeded traffic, and Compose definitions."""

import json
from pathlib import Path

import pytest
import yaml

from lab.traffic import generate, tamper


def test_lab_url_accepts_only_target_service() -> None:
    """Normal lab paths work while absolute and network-path URLs are rejected."""
    assert generate.lab_url("/search?q=test") == "http://target/search?q=test"
    for path in ("//example.com/collect", "http://example.com", "http://target@evil.example"):
        with pytest.raises(ValueError, match="restricted"):
            generate.lab_url(path)


def test_benign_delays_follow_compressed_daily_pattern() -> None:
    """Benign timing varies by virtual hour and retains the requested duration."""
    delays = generate.benign_delays(24, 24.0)
    assert len(delays) == 24
    assert sum(delays) == pytest.approx(24.0)
    assert delays[12] < delays[0]
    assert all(delay > 0 for delay in delays)


def test_seeded_traffic_repeats_and_writes_per_request_trace_labels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Seeded paths repeat and every request receives one unique trace label."""
    calls: list[tuple[str, str, bytes | None, str]] = []

    def fake_send(
        path: str,
        *,
        trace_id: str,
        method: str = "GET",
        data: bytes | None = None,
    ) -> int:
        calls.append((path, method, data, trace_id))
        return 200

    monkeypatch.setattr(generate, "_send", fake_send)
    monkeypatch.setattr(generate.time, "sleep", lambda _seconds: None)
    first_output = tmp_path / "first-labels.jsonl"
    first = generate.main(
        ["--seed", "42", "--benign-count", "4", "--output", str(first_output)]
    )
    capsys.readouterr()
    first_calls = list(calls)
    calls.clear()
    second_output = tmp_path / "second-labels.jsonl"
    second = generate.main(
        ["--seed", "42", "--benign-count", "4", "--output", str(second_output)]
    )
    capsys.readouterr()
    assert first == second == 0
    assert [call[:3] for call in calls] == [call[:3] for call in first_calls]
    assert any(call[0] == "/upstream/synthetic-outage" for call in calls)
    labels = [json.loads(line) for line in first_output.read_text(encoding="utf-8").splitlines()]
    assert {label["class"] for label in labels} == {
        "benign",
        "path_scan",
        "sqli_like",
        "traversal",
        "brute_force",
        "low_slow",
    }
    assert len(labels) == len(first_calls)
    assert [label["trace_id"] for label in labels] == [call[3] for call in first_calls]
    assert len({label["trace_id"] for label in labels}) == len(labels)
    assert all(label["seed"] == 42 for label in labels)
    assert all(label["scenario_id"] and label["start_utc"] for label in labels)


def test_tamper_is_an_explicit_phase_one_stub(capsys: pytest.CaptureFixture[str]) -> None:
    """Phase 1 does not create or modify tampered log copies."""
    assert tamper.main() == 0
    assert capsys.readouterr().out.strip() == "not implemented in this phase"


def test_compose_and_target_configuration() -> None:
    """Compose includes required services and nginx captures analysis fields."""
    root = Path(__file__).parents[2]
    compose = yaml.safe_load((root / "lab" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"target", "traffic"} <= set(compose["services"])
    assert "store" not in compose["services"]
    assert "floci" not in compose["services"]

    nginx = (root / "lab" / "target" / "nginx.conf").read_text(encoding="utf-8")
    for variable in (
        "$remote_addr",
        "$remote_user",
        "$time_local",
        "$request",
        "$status",
        "$body_bytes_sent",
        "$http_referer",
        "$http_user_agent",
        "$msec",
        "$request_time",
        "$request_id",
        "$connection",
        "$http_x_lapa_trace",
    ):
        assert variable in nginx
    inventory = (root / "lab" / "inventory.ini").read_text(encoding="utf-8")
    assert "ansible_user=forensic-acq" in inventory
    assert "ansible_user=root" not in inventory


def test_base_url_override_confines_requests_to_chosen_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--base-url targets the specified HTTP origin while still rejecting cross-host paths."""
    assert generate.lab_url("/login", base_url="http://203.0.113.10") == "http://203.0.113.10/login"
    with pytest.raises(ValueError, match="restricted"):
        generate.lab_url("http://other.example/", base_url="http://203.0.113.10")
    with pytest.raises(ValueError, match="invalid base URL"):
        generate.validate_base_url("ftp://203.0.113.10")

    seen_bases: set[str] = set()

    def fake_send(
        path: str,
        *,
        trace_id: str,
        method: str = "GET",
        data: bytes | None = None,
        base_url: str = generate.BASE_URL,
    ) -> int:
        seen_bases.add(base_url)
        return 200

    monkeypatch.setattr(generate, "_send", fake_send)
    monkeypatch.setattr(generate.time, "sleep", lambda _seconds: None)
    out = tmp_path / "aws_labels.jsonl"
    rc = generate.main(
        [
            "--base-url",
            "http://203.0.113.10:8080",
            "--benign-count",
            "2",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["target"] == "http://203.0.113.10:8080"
    assert seen_bases == {"http://203.0.113.10:8080"}
    assert out.is_file()
