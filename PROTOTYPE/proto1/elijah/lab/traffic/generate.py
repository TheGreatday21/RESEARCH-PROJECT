"""Generate seeded synthetic traffic exclusively for the lab target service."""

from __future__ import annotations

import argparse
import json
import math
import random
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

BASE_URL = "http://target"
ATTACK_PATHS = {
    "path_scanning": [
        "/.git/config",
        "/.env",
        "/wp-admin/",
        "/phpmyadmin/",
        "/server-status",
        "/backup.zip",
    ],
    "sql_injection": [
        "/search?" + urlencode({"q": "' OR '1'='1"}),
        "/search?" + urlencode({"q": "1 UNION SELECT username,password FROM users"}),
        "/search?" + urlencode({"q": "'; DROP TABLE sessions; --"}),
    ],
    "path_traversal": [
        "/%2e%2e/%2e%2e/etc/passwd",
        "/download?file=..%2f..%2f..%2fetc%2fshadow",
        "/%2e%2e%2f%2e%2e%2fvar%2flog%2fnginx%2faccess.log",
    ],
    "low_and_slow_scan": [
        "/hidden-01",
        "/hidden-02",
        "/hidden-03",
        "/hidden-04",
        "/hidden-05",
    ],
}


def _canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _utc_now() -> str:
    """Return the current UTC timestamp for attack labels."""
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def lab_url(path: str) -> str:
    """Join a request path while rejecting every non-lab destination."""
    url = urljoin(BASE_URL, path)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.netloc != "target"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("traffic is restricted to http://target inside the Docker lab")
    return url


class NoExternalRedirect(urllib.request.HTTPRedirectHandler):
    """Disable redirects so a lab response cannot select another destination."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        """Reject every redirect rather than following its location."""
        return None


def _send(path: str, *, method: str = "GET", data: bytes | None = None) -> int:
    """Send one lab request and return its HTTP status, including error statuses."""
    request = urllib.request.Request(
        lab_url(path),
        data=data,
        method=method,
        headers={"User-Agent": "elijah-synthetic-traffic/0.1"},
    )
    opener = urllib.request.build_opener(NoExternalRedirect())
    try:
        with opener.open(request, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def benign_delays(count: int, duration_seconds: float) -> list[float]:
    """Compress a sinusoidal daily request-rate pattern into a short test run."""
    if count < 0 or duration_seconds <= 0:
        raise ValueError("count must be non-negative and duration must be positive")
    if count == 0:
        return []
    inverse_rates: list[float] = []
    for index in range(count):
        hour = 24 * (index + 0.5) / count
        daily_cycle = 0.5 + 0.5 * math.sin(2 * math.pi * (hour - 6) / 24)
        requests_per_virtual_hour = 0.2 + 1.8 * daily_cycle
        inverse_rates.append(1 / requests_per_virtual_hour)
    scale = duration_seconds / sum(inverse_rates)
    return [value * scale for value in inverse_rates]


def _attack_label(attack_type: str, start: str, end: str) -> dict[str, str]:
    """Create one required attack-label record."""
    return {
        "start_utc": start,
        "end_utc": end,
        "attack_type": attack_type,
        "client": "traffic",
    }


def _run_attacks(seed: int) -> tuple[list[dict[str, str]], int]:
    """Run all five labelled synthetic attack workloads."""
    rng = random.Random(seed + 1)
    labels: list[dict[str, str]] = []
    request_count = 0

    scan_paths = list(ATTACK_PATHS["path_scanning"])
    rng.shuffle(scan_paths)
    start = _utc_now()
    for path in scan_paths:
        _send(path)
        request_count += 1
    labels.append(_attack_label("path_scanning", start, _utc_now()))

    start = _utc_now()
    for path in ATTACK_PATHS["sql_injection"]:
        _send(path)
        request_count += 1
    labels.append(_attack_label("sql_injection", start, _utc_now()))

    start = _utc_now()
    for path in ATTACK_PATHS["path_traversal"]:
        _send(path)
        request_count += 1
    labels.append(_attack_label("path_traversal", start, _utc_now()))

    start = _utc_now()
    for index in range(8):
        credentials = urlencode({"username": "admin", "password": f"guess-{index}"}).encode()
        _send("/login", method="POST", data=credentials)
        request_count += 1
    labels.append(_attack_label("login_brute_force", start, _utc_now()))

    start = _utc_now()
    for path in ATTACK_PATHS["low_and_slow_scan"]:
        _send(path)
        request_count += 1
        time.sleep(0.4)
    labels.append(_attack_label("low_and_slow_scan", start, _utc_now()))
    return labels, request_count


def _parser() -> argparse.ArgumentParser:
    """Create the traffic generator CLI without a target-host override."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--benign-count", type=int, default=48)
    parser.add_argument("--duration-seconds", type=float, default=6.0)
    parser.add_argument("--output", type=Path, default=Path("/app/output/labels.jsonl"))
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate benign and attack traffic and write canonical JSONL labels."""
    args = _parser().parse_args(argv)
    if args.benign_count < 0 or args.duration_seconds <= 0:
        raise ValueError("benign count must be non-negative and duration must be positive")
    rng = random.Random(args.seed)
    benign_paths = ["/", "/index.html", "/assets/site.css", "/missing-benign"]
    request_count = 0
    try:
        for delay in benign_delays(args.benign_count, args.duration_seconds):
            time.sleep(delay)
            path = rng.choice(benign_paths)
            if rng.random() < 0.2:
                path += "?" + urlencode({"session": rng.randrange(1000, 9999)})
            _send(path)
            request_count += 1
        _send("/upstream/synthetic-outage")
        request_count += 1
        labels, attack_requests = _run_attacks(args.seed)
        request_count += attack_requests
    except (OSError, ValueError) as error:
        print(f"traffic generation failed: {error}")
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as output:
        for label in labels:
            output.write(_canonical_json(label) + b"\n")
    print(
        _canonical_json(
            {
                "attack_count": len(labels),
                "labels": str(args.output),
                "request_count": request_count,
                "seed": args.seed,
                "target": BASE_URL,
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
