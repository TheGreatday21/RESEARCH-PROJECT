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
from uuid import uuid4

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


def validate_base_url(base_url: str) -> str:
    """Validate and normalize an explicit HTTP(S) base URL without credentials."""
    parsed = urlsplit(base_url.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"invalid base URL: {base_url!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def lab_url(path: str, base_url: str = BASE_URL) -> str:
    """Join a request path while rejecting every destination outside the chosen base URL."""
    origin = validate_base_url(base_url)
    origin_parsed = urlsplit(origin)
    url = urljoin(origin + "/", path)
    parsed = urlsplit(url)
    if (
        parsed.scheme != origin_parsed.scheme
        or parsed.netloc != origin_parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"traffic is restricted to {origin}")
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


def _send(
    path: str,
    *,
    trace_id: str,
    method: str = "GET",
    data: bytes | None = None,
    base_url: str = BASE_URL,
) -> int:
    """Send one traced test request and return its HTTP status, including errors."""
    request = urllib.request.Request(
        lab_url(path, base_url=base_url),
        data=data,
        method=method,
        headers={
            "User-Agent": "lapa-synthetic-traffic/0.2",
            "X-Lapa-Trace": trace_id,
        },
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


def _request_label(
    path: str,
    *,
    request_class: str,
    scenario_id: str,
    seed: int,
    method: str = "GET",
    data: bytes | None = None,
    base_url: str = BASE_URL,
) -> dict[str, Any]:
    """Send and label one request with its unique ground-truth trace ID."""
    trace_id = str(uuid4())
    start = _utc_now()
    if base_url == BASE_URL:
        _send(path, method=method, data=data, trace_id=trace_id)
    else:
        _send(path, method=method, data=data, trace_id=trace_id, base_url=base_url)
    return {
        "trace_id": trace_id,
        "class": request_class,
        "scenario_id": scenario_id,
        "seed": seed,
        "start_utc": start,
    }


def _run_attacks(seed: int, *, base_url: str = BASE_URL) -> list[dict[str, Any]]:
    """Run all five labelled synthetic attack workloads."""
    rng = random.Random(seed + 1)
    labels: list[dict[str, Any]] = []

    scan_paths = list(ATTACK_PATHS["path_scanning"])
    rng.shuffle(scan_paths)
    for path in scan_paths:
        labels.append(
            _request_label(
                path,
                request_class="path_scan",
                scenario_id="live-path-scan",
                seed=seed,
                base_url=base_url,
            )
        )
    for path in ATTACK_PATHS["sql_injection"]:
        labels.append(
            _request_label(
                path,
                request_class="sqli_like",
                scenario_id="live-sqli",
                seed=seed,
                base_url=base_url,
            )
        )
    for path in ATTACK_PATHS["path_traversal"]:
        labels.append(
            _request_label(
                path,
                request_class="traversal",
                scenario_id="live-traversal",
                seed=seed,
                base_url=base_url,
            )
        )
    for index in range(8):
        credentials = urlencode({"username": "admin", "password": f"guess-{index}"}).encode()
        labels.append(
            _request_label(
                "/login",
                request_class="brute_force",
                scenario_id="live-brute-force",
                seed=seed,
                method="POST",
                data=credentials,
                base_url=base_url,
            )
        )
    for path in ATTACK_PATHS["low_and_slow_scan"]:
        labels.append(
            _request_label(
                path,
                request_class="low_slow",
                scenario_id="live-low-slow",
                seed=seed,
                base_url=base_url,
            )
        )
        time.sleep(0.4)
    return labels


def _parser() -> argparse.ArgumentParser:
    """Create the traffic generator CLI (defaulting to http://target for Docker Compose)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--benign-count", type=int, default=48)
    parser.add_argument("--duration-seconds", type=float, default=6.0)
    parser.add_argument("--output", type=Path, default=Path("/out/labels.jsonl"))
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate benign and attack traffic and write canonical JSONL labels."""
    args = _parser().parse_args(argv)
    base_url = validate_base_url(args.base_url)
    if args.benign_count < 0 or args.duration_seconds <= 0:
        raise ValueError("benign count must be non-negative and duration must be positive")
    rng = random.Random(args.seed)
    benign_paths = ["/", "/index.html", "/assets/site.css", "/missing-benign"]
    labels: list[dict[str, Any]] = []
    try:
        for index, delay in enumerate(benign_delays(args.benign_count, args.duration_seconds)):
            time.sleep(delay)
            path = rng.choice(benign_paths)
            if rng.random() < 0.2:
                path += "?" + urlencode({"session": rng.randrange(1000, 9999)})
            labels.append(
                _request_label(
                    path,
                    request_class="benign",
                    scenario_id=f"live-benign-{index:04d}",
                    seed=args.seed,
                    base_url=base_url,
                )
            )
        labels.append(
            _request_label(
                "/upstream/synthetic-outage",
                request_class="benign",
                scenario_id="live-synthetic-outage",
                seed=args.seed,
                base_url=base_url,
            )
        )
        labels.extend(_run_attacks(args.seed, base_url=base_url))
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
                "attack_count": sum(label["class"] != "benign" for label in labels),
                "labels": str(args.output),
                "request_count": len(labels),
                "seed": args.seed,
                "target": base_url,
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
