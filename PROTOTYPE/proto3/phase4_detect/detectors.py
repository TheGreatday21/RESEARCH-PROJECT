"""Transparent rule-based detectors for web attack patterns in nginx access logs.

Every detection names its rule, class, and a human-readable reason, and carries
the row reference (artifact, line, byte offset) needed to find the original
bytes. The rules are deliberately simple so an examiner can explain each one.
They are signatures and heuristics, not proof of intent.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import unquote

from phase4_detect.features import RequestFeatures

ATTACK_CLASSES = ("path_scan", "sqli_like", "traversal", "brute_force", "low_slow")

_SENSITIVE_PATH = re.compile(
    r"(?:^|/)\.(?:git|svn|hg|env|htaccess|htpasswd|ds_store)(?:/|$)"
    r"|(?:^|/)wp-(?:admin|login|content|includes)"
    r"|(?:^|/)(?:phpmyadmin|pma|adminer)(?:/|$)"
    r"|(?:^|/)server-(?:status|info)(?:/|$)"
    r"|(?:^|/)backups?(?:[./_-]|$)"
    r"|\.(?:zip|tar|tgz|7z|bak|old|sql|swp)$"
)
_TRAVERSAL = re.compile(r"\.\.[/\\]")
_SENSITIVE_FILE = re.compile(r"/etc/(?:passwd|shadow)|boot\.ini|win\.ini")
_SQLI_PATTERNS = (
    ("UNION SELECT", re.compile(r"\bunion\b[\s/*]+(?:all[\s/*]+)?select\b")),
    ("tautology", re.compile(r"\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+")),
    ("stacked statement", re.compile(r";\s*(?:drop|delete|insert|update|alter|truncate)\b")),
    ("time-delay function", re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay")),
    ("information_schema", re.compile(r"information_schema")),
    ("quoted comment terminator", re.compile(r"['\"]\s*;?\s*--")),
    (
        "RCE / command execution",
        re.compile(r"\b(?:shell_exec|call_user_func_array|invokefunction)\b"),
    ),
)
_LOGIN_PATH = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|log-in|auth|authenticate|wp-login\.php|xmlrpc\.php)(?:/|$|\.)"
)
_TRAILING_NUMBER = re.compile(r"^(?P<prefix>.*?)(?P<number>\d+)(?P<suffix>\.[A-Za-z0-9]+)?$")


@dataclass(frozen=True)
class DetectorConfig:
    """Tunable thresholds, recorded in every detection report for reproducibility."""

    brute_force_attempts: int = 5
    brute_force_window_seconds: float = 60.0
    enumeration_min_distinct: int = 4
    enumeration_window_seconds: float = 3600.0

    def to_dict(self) -> dict[str, Any]:
        """Return the thresholds as JSON-compatible values."""
        return {
            "brute_force_attempts": self.brute_force_attempts,
            "brute_force_window_seconds": self.brute_force_window_seconds,
            "enumeration_min_distinct": self.enumeration_min_distinct,
            "enumeration_window_seconds": self.enumeration_window_seconds,
        }


@dataclass(frozen=True)
class Detection:
    """One rule firing on one access row."""

    detector: str
    attack_class: str
    confidence: str  # "high" or "medium"
    reason: str
    artifact_path: str
    line_no: int
    byte_offset: int
    trace_id: str | None
    ts_utc: str
    remote_addr: str
    uri_raw: str
    status: int | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible detection."""
        return {
            "detector": self.detector,
            "attack_class": self.attack_class,
            "confidence": self.confidence,
            "reason": self.reason,
            "artifact_path": self.artifact_path,
            "line_no": self.line_no,
            "byte_offset": self.byte_offset,
            "trace_id": self.trace_id,
            "ts_utc": self.ts_utc,
            "remote_addr": self.remote_addr,
            "uri_raw": self.uri_raw,
            "status": self.status,
        }


def _detection(
    item: RequestFeatures, detector: str, attack_class: str, confidence: str, reason: str
) -> Detection:
    return Detection(
        detector=detector,
        attack_class=attack_class,
        confidence=confidence,
        reason=reason,
        artifact_path=item.artifact_path,
        line_no=item.line_no,
        byte_offset=item.byte_offset,
        trace_id=item.trace_id,
        ts_utc=item.ts.isoformat().replace("+00:00", "Z"),
        remote_addr=item.remote_addr,
        uri_raw=item.uri_raw,
        status=item.status,
    )


def _decoded_views(item: RequestFeatures) -> list[str]:
    """Return the request target decoded once and twice, lowercased, to catch double encoding."""
    # The parser percent-decodes but keeps "+"; in a query string "+" means a space.
    query = item.query_decoded.replace("+", " ")
    once = f"{item.path_decoded} {query}".lower()
    twice = unquote(once, errors="replace")
    return [once] if twice == once else [once, twice]


def detect_traversal(item: RequestFeatures) -> Detection | None:
    """Flag ``../`` sequences (including percent-encoded) and well-known secret files."""
    for view in _decoded_views(item):
        if _TRAVERSAL.search(view):
            return _detection(
                item, "traversal_sequence", "traversal", "high", "directory traversal sequence"
            )
    for view in _decoded_views(item):
        if _SENSITIVE_FILE.search(view):
            return _detection(
                item, "sensitive_file", "traversal", "medium", "request for a system secret file"
            )
    return None


def detect_sqli(item: RequestFeatures) -> Detection | None:
    """Flag common SQL injection fragments in the decoded path and query."""
    for view in _decoded_views(item):
        for name, pattern in _SQLI_PATTERNS:
            if pattern.search(view):
                return _detection(
                    item, "sqli_signature", "sqli_like", "high", f"SQL fragment: {name}"
                )
    return None


def detect_sensitive_path(item: RequestFeatures) -> Detection | None:
    """Flag probes for VCS metadata, admin consoles, status pages, and backup archives."""
    if _SENSITIVE_PATH.search(item.path_decoded.lower()):
        return _detection(
            item,
            "sensitive_path",
            "path_scan",
            "high",
            "probe of a commonly scanned sensitive path",
        )
    return None


def _window_runs(
    items: list[RequestFeatures], window: timedelta, minimum: int
) -> set[tuple[str, int, int]]:
    """Return keys of every row inside any time window holding at least ``minimum`` rows."""
    ordered = sorted(items, key=lambda value: (value.ts, value.key))
    marked: set[tuple[str, int, int]] = set()
    start = 0
    for end, item in enumerate(ordered):
        while item.ts - ordered[start].ts > window:
            start += 1
        if end - start + 1 >= minimum:
            marked.update(value.key for value in ordered[start : end + 1])
    return marked


def detect_brute_force(
    features: list[RequestFeatures], config: DetectorConfig
) -> list[Detection]:
    """Flag bursts of POSTs to one login-like path from one client."""
    groups: dict[tuple[str, str], list[RequestFeatures]] = defaultdict(list)
    for item in features:
        if item.method == "POST" and _LOGIN_PATH.search(item.path_decoded.lower()):
            groups[(item.remote_addr, item.path_decoded)].append(item)
    window = timedelta(seconds=config.brute_force_window_seconds)
    detections: list[Detection] = []
    for (address, path), items in sorted(groups.items()):
        marked = _window_runs(items, window, config.brute_force_attempts)
        for item in items:
            if item.key in marked:
                detections.append(
                    _detection(
                        item,
                        "login_burst",
                        "brute_force",
                        "high",
                        f"{config.brute_force_attempts}+ POSTs to {path} from {address} "
                        f"within {config.brute_force_window_seconds:g} s",
                    )
                )
    return detections


def _enumeration_template(path: str) -> tuple[str, int] | None:
    """Split ``/hidden-03`` into (``/hidden-#``, 3); None when the last segment has no number."""
    head, separator, last = path.rpartition("/")
    match = _TRAILING_NUMBER.match(last)
    if match is None:
        return None
    template = f"{head}{separator}{match.group('prefix')}#{match.group('suffix') or ''}"
    return template, int(match.group("number"))


def detect_enumeration(
    features: list[RequestFeatures], config: DetectorConfig
) -> list[Detection]:
    """Flag one client walking numbered resources that mostly do not exist.

    Counting distinct failed resources inside a long window finds scanners that
    stay below any request-rate threshold.
    """
    groups: dict[tuple[str, str], list[tuple[RequestFeatures, int]]] = defaultdict(list)
    for item in features:
        if item.status not in (401, 403, 404):
            continue
        template = _enumeration_template(item.path_decoded)
        if template is not None:
            groups[(item.remote_addr, template[0])].append((item, template[1]))
    window = timedelta(seconds=config.enumeration_window_seconds)
    detections: list[Detection] = []
    for (address, pattern), pairs in sorted(groups.items()):
        ordered = sorted(pairs, key=lambda pair: (pair[0].ts, pair[0].key))
        marked: set[tuple[str, int, int]] = set()
        start = 0
        for end, (item, _) in enumerate(ordered):
            while item.ts - ordered[start][0].ts > window:
                start += 1
            span = ordered[start : end + 1]
            if len({number for _, number in span}) >= config.enumeration_min_distinct:
                marked.update(value.key for value, _ in span)
        for item, _ in ordered:
            if item.key in marked:
                detections.append(
                    _detection(
                        item,
                        "numbered_enumeration",
                        "low_slow",
                        "medium",
                        f"{address} requested {config.enumeration_min_distinct}+ distinct "
                        f"missing resources matching {pattern}",
                    )
                )
    return detections


def run_detectors(
    features: list[RequestFeatures], config: DetectorConfig | None = None
) -> list[Detection]:
    """Run every rule and return detections in deterministic row order."""
    config = config or DetectorConfig()
    detections: list[Detection] = []
    for item in features:
        for rule in (detect_traversal, detect_sqli, detect_sensitive_path):
            found = rule(item)
            if found is not None:
                detections.append(found)
    detections.extend(detect_brute_force(features, config))
    detections.extend(detect_enumeration(features, config))
    return sorted(
        detections,
        key=lambda value: (value.ts_utc, value.artifact_path, value.line_no, value.detector),
    )
