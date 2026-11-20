"""Extract per-request and per-client features from the derived access table."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")


def parse_utc(value: str) -> datetime:
    """Parse the parser's UTC ISO timestamps (``...Z``) into aware datetimes."""
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class RequestFeatures:
    """One parsed access request, with the provenance needed to find its original bytes."""

    artifact_path: str
    line_no: int
    byte_offset: int
    trace_id: str | None
    ts: datetime
    remote_addr: str
    method: str
    uri_raw: str
    path: str
    path_decoded: str
    query_decoded: str
    status: int | None
    user_agent: str
    path_depth: int
    query_length: int
    encoded_char_count: int
    user_agent_empty: bool

    @property
    def status_class(self) -> int | None:
        """Return the leading status digit (2, 4, 5, ...) or None when status is unknown."""
        return None if self.status is None else self.status // 100

    @property
    def key(self) -> tuple[str, int, int]:
        """Stable row identity: artifact, line number, byte offset."""
        return (self.artifact_path, self.line_no, self.byte_offset)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible view without losing the row reference."""
        return {
            "artifact_path": self.artifact_path,
            "line_no": self.line_no,
            "byte_offset": self.byte_offset,
            "trace_id": self.trace_id,
            "ts_utc": self.ts.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "remote_addr": self.remote_addr,
            "method": self.method,
            "uri_raw": self.uri_raw,
            "status": self.status,
            "path_depth": self.path_depth,
            "query_length": self.query_length,
            "encoded_char_count": self.encoded_char_count,
            "user_agent_empty": self.user_agent_empty,
        }


@dataclass(frozen=True)
class ClientSummary:
    """Aggregate behaviour of one remote address across the whole acquisition."""

    remote_addr: str
    requests: int
    distinct_paths: int
    client_errors: int
    distinct_404_paths: int
    first_ts: datetime
    last_ts: datetime

    @property
    def client_error_ratio(self) -> float:
        """Fraction of this client's requests that returned a 4xx status."""
        return self.client_errors / self.requests if self.requests else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible summary."""

        def stamp(value: datetime) -> str:
            return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

        return {
            "remote_addr": self.remote_addr,
            "requests": self.requests,
            "distinct_paths": self.distinct_paths,
            "client_errors": self.client_errors,
            "client_error_ratio": round(self.client_error_ratio, 4),
            "distinct_404_paths": self.distinct_404_paths,
            "first_ts_utc": stamp(self.first_ts),
            "last_ts_utc": stamp(self.last_ts),
        }


_ACCESS_FEATURE_SQL = """\
SELECT artifact_path, line_no, byte_offset, trace_id, ts_utc, remote_addr, method,
       uri_raw, path, path_decoded, query_decoded, status, user_agent
FROM read_parquet({path!r})
WHERE parse_ok AND ts_utc IS NOT NULL AND method IS NOT NULL
ORDER BY ts_utc, artifact_path, line_no
"""


def extract_request_features(derived_directory: Path) -> list[RequestFeatures]:
    """Read parsed access rows in time order and compute per-request features.

    Rows that failed parsing or lack a UTC timestamp are not scored; they remain
    visible through the parse report and the timeline's ``unparsed_count``.
    """
    access_path = derived_directory / "access.parquet"
    if not access_path.is_file():
        raise FileNotFoundError(f"derived table not found: {access_path}")
    connection = duckdb.connect(":memory:")
    try:
        rows = connection.execute(
            _ACCESS_FEATURE_SQL.format(path=str(access_path.resolve()))
        ).fetchall()
    finally:
        connection.close()

    features: list[RequestFeatures] = []
    for (
        artifact_path,
        line_no,
        byte_offset,
        trace_id,
        ts_utc,
        remote_addr,
        method,
        uri_raw,
        path,
        path_decoded,
        query_decoded,
        status,
        user_agent,
    ) in rows:
        path_text = str(path or "")
        decoded_path = str(path_decoded or "")
        decoded_query = str(query_decoded or "")
        uri_text = str(uri_raw or "")
        agent = str(user_agent or "")
        features.append(
            RequestFeatures(
                artifact_path=str(artifact_path),
                line_no=int(line_no),
                byte_offset=int(byte_offset),
                trace_id=str(trace_id) if trace_id not in (None, "", "-") else None,
                ts=parse_utc(str(ts_utc)),
                remote_addr=str(remote_addr or ""),
                method=str(method),
                uri_raw=uri_text,
                path=path_text,
                path_decoded=decoded_path,
                query_decoded=decoded_query,
                status=int(status) if status is not None else None,
                user_agent=agent,
                path_depth=len([part for part in decoded_path.split("/") if part]),
                query_length=len(decoded_query),
                encoded_char_count=len(_ENCODED.findall(uri_text)),
                user_agent_empty=agent in ("", "-"),
            )
        )
    return features


def summarize_clients(features: list[RequestFeatures]) -> list[ClientSummary]:
    """Aggregate request features per remote address, ordered by address."""
    grouped: dict[str, list[RequestFeatures]] = defaultdict(list)
    for item in features:
        grouped[item.remote_addr].append(item)
    summaries: list[ClientSummary] = []
    for address in sorted(grouped):
        items = grouped[address]
        summaries.append(
            ClientSummary(
                remote_addr=address,
                requests=len(items),
                distinct_paths=len({item.path_decoded for item in items}),
                client_errors=sum(item.status_class == 4 for item in items),
                distinct_404_paths=len({item.path_decoded for item in items if item.status == 404}),
                first_ts=min(item.ts for item in items),
                last_ts=max(item.ts for item in items),
            )
        )
    return summaries
