"""Unsupervised Isolation Forest anomaly detection over parsed nginx access logs.

Implements the Isolation Forest algorithm in deterministic pure Python so it requires
no native C/Fortran extensions while producing reproducible anomaly scores s(x, n) in
(0, 1] linked to exact log-row provenance (artifact_path, line_no, byte_offset).
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from phase4_detect.features import RequestFeatures

EULER_GAMMA = 0.5772156649015329
FEATURE_NAMES = (
    "uri_length",
    "path_depth",
    "query_length",
    "encoded_char_count",
    "special_char_count",
    "status_severity",
    "client_burst_60s",
    "client_error_ratio",
)
_SPECIAL_CHARS = frozenset("'\"`;|()\\<>[]$")


@dataclass(frozen=True)
class IsolationForestConfig:
    """Hyperparameters for the Isolation Forest detector."""

    n_trees: int = 100
    max_samples: int = 256
    contamination: float = 0.05
    min_score_threshold: float = 0.60
    seed: int = 42

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": "IsolationForest",
            "n_trees": self.n_trees,
            "max_samples": self.max_samples,
            "contamination": self.contamination,
            "min_score_threshold": self.min_score_threshold,
            "seed": self.seed,
            "features": list(FEATURE_NAMES),
        }


@dataclass(frozen=True)
class AnomalyRecord:
    """One access-log request scored as anomalous by the Isolation Forest."""

    rank: int
    anomaly_score: float
    top_features: tuple[str, ...]
    artifact_path: str
    line_no: int
    byte_offset: int
    trace_id: str | None
    ts_utc: str
    remote_addr: str
    method: str
    uri_raw: str
    status: int | None
    feature_values: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "anomaly_score": round(self.anomaly_score, 4),
            "top_features": list(self.top_features),
            "artifact_path": self.artifact_path,
            "line_no": self.line_no,
            "byte_offset": self.byte_offset,
            "trace_id": self.trace_id,
            "ts_utc": self.ts_utc,
            "remote_addr": self.remote_addr,
            "method": self.method,
            "uri_raw": self.uri_raw,
            "status": self.status,
            "feature_values": {k: round(v, 4) for k, v in self.feature_values.items()},
        }


@dataclass(frozen=True)
class IsolationForestResult:
    """Summary and top anomalous rows from an Isolation Forest run."""

    config: IsolationForestConfig
    total_scored: int
    anomaly_count: int
    threshold_used: float
    score_min: float
    score_median: float
    score_p95: float
    score_max: float
    anomalies: tuple[AnomalyRecord, ...]
    all_scores: tuple[float, ...]

    def to_dict(self, *, max_anomalies: int = 25) -> dict[str, Any]:
        return {
            "model": self.config.to_dict(),
            "total_scored": self.total_scored,
            "anomaly_count": self.anomaly_count,
            "threshold_used": round(self.threshold_used, 4),
            "score_distribution": {
                "min": round(self.score_min, 4),
                "median": round(self.score_median, 4),
                "p95": round(self.score_p95, 4),
                "max": round(self.score_max, 4),
            },
            "anomalies": [item.to_dict() for item in self.anomalies[:max_anomalies]],
        }


def _c_factor(n: int) -> float:
    """Average path length of unsuccessful BST search, c(n) in Liu et al. (2008)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    harmonic = math.log(n - 1.0) + EULER_GAMMA
    return 2.0 * harmonic - (2.0 * (n - 1.0) / n)


@dataclass(frozen=True)
class _ITreeNode:
    size: int
    split_attr: int | None = None
    split_val: float | None = None
    left: _ITreeNode | None = None
    right: _ITreeNode | None = None


def _build_itree(
    vectors: Sequence[tuple[float, ...]],
    depth: int,
    height_limit: int,
    rng: random.Random,
) -> _ITreeNode:
    n = len(vectors)
    if depth >= height_limit or n <= 1:
        return _ITreeNode(size=n)

    num_features = len(vectors[0])
    candidate_attrs: list[tuple[int, float, float]] = []
    for attr in range(num_features):
        col = [row[attr] for row in vectors]
        lo, hi = min(col), max(col)
        if lo < hi:
            candidate_attrs.append((attr, lo, hi))

    if not candidate_attrs:
        return _ITreeNode(size=n)

    attr, lo, hi = rng.choice(candidate_attrs)
    split_val = rng.uniform(lo, hi)
    left_vecs = [row for row in vectors if row[attr] < split_val]
    right_vecs = [row for row in vectors if row[attr] >= split_val]
    if not left_vecs or not right_vecs:
        return _ITreeNode(size=n)

    return _ITreeNode(
        size=n,
        split_attr=attr,
        split_val=split_val,
        left=_build_itree(left_vecs, depth + 1, height_limit, rng),
        right=_build_itree(right_vecs, depth + 1, height_limit, rng),
    )


def _path_length(x: tuple[float, ...], node: _ITreeNode, current_depth: int) -> float:
    if node.split_attr is None or node.split_val is None or node.left is None or node.right is None:
        return float(current_depth) + _c_factor(node.size)
    if x[node.split_attr] < node.split_val:
        return _path_length(x, node.left, current_depth + 1)
    return _path_length(x, node.right, current_depth + 1)


def _status_severity(status: int | None) -> float:
    if status is None:
        return 2.0
    if status == 400 or status >= 500:
        return 3.0
    if status in (401, 403, 499):
        return 2.0
    if 400 <= status < 500:
        return 1.0
    return 0.0


def build_feature_matrix(features: Sequence[RequestFeatures]) -> list[tuple[float, ...]]:
    """Compute the 8-dimensional numerical feature vector for each request."""
    if not features:
        return []

    by_client: dict[str, list[RequestFeatures]] = defaultdict(list)
    for item in features:
        by_client[item.remote_addr].append(item)

    client_err_ratio: dict[str, float] = {}
    burst_counts: dict[tuple[str, int, int], int] = {}
    window = timedelta(seconds=60.0)

    for addr, items in by_client.items():
        ordered = sorted(items, key=lambda r: (r.ts, r.key))
        errors = sum(1 for r in ordered if r.status is not None and r.status >= 400)
        client_err_ratio[addr] = errors / len(ordered) if ordered else 0.0
        left = 0
        for right, item in enumerate(ordered):
            while item.ts - ordered[left].ts > window:
                left += 1
            burst_counts[item.key] = right - left + 1

    matrix: list[tuple[float, ...]] = []
    for item in features:
        special = sum(1 for ch in item.uri_raw if ch in _SPECIAL_CHARS)
        matrix.append(
            (
                float(len(item.uri_raw)),
                float(item.path_depth),
                float(item.query_length),
                float(item.encoded_char_count),
                float(special),
                _status_severity(item.status),
                float(burst_counts.get(item.key, 1)),
                client_err_ratio.get(item.remote_addr, 0.0),
            )
        )
    return matrix


def _quantile(sorted_vals: Sequence[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(max(int(round(q * (len(sorted_vals) - 1))), 0), len(sorted_vals) - 1)
    return sorted_vals[idx]


def run_isolation_forest(
    features: Sequence[RequestFeatures],
    config: IsolationForestConfig | None = None,
) -> IsolationForestResult:
    """Fit an Isolation Forest on ``features`` and score every request."""
    config = config or IsolationForestConfig()
    n = len(features)
    if n == 0:
        return IsolationForestResult(
            config=config,
            total_scored=0,
            anomaly_count=0,
            threshold_used=config.min_score_threshold,
            score_min=0.0,
            score_median=0.0,
            score_p95=0.0,
            score_max=0.0,
            anomalies=(),
            all_scores=(),
        )

    matrix = build_feature_matrix(features)
    num_dims = len(FEATURE_NAMES)
    means = [sum(row[d] for row in matrix) / n for d in range(num_dims)]
    stds = [
        math.sqrt(sum((row[d] - means[d]) ** 2 for row in matrix) / max(n - 1, 1)) or 1.0
        for d in range(num_dims)
    ]

    sample_size = min(config.max_samples, n)
    height_limit = max(1, int(math.ceil(math.log2(max(sample_size, 2)))))
    c_norm = _c_factor(sample_size) or 1.0
    rng = random.Random(config.seed)

    trees: list[_ITreeNode] = []
    indices = list(range(n))
    for _ in range(config.n_trees):
        chosen = rng.sample(indices, sample_size) if sample_size < n else indices
        subsample = [matrix[i] for i in chosen]
        trees.append(_build_itree(subsample, 0, height_limit, rng))

    scores: list[float] = []
    for vec in matrix:
        avg_path = sum(_path_length(vec, tree, 0) for tree in trees) / len(trees)
        score = 2.0 ** (-avg_path / c_norm)
        scores.append(score)

    sorted_scores = sorted(scores)
    quantile_cutoff = _quantile(sorted_scores, 1.0 - config.contamination)
    threshold = max(config.min_score_threshold, quantile_cutoff)

    flagged_indices = [i for i, s in enumerate(scores) if s >= threshold]
    flagged_indices.sort(key=lambda i: (-scores[i], features[i].line_no))

    anomalies: list[AnomalyRecord] = []
    for rank, idx in enumerate(flagged_indices, start=1):
        item = features[idx]
        vec = matrix[idx]
        z_pairs = sorted(
            ((abs(vec[d] - means[d]) / stds[d], FEATURE_NAMES[d], vec[d]) for d in range(num_dims)),
            reverse=True,
        )
        top_feats = tuple(
            f"{name}={val:g}" for z, name, val in z_pairs[:3] if z > 0.5 or len(z_pairs) > 0
        )[:3]
        anomalies.append(
            AnomalyRecord(
                rank=rank,
                anomaly_score=scores[idx],
                top_features=top_feats,
                artifact_path=item.artifact_path,
                line_no=item.line_no,
                byte_offset=item.byte_offset,
                trace_id=item.trace_id,
                ts_utc=item.ts.isoformat().replace("+00:00", "Z"),
                remote_addr=item.remote_addr,
                method=item.method,
                uri_raw=item.uri_raw,
                status=item.status,
                feature_values=dict(zip(FEATURE_NAMES, vec, strict=True)),
            )
        )

    return IsolationForestResult(
        config=config,
        total_scored=n,
        anomaly_count=len(anomalies),
        threshold_used=threshold,
        score_min=sorted_scores[0],
        score_median=_quantile(sorted_scores, 0.50),
        score_p95=_quantile(sorted_scores, 0.95),
        score_max=sorted_scores[-1],
        anomalies=tuple(anomalies),
        all_scores=tuple(scores),
    )
