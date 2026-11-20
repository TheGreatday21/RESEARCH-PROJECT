"""Run DuckDB queries against read-only Parquet views of derived evidence."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import duckdb


@dataclass(frozen=True)
class QueryResult:
    """Hold query columns and rows without keeping a database connection open."""

    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-compatible query output."""
        return {
            "columns": list(self.columns),
            "rows": [[_json_value(value) for value in row] for row in self.rows],
            "row_count": len(self.rows),
        }


def _json_value(value: Any) -> Any:
    """Convert common DuckDB values into explicit JSON representations."""
    if isinstance(value, bytes):
        return {"$bytes_base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime | date | time | Decimal | UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    return value


def _parquet_literal(path: Path) -> str:
    """Quote an absolute Parquet path for DuckDB's read_parquet table function."""
    resolved = str(path.resolve()).replace("'", "''")
    return f"'{resolved}'"


def run_query(derived_directory: Path, query: str) -> QueryResult:
    """Register access and error as Parquet-backed views and execute one query."""
    if not query.strip():
        raise ValueError("SQL query must not be empty")
    access_path = derived_directory / "access.parquet"
    error_path = derived_directory / "error.parquet"
    for path in (access_path, error_path):
        if not path.is_file():
            raise FileNotFoundError(f"derived table not found: {path}")

    connection = duckdb.connect(":memory:")
    try:
        connection.execute(
            "CREATE VIEW access AS SELECT * FROM read_parquet("
            f"{_parquet_literal(access_path)})"
        )
        connection.execute(
            "CREATE VIEW error AS SELECT * FROM read_parquet("
            f"{_parquet_literal(error_path)})"
        )
        cursor = connection.execute(query)
        description = cursor.description
        if description is None:
            raise ValueError("SQL query did not return a result set")
        columns = tuple(str(item[0]) for item in description)
        rows = tuple(tuple(row) for row in cursor.fetchall())
        return QueryResult(columns, rows)
    finally:
        connection.close()
