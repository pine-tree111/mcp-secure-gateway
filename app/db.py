"""Read-only SQLite connection manager with opcode timeout and query runner.

Enforces driver-level mode=ro and opcode timeouts
"""

import json
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.errors import (
    PathTraversalError,
    PayloadTooLargeError,
    QueryTimeoutError,
    SecurityViolationError,
)
from app.masker import is_sensitive_column


def resolve_database_path(database_path: Path, project_root: Path) -> Path:
    """Resolve and sandbox SQLite database path against project root.

    Raises:
        PathTraversalError: If path escapes sandbox boundary.
        FileNotFoundError: If database file does not exist.
    """
    root = project_root.resolve(strict=True)
    resolved = (root / database_path).resolve()

    if not resolved.is_relative_to(root):
        raise PathTraversalError(
            f"Database path '{database_path}' escapes project boundary '{root}'"
        )

    if not resolved.exists():
        raise FileNotFoundError(f"Database file '{resolved}' does not exist")

    return resolved


@contextmanager
def get_connection(
    db_path: Path,
    timeout_seconds: float = 2.0,
) -> Generator[sqlite3.Connection, None, None]:
    """Provide a read-only SQLite connection with opcode execution timeout.

    Ref: context-managed connection lifecycle.

    Raises:
        sqlite3.OperationalError: If connection cannot be opened in mode=ro.
    """
    resolved_path = db_path.resolve()
    uri = f"file:{resolved_path}?mode=ro"

    conn = sqlite3.connect(
        uri,
        uri=True,
        check_same_thread=False,
        autocommit=False,
    )

    start_time = time.monotonic()

    def _progress_handler() -> int:
        if time.monotonic() - start_time > timeout_seconds:
            return 1
        return 0

    conn.set_progress_handler(_progress_handler, 1000)

    try:
        yield conn
    finally:
        conn.set_progress_handler(None, 0)
        conn.close()


def get_schema_metadata(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Extract schema metadata including table names, columns, and sensitivity flags."""
    cursor = conn.cursor()
    query = (
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    )
    cursor.execute(query)
    tables = [row[0] for row in cursor.fetchall()]

    schema: list[dict[str, Any]] = []
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table})")
        columns: list[dict[str, Any]] = []
        for col in cursor.fetchall():
            col_name = str(col[1])
            col_type = str(col[2])
            columns.append(
                {
                    "name": col_name,
                    "type": col_type,
                    "sensitive": is_sensitive_column(col_name),
                }
            )
        schema.append(
            {
                "table_name": table,
                "columns": columns,
            }
        )

    return schema


def run_safe_query(
    conn: sqlite3.Connection,
    sanitized_sql: str,
    *,
    max_rows: int = 100,
    max_payload_bytes: int = 65536,
    timeout_seconds: float = 2.0,
) -> list[dict[str, Any]]:
    """Execute pre-sanitized SQL query and verify payload size caps.

    Raises:
        QueryTimeoutError: If execution exceeds opcode/time threshold.
        SecurityViolationError: If driver-level mode=ro blocks an attempted write.
        PayloadTooLargeError: If serialized result exceeds max_payload_bytes.
    """
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row

    try:
        cursor.execute(sanitized_sql)
        rows = cursor.fetchmany(max_rows)
    except sqlite3.OperationalError as err:
        err_msg = str(err).lower()
        if "interrupted" in err_msg or "abort" in err_msg:
            raise QueryTimeoutError(
                f"Query execution exceeded {timeout_seconds}s timeout"
            ) from err
        if "readonly" in err_msg or "attempt to write a readonly database" in err_msg:
            raise SecurityViolationError(
                "Driver-level write rejection: database is opened in mode=ro"
            ) from err
        raise

    results = [dict(row) for row in rows]

    serialized = json.dumps(results, default=str)
    payload_size = len(serialized.encode("utf-8"))
    if payload_size > max_payload_bytes:
        msg = f"Query result size ({payload_size} B) exceeds limit ({max_payload_bytes} B)"
        raise PayloadTooLargeError(msg)

    return results
