"""Unit tests for read-only SQLite engine, opcode timeout, and schema metadata."""

import sqlite3
from pathlib import Path

import pytest

from app.db import (
    get_connection,
    get_schema_metadata,
    resolve_database_path,
    run_safe_query,
)
from app.errors import (
    PathTraversalError,
    PayloadTooLargeError,
    QueryTimeoutError,
    SecurityViolationError,
)


def test_resolve_database_path_valid(populated_db: Path, tmp_path: Path) -> None:
    """Verify valid database path resolves cleanly."""
    resolved = resolve_database_path(populated_db, tmp_path)
    assert resolved == populated_db


def test_resolve_database_path_traversal(tmp_path: Path) -> None:
    """Verify path traversal escapes raise PathTraversalError."""
    with pytest.raises(PathTraversalError):
        resolve_database_path(Path("../outside.db"), tmp_path)


def test_resolve_database_path_nonexistent(tmp_path: Path) -> None:
    """Verify missing database file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        resolve_database_path(Path("missing.db"), tmp_path)


def test_mode_ro_prevents_writes(populated_db: Path) -> None:
    """Verify connection in mode=ro raises OperationalError on write attempts."""
    with get_connection(populated_db) as conn:
        cursor = conn.cursor()
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            cursor.execute(
                "INSERT INTO products (title, category, price, stock) VALUES ('X', 'Y', 1, 1)"
            )


def test_get_schema_metadata(populated_db: Path) -> None:
    """Verify schema metadata extraction and sensitivity labeling."""
    with get_connection(populated_db) as conn:
        schema = get_schema_metadata(conn)

    tables = {table["table_name"] for table in schema}
    assert "customers" in tables
    assert "products" in tables
    assert "orders" in tables

    cust_table = next(t for t in schema if t["table_name"] == "customers")
    col_dict = {col["name"]: col["sensitive"] for col in cust_table["columns"]}
    assert col_dict["email"] is True
    assert col_dict["phone"] is True
    assert col_dict["ssn"] is True
    assert col_dict["name"] is False


def test_run_safe_query_success(populated_db: Path) -> None:
    """Verify query execution returns dictionaries."""
    with get_connection(populated_db) as conn:
        rows = run_safe_query(conn, "SELECT id, title, price FROM products LIMIT 2")
    assert len(rows) == 2
    assert "title" in rows[0]
    assert "price" in rows[0]


def test_run_safe_query_write_rejected(populated_db: Path) -> None:
    """Verify write attempts via run_safe_query raise SecurityViolationError."""
    with get_connection(populated_db) as conn:
        with pytest.raises(SecurityViolationError, match="mode=ro"):
            run_safe_query(
                conn,
                "INSERT INTO products (title, category, price, stock) VALUES ('A', 'B', 1, 1)",
            )


def test_run_safe_query_payload_limit(populated_db: Path) -> None:
    """Verify oversized query results trigger PayloadTooLargeError."""
    with get_connection(populated_db) as conn:
        with pytest.raises(PayloadTooLargeError, match="exceeds limit"):
            run_safe_query(conn, "SELECT * FROM products", max_payload_bytes=50)


def test_opcode_timeout_aborts_slow_query(populated_db: Path) -> None:
    """Verify expensive queries abort via QueryTimeoutError."""
    # Recursive CTE creating a large compute loop with a tight 0.05s timeout
    slow_sql = """
    WITH RECURSIVE r(i) AS (
        VALUES(0)
        UNION ALL
        SELECT i + 1 FROM r WHERE i < 10000000
    )
    SELECT count(*) FROM r;
    """
    with get_connection(populated_db, timeout_seconds=0.05) as conn:
        with pytest.raises(QueryTimeoutError, match="timeout"):
            run_safe_query(conn, slow_sql, timeout_seconds=0.05)
