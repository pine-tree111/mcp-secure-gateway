"""Unit tests for sqlglot AST SQL validator, mutation rejection, and LIMIT clamp."""

import pytest

from app.errors import SecurityViolationError
from app.validator import validate_and_sanitize_sql


def test_simple_select_injects_limit() -> None:
    """Verify plain SELECT without LIMIT gets LIMIT injected."""
    result = validate_and_sanitize_sql("SELECT id, name FROM users", max_rows=100)
    assert "LIMIT 100" in result.upper()
    assert "FROM users" in result


def test_select_preserves_smaller_limit() -> None:
    """Verify user LIMIT smaller than max_rows is preserved."""
    result = validate_and_sanitize_sql("SELECT id FROM users LIMIT 25", max_rows=100)
    assert "LIMIT 25" in result.upper()


def test_select_clamps_excessive_limit() -> None:
    """Verify user LIMIT exceeding max_rows is clamped to max_rows."""
    result = validate_and_sanitize_sql("SELECT id FROM users LIMIT 5000", max_rows=100)
    assert "LIMIT 100" in result.upper()
    assert "5000" not in result


def test_union_query_clamped() -> None:
    """Verify UNION query is allowed and clamped."""
    result = validate_and_sanitize_sql(
        "SELECT id FROM a UNION SELECT id FROM b", max_rows=50
    )
    assert "UNION" in result.upper()
    assert "LIMIT 50" in result.upper()


def test_empty_query_rejected() -> None:
    """Verify empty or whitespace-only queries raise SecurityViolationError."""
    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql("")

    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql("   ")

    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql("-- only a comment\n")


def test_multi_statement_rejected() -> None:
    """Verify multi-statement chaining is rejected."""
    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql("SELECT 1; DROP TABLE users;")


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO users (name) VALUES ('evil')",
        "UPDATE users SET role = 'admin' WHERE id = 1",
        "DELETE FROM users WHERE id = 1",
        "DROP TABLE users",
        "ALTER TABLE users ADD COLUMN balance INT",
        "CREATE TABLE backdoors (id INT)",
        "ATTACH DATABASE 'evil.db' AS evil",
        "PRAGMA table_info(users)",
    ],
)
def test_mutation_statements_rejected(sql: str) -> None:
    """Verify DDL and DML mutation statements raise SecurityViolationError."""
    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT load_extension('evil.so')",
        "SELECT writefile('dest', 'data')",
        "SELECT readfile('/etc/passwd')",
    ],
)
def test_dangerous_functions_rejected(sql: str) -> None:
    """Verify dangerous SQLite functions raise SecurityViolationError."""
    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql(sql)


def test_nested_mutation_in_cte_rejected() -> None:
    """Verify mutations hidden inside CTEs or subqueries are rejected."""
    nested_sql = "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted"
    with pytest.raises(SecurityViolationError):
        validate_and_sanitize_sql(nested_sql)
