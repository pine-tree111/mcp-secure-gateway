"""Automated security penetration test suite mapped to OWASP Top 10 for LLM Applications.

Deterministic penetration verification.
"""

import sqlite3
from pathlib import Path

import pytest

from app.config import Settings
from app.db import get_connection, run_safe_query
from app.errors import (
    PathTraversalError,
    PayloadTooLargeError,
    QueryTimeoutError,
    SecurityViolationError,
    SensitiveFileError,
    SSRFBlockedError,
)
from app.security import read_safe_file, resolve_safe_path, validate_url
from app.tools import SQLInput, query_database
from app.validator import validate_and_sanitize_sql


@pytest.mark.security
def test_llm01_llm02_sql_injection_chaining() -> None:
    """Reject multi-statement SQL injection vectors."""
    vectors = [
        "SELECT 1; DROP TABLE customers;",
        "SELECT id FROM products; INSERT INTO customers VALUES (999, 'hacked');",
        "SELECT 1 /* comment */ ; DELETE FROM orders;",
    ]
    for vector in vectors:
        with pytest.raises(SecurityViolationError):
            validate_and_sanitize_sql(vector)


@pytest.mark.security
def test_llm01_llm02_dangerous_sqlite_functions() -> None:
    """Reject dangerous SQLite C extension and file I/O functions."""
    banned = [
        "SELECT load_extension('malware.so')",
        "SELECT writefile('/tmp/pwn.txt', 'evil')",
        "SELECT readfile('/etc/shadow')",
    ]
    for sql in banned:
        with pytest.raises(SecurityViolationError):
            validate_and_sanitize_sql(sql)


@pytest.mark.security
def test_llm04_resource_dos_file_size_limit(tmp_path: Path) -> None:
    """Enforce 1 MiB hard ceiling on agent file inspection."""
    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"0" * (1024 * 1024 + 1))  # 1 MiB + 1 byte

    with pytest.raises(PayloadTooLargeError):
        read_safe_file("oversized.bin", tmp_path, max_agent_file_bytes=1024 * 1024)


@pytest.mark.security
def test_llm04_resource_dos_query_timeout(populated_db: Path) -> None:
    """Abort runaway queries exceeding opcode execution budget."""
    runaway_sql = """
    WITH RECURSIVE loop(n) AS (
        VALUES(1)
        UNION ALL
        SELECT n + 1 FROM loop WHERE n < 100000000
    )
    SELECT count(*) FROM loop;
    """
    with get_connection(populated_db, timeout_seconds=0.05) as conn:
        with pytest.raises(QueryTimeoutError):
            run_safe_query(conn, runaway_sql, timeout_seconds=0.05)


@pytest.mark.security
def test_llm06_sensitive_credential_files_blocked(tmp_path: Path) -> None:
    """Block agent access to sensitive files and credentials."""
    sensitive_targets = [
        ".env",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "server.key",
        "database.pem",
        ".aws/credentials",
        ".git/config",
        "passwd",
    ]
    for target in sensitive_targets:
        file_path = tmp_path / target
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("DUMMY_SECRET", encoding="utf-8")

        with pytest.raises(SensitiveFileError):
            resolve_safe_path(target, tmp_path)


@pytest.mark.security
def test_llm06_pii_exfiltration_redaction(test_settings: Settings) -> None:
    """Mask customer PII (email, phone, SSN) before serialization."""
    res = query_database(
        SQLInput(sql="SELECT email, phone, ssn FROM customers LIMIT 1"),
        settings=test_settings,
    )
    assert "alice@example.com" not in res
    assert "555-123-4567" not in res
    assert "123-45-6789" not in res
    assert "[REDACTED EMAIL]" in res
    assert "[REDACTED PHONE]" in res
    assert "[REDACTED SSN]" in res


@pytest.mark.security
def test_llm06_core_dump_suppression() -> None:
    """Verify core dump suppression is executed at application entrypoint."""
    from app.server import suppress_core_dumps

    suppress_core_dumps()
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
        assert soft == 0
    except (ImportError, AttributeError, OSError):
        pass


@pytest.mark.security
def test_llm08_driver_level_write_rejection(populated_db: Path) -> None:
    """Verify database driver rejects write attempts unconditionally in mode=ro."""
    with get_connection(populated_db) as conn:
        cursor = conn.cursor()
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            cursor.execute("DROP TABLE customers;")


@pytest.mark.security
def test_llm10_path_traversal_containment(tmp_path: Path) -> None:
    """Block directory traversal sequences trying to escape root."""
    traversal_attacks = [
        "../etc/passwd",
        "../../../../var/log/syslog",
        "documents/../../secrets.txt",
    ]
    for attack in traversal_attacks:
        with pytest.raises(PathTraversalError):
            resolve_safe_path(attack, tmp_path)


@pytest.mark.security
def test_llm10_ssrf_cloud_metadata_blocked() -> None:
    """Deny outbound requests to cloud metadata and local loopback."""
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8000/",
        "http://localhost:9090/",
    ]
    for target in ssrf_targets:
        with pytest.raises(SSRFBlockedError):
            validate_url(target)
