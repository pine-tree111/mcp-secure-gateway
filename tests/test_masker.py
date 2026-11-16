"""Unit tests for PII masking and redaction."""

from app.masker import (
    is_sensitive_column,
    mask_rows,
    mask_value,
    redact_text,
)


def test_sensitive_column_detection() -> None:
    """Verify column heuristic detects sensitive names."""
    assert is_sensitive_column("email")
    assert is_sensitive_column("user_email")
    assert is_sensitive_column("phone_number")
    assert is_sensitive_column("ssn")
    assert is_sensitive_column("credit_card")
    assert is_sensitive_column("password_hash")

    # Non-sensitive columns must remain False
    assert not is_sensitive_column("id")
    assert not is_sensitive_column("title")
    assert not is_sensitive_column("created_at")
    assert not is_sensitive_column("status")


def test_mask_value_sensitive_column() -> None:
    """Verify sensitive columns mask the entire value."""
    assert mask_value("email", "john@example.com") == "[REDACTED EMAIL]"
    assert mask_value("phone", "555-123-4567") == "[REDACTED PHONE]"
    assert mask_value("ssn", "123-45-6789") == "[REDACTED SSN]"
    assert mask_value("id", 42) == 42
    assert mask_value("status", "ACTIVE") == "ACTIVE"


def test_redact_inline_text() -> None:
    """Verify regex redacts inline PII in freeform text."""
    raw = "Reach out to admin@company.org or call 555-888-9999 (SSN: 999-88-7777)."
    redacted = redact_text(raw)
    assert "admin@company.org" not in redacted
    assert "555-888-9999" not in redacted
    assert "999-88-7777" not in redacted
    assert "[REDACTED EMAIL]" in redacted
    assert "[REDACTED PHONE]" in redacted
    assert "[REDACTED SSN]" in redacted


def test_mask_rows() -> None:
    """Verify mask_rows processes row dictionaries properly."""
    rows = [
        {"id": 1, "name": "Alice", "email": "alice@test.com", "role": "developer"},
        {"id": 2, "name": "Bob", "email": "bob@test.com", "role": "designer"},
    ]
    masked = mask_rows(rows)
    assert len(masked) == 2
    assert masked[0]["id"] == 1
    assert masked[0]["name"] == "Alice"
    assert masked[0]["email"] == "[REDACTED EMAIL]"
    assert masked[1]["email"] == "[REDACTED EMAIL]"
