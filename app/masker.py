"""Column heuristic and regex-based PII redaction engine.

Enforces zero PII disclosure invariants.
"""

import re
from typing import Any

# Columns containing sensitive PII or credentials
SENSITIVE_COLUMN_PATTERNS: frozenset[str] = frozenset(
    {
        "email",
        "phone",
        "mobile",
        "cell",
        "ssn",
        "password",
        "secret",
        "token",
        "card",
        "cvv",
        "credit_card",
        "pin",
    }
)

# SECURITY-WAIVER: stdlib-re on length-bounded inputs
# Static regex patterns for inline PII value scrubbing
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")


def is_sensitive_column(column_name: str) -> bool:
    """Check if column name matches known PII or credential keywords."""
    col_lower = column_name.lower().replace("_", "").replace("-", "")
    return any(pattern in col_lower for pattern in SENSITIVE_COLUMN_PATTERNS)


def redact_text(text: str) -> str:
    """Scrub email, phone, SSN, and credit card patterns from string text."""
    if not text:
        return text

    bounded_text = text[:100_000]

    masked = _EMAIL_RE.sub("[REDACTED EMAIL]", bounded_text)
    masked = _SSN_RE.sub("[REDACTED SSN]", masked)
    masked = _CREDIT_CARD_RE.sub("[REDACTED CARD]", masked)
    masked = _PHONE_RE.sub("[REDACTED PHONE]", masked)
    return masked


def mask_value(column_name: str, value: Any) -> Any:
    """Mask a single value based on column heuristic and regex content matching."""
    if value is None:
        return None

    if is_sensitive_column(column_name):
        return f"[REDACTED {column_name.upper()}]"

    if isinstance(value, str):
        return redact_text(value)

    return value


def mask_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Iterate row dictionaries and apply PII redactions to all columns."""
    masked_result: list[dict[str, Any]] = []
    for row in rows:
        masked_row: dict[str, Any] = {}
        for col, val in row.items():
            masked_row[col] = mask_value(col, val)
        masked_result.append(masked_row)
    return masked_result
