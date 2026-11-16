"""Unit tests for configuration, structured logging, and tool registry."""

from pathlib import Path

from pydantic import SecretStr

from app.config import Settings, get_settings
from app.logging import (
    bind_correlation_id,
    configure_logging,
    log_tool_invocation,
    sanitize_log_value,
)
from app.tools import TOOL_PERMISSIONS, ToolName, ToolPermission


def test_settings_defaults() -> None:
    """Verify default Settings values and constraints."""
    settings = Settings()
    assert settings.transport == "streamable-http"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.max_rows == 100
    assert settings.max_payload_bytes == 65536
    assert settings.query_timeout_seconds == 2.0
    assert settings.max_agent_file_bytes == 1048576
    assert settings.redact_pii is True
    assert settings.log_level == "INFO"
    assert isinstance(settings.project_root, Path)


def test_settings_custom_values() -> None:
    """Verify custom settings overrides."""
    settings = Settings(
        port=9000,
        max_rows=50,
        auth_token=SecretStr("custom-secret"),
        environment="test",
    )
    assert settings.port == 9000
    assert settings.max_rows == 50
    assert settings.auth_token is not None
    assert settings.auth_token.get_secret_value() == "custom-secret"
    assert settings.environment == "test"


def test_get_settings_singleton() -> None:
    """Verify get_settings returns cached singleton instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_sanitize_log_value() -> None:
    """Verify ANSI escape stripping and newline sanitization."""
    dirty = "\x1b[31mRED_ALERT\x1b[0m\nLine2\rLine3\0NULL"
    cleaned = sanitize_log_value(dirty)
    assert "\x1b[" not in cleaned
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\0" not in cleaned
    assert "RED_ALERT" in cleaned


def test_configure_logging_and_bind_correlation() -> None:
    """Verify configure_logging and context correlation binding."""
    configure_logging(log_level="DEBUG")
    bind_correlation_id("test-corr-id-123")


def test_log_tool_invocation() -> None:
    """Verify log_tool_invocation executes for SUCCESS and ERROR results."""
    log_tool_invocation(
        tool_name="test_tool",
        input_hash="abc123hash",
        result_status="SUCCESS",
        latency_ms=12.345,
        rows_returned=10,
        pii_redacted=True,
    )
    log_tool_invocation(
        tool_name="test_tool",
        input_hash="abc123hash",
        result_status="ERROR",
        latency_ms=5.678,
        extra={"error_type": "SecurityViolation"},
    )


def test_tool_name_registry() -> None:
    """Verify ToolName enum and permissions table."""
    assert len(ToolName) == 7
    assert ToolName.QUERY_DATABASE.value == "query_database"
    for tool in ToolName:
        assert tool in TOOL_PERMISSIONS
        assert TOOL_PERMISSIONS[tool] == ToolPermission.READ
