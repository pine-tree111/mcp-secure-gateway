"""Structured JSON logging configuration and correlation context utilities."""

import logging
import re
import sys
from typing import Any

import structlog

# Strip ANSI escapes from untrusted user values before logging
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def sanitize_log_value(val: str) -> str:
    """Sanitize user-controlled strings before logging to prevent log injection."""
    cleaned = _ANSI_ESCAPE_RE.sub("", val)
    return cleaned.replace("\0", "").replace("\r", " ").replace("\n", " ")


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structlog with machine-readable JSON rendering."""
    level_num = getattr(logging, log_level.upper(), logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level_num),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def bind_correlation_id(correlation_id: str) -> None:
    """Bind a request or session correlation ID to the current async context."""
    structlog.contextvars.bind_contextvars(
        correlation_id=sanitize_log_value(correlation_id)
    )


def log_tool_invocation(
    *,
    tool_name: str,
    input_hash: str,
    result_status: str,
    latency_ms: float,
    rows_returned: int | None = None,
    pii_redacted: bool = False,
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a structured audit log entry for an MCP tool invocation."""
    logger = structlog.get_logger("mcp.audit")
    event_dict: dict[str, Any] = {
        "event": "tool_invocation",
        "tool_name": sanitize_log_value(tool_name),
        "input_hash": input_hash,
        "result_status": result_status,
        "latency_ms": round(latency_ms, 3),
        "rows_returned": rows_returned,
        "pii_redacted": pii_redacted,
    }
    if extra:
        event_dict.update(extra)

    if result_status == "SUCCESS":
        logger.info(**event_dict)
    else:
        logger.warning(**event_dict)
