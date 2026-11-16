"""Database inspection and read-only query tools for mcp-secure-gateway.

Enforces AST verification, mode=ro driver guarantees, opcode timeouts, and PII masking.
"""

import hashlib
import json
import time

from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings, get_settings
from app.db import get_connection, get_schema_metadata, run_safe_query
from app.errors import MCPGuardError
from app.logging import log_tool_invocation
from app.masker import mask_rows
from app.validator import validate_and_sanitize_sql


class SQLInput(BaseModel):
    """Input model for SQL query execution."""

    model_config = ConfigDict(extra="forbid", strict=True)
    sql: str = Field(
        max_length=10_000,
        description="SQL SELECT query (mutation commands are strictly forbidden)",
    )


def describe_schema(settings: Settings | None = None) -> str:
    """MCP Tool: Return schema metadata for all tables with column sensitivity markers."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(b"describe_schema").hexdigest()[:16]

    try:
        with get_connection(
            active_settings.database_path,
            timeout_seconds=active_settings.query_timeout_seconds,
        ) as conn:
            schema = get_schema_metadata(conn)

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="describe_schema",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            rows_returned=len(schema),
        )
        return json.dumps({"status": "success", "tables": schema})

    except (MCPGuardError, Exception) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="describe_schema",
            input_hash=input_hash,
            result_status="ERROR",
            latency_ms=latency,
            extra={"error": str(err)},
        )
        return json.dumps(
            {
                "status": "error",
                "error_type": type(err).__name__,
                "message": str(err),
            }
        )


def query_database(
    input_data: SQLInput,
    settings: Settings | None = None,
) -> str:
    """MCP Tool: Validate, clamp, execute read-only query, and redact PII."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        sanitized_sql = validate_and_sanitize_sql(
            input_data.sql,
            max_rows=active_settings.max_rows,
        )

        with get_connection(
            active_settings.database_path,
            timeout_seconds=active_settings.query_timeout_seconds,
        ) as conn:
            raw_rows = run_safe_query(
                conn,
                sanitized_sql,
                max_rows=active_settings.max_rows,
                max_payload_bytes=active_settings.max_payload_bytes,
                timeout_seconds=active_settings.query_timeout_seconds,
            )

        pii_redacted = False
        if active_settings.redact_pii:
            rows = mask_rows(raw_rows)
            pii_redacted = True
        else:
            rows = raw_rows

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="query_database",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            rows_returned=len(rows),
            pii_redacted=pii_redacted,
        )
        return json.dumps(
            {
                "status": "success",
                "executed_sql": sanitized_sql,
                "rows_returned": len(rows),
                "data": rows,
            }
        )

    except (MCPGuardError, Exception) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="query_database",
            input_hash=input_hash,
            result_status="ERROR",
            latency_ms=latency,
            extra={"error": str(err)},
        )
        return json.dumps(
            {
                "status": "error",
                "error_type": type(err).__name__,
                "message": str(err),
            }
        )


def explain_query(
    input_data: SQLInput,
    settings: Settings | None = None,
) -> str:
    """MCP Tool: Return query plan execution steps."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        sanitized_sql = validate_and_sanitize_sql(
            input_data.sql,
            max_rows=active_settings.max_rows,
        )
        explain_sql = f"EXPLAIN QUERY PLAN {sanitized_sql}"

        with get_connection(
            active_settings.database_path,
            timeout_seconds=active_settings.query_timeout_seconds,
        ) as conn:
            plan_rows = run_safe_query(
                conn,
                explain_sql,
                max_rows=active_settings.max_rows,
                max_payload_bytes=active_settings.max_payload_bytes,
                timeout_seconds=active_settings.query_timeout_seconds,
            )

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="explain_query",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            rows_returned=len(plan_rows),
        )
        return json.dumps(
            {
                "status": "success",
                "query_plan": plan_rows,
            }
        )

    except (MCPGuardError, Exception) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="explain_query",
            input_hash=input_hash,
            result_status="ERROR",
            latency_ms=latency,
            extra={"error": str(err)},
        )
        return json.dumps(
            {
                "status": "error",
                "error_type": type(err).__name__,
                "message": str(err),
            }
        )
