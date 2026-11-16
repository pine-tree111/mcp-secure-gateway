"""Filesystem inspection tools for mcp-secure-gateway.

Enforces TOCTOU-safe path containment, size ceilings, and PII masking.
"""

import hashlib
import json
import time

from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings, get_settings
from app.errors import MCPGuardError
from app.logging import log_tool_invocation
from app.masker import redact_text
from app.security import is_sensitive_file, read_safe_file, resolve_safe_path


class FilePathInput(BaseModel):
    """Input model for file and directory inspection."""

    model_config = ConfigDict(extra="forbid", strict=True)
    path: str = Field(
        default=".",
        max_length=1024,
        description="Relative file or directory path within authorized sandbox",
    )


class SearchInput(BaseModel):
    """Input model for literal text search across files."""

    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(
        max_length=500,
        description="Literal substring to search for (regex is forbidden)",
    )
    path: str = Field(
        default=".",
        max_length=1024,
        description="Directory to search within",
    )


def list_directory(
    input_data: FilePathInput,
    settings: Settings | None = None,
) -> str:
    """MCP Tool: List files and subdirectories within the sandboxed path."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        sandbox_root = active_settings.documents_path.resolve()
        target_dir = resolve_safe_path(input_data.path, sandbox_root)

        if not target_dir.is_dir():
            raise NotADirectoryError(f"Path '{input_data.path}' is not a directory")

        entries: list[dict[str, object]] = []
        for item in sorted(target_dir.iterdir()):
            rel_item = item.relative_to(sandbox_root)
            if is_sensitive_file(rel_item):
                continue

            stat_info = item.stat()
            entries.append(
                {
                    "name": item.name,
                    "is_directory": item.is_dir(),
                    "size_bytes": stat_info.st_size if item.is_file() else None,
                }
            )

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="list_directory",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            rows_returned=len(entries),
        )
        return json.dumps({"status": "success", "entries": entries})

    except (MCPGuardError, OSError) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="list_directory",
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


def read_file(
    input_data: FilePathInput,
    settings: Settings | None = None,
) -> str:
    """MCP Tool: Read content of a sandboxed file with PII redaction."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        sandbox_root = active_settings.documents_path.resolve()
        raw_bytes = read_safe_file(
            input_data.path,
            sandbox_root,
            max_agent_file_bytes=active_settings.max_agent_file_bytes,
        )

        content = raw_bytes.decode("utf-8", errors="replace")
        pii_redacted = False
        if active_settings.redact_pii:
            redacted = redact_text(content)
            if redacted != content:
                pii_redacted = True
            content = redacted

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="read_file",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            pii_redacted=pii_redacted,
        )
        return json.dumps(
            {
                "status": "success",
                "path": input_data.path,
                "content": content,
                "bytes_read": len(raw_bytes),
            }
        )

    except (MCPGuardError, OSError) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="read_file",
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


def search_files(
    input_data: SearchInput,
    settings: Settings | None = None,
) -> str:
    """MCP Tool: Search literal text across files (ReDoS-immune matching)."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        sandbox_root = active_settings.documents_path.resolve()
        target_dir = resolve_safe_path(input_data.path, sandbox_root)

        if not target_dir.is_dir():
            raise NotADirectoryError(f"Path '{input_data.path}' is not a directory")

        matches: list[dict[str, object]] = []
        for file_path in target_dir.rglob("*"):
            if not file_path.is_file():
                continue

            rel_path = file_path.relative_to(sandbox_root)
            if is_sensitive_file(rel_path):
                continue

            if file_path.stat().st_size > active_settings.max_agent_file_bytes:
                continue

            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            query = input_data.query
            for line_no, line in enumerate(text.splitlines(), start=1):
                if query in line:
                    line_content = line.strip()
                    if active_settings.redact_pii:
                        line_content = redact_text(line_content)
                    matches.append(
                        {
                            "file": str(rel_path),
                            "line": line_no,
                            "text": line_content,
                        }
                    )

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="search_files",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            rows_returned=len(matches),
        )
        return json.dumps(
            {
                "status": "success",
                "query": input_data.query,
                "matches_count": len(matches),
                "matches": matches,
            }
        )

    except (MCPGuardError, OSError) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="search_files",
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
