"""Web retrieval tools with SSRF guardrails and PII redaction."""

import hashlib
import json
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings, get_settings
from app.errors import MCPGuardError, PayloadTooLargeError
from app.logging import log_tool_invocation
from app.masker import redact_text
from app.security import validate_url


class URLInput(BaseModel):
    """Input model for outbound HTTP fetching."""

    model_config = ConfigDict(extra="forbid", strict=True)
    url: str = Field(
        max_length=2048,
        description="Public HTTP or HTTPS URL to fetch",
    )


def fetch_url(
    input_data: URLInput,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> str:
    """MCP Tool: Fetch text from a public web URL with SSRF protection."""
    active_settings = settings or get_settings()
    start_time = time.monotonic()
    input_hash = hashlib.sha256(input_data.model_dump_json().encode()).hexdigest()[:16]

    try:
        validated_url = validate_url(input_data.url)

        timeout = httpx.Timeout(10.0, connect=5.0)
        # Context-managed HTTP client
        if client is not None:
            response = client.get(validated_url, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=False) as http_client:
                response = http_client.get(validated_url)

        content = response.text
        if len(content.encode("utf-8")) > active_settings.max_payload_bytes:
            raise PayloadTooLargeError(
                f"Web response size exceeds ceiling ({active_settings.max_payload_bytes} bytes)"
            )

        pii_redacted = False
        if active_settings.redact_pii:
            redacted = redact_text(content)
            if redacted != content:
                pii_redacted = True
            content = redacted

        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="fetch_url",
            input_hash=input_hash,
            result_status="SUCCESS",
            latency_ms=latency,
            pii_redacted=pii_redacted,
        )
        return json.dumps(
            {
                "status": "success",
                "url": validated_url,
                "status_code": response.status_code,
                "content": content,
            }
        )

    except (MCPGuardError, httpx.HTTPError) as err:
        latency = (time.monotonic() - start_time) * 1000
        log_tool_invocation(
            tool_name="fetch_url",
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
