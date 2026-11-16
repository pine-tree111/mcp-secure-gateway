"""Full-wiring integration tests exercising tool dispatch through the FastMCP protocol layer.

MCP Server Full-Wiring Integration Mandate.
Mocking internal adapters or the MCP dispatcher is strictly forbidden.
"""

import importlib
import json
from typing import Any

import pytest

from app.config import Settings
from app.server import health_check, mcp
from app.tools import ToolName


def _extract_text(result: Any) -> str:
    """Extract string payload from FastMCP call_tool return structures."""
    if isinstance(result, str):
        return result
    if isinstance(result, list) and len(result) > 0:
        item = result[0]
        if hasattr(item, "text"):
            return str(item.text)
        return str(item)
    if hasattr(result, "content"):
        content = result.content
        if (
            isinstance(content, list)
            and len(content) > 0
            and hasattr(content[0], "text")
        ):
            return str(content[0].text)
    return str(result)


def test_health_check_endpoint() -> None:
    """Verify liveness probe returns healthy status dictionary."""
    status = health_check()
    assert status["status"] == "healthy"
    assert status["service"] == "mcp-secure-gateway"


def test_entrypoint_resolution_smoke() -> None:
    """Verify app.server module, run entrypoint, and core dump suppression."""
    mod = importlib.import_module("app.server")
    assert hasattr(mod, "mcp")
    assert callable(mod.run)
    assert callable(mod.suppress_core_dumps)
    mod.suppress_core_dumps()


async def test_mcp_tool_list_registration() -> None:
    """Verify all 7 tools from ToolName enum are registered on FastMCP server."""
    registered = await mcp.list_tools()
    registered_names = {t.name for t in registered}
    for tool_name in ToolName:
        assert tool_name.value in registered_names


async def test_full_wiring_list_directory(test_settings: Settings) -> None:
    """Full-wiring test: list_directory dispatched via protocol layer."""
    res = await mcp.call_tool(ToolName.LIST_DIRECTORY.value, arguments={"path": "."})
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    names = [e["name"] for e in data["entries"]]
    assert "policies.md" in names


async def test_full_wiring_read_file(test_settings: Settings) -> None:
    """Full-wiring test: read_file dispatched via protocol layer with PII masking."""
    res = await mcp.call_tool(ToolName.READ_FILE.value, arguments={"path": "notes.txt"})
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    assert "[REDACTED EMAIL]" in data["content"]


async def test_full_wiring_search_files(test_settings: Settings) -> None:
    """Full-wiring test: search_files dispatched via protocol layer."""
    res = await mcp.call_tool(
        ToolName.SEARCH_FILES.value, arguments={"query": "Zero trust", "path": "."}
    )
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    assert data["matches_count"] >= 1


async def test_full_wiring_describe_schema(test_settings: Settings) -> None:
    """Full-wiring test: describe_schema dispatched via protocol layer."""
    res = await mcp.call_tool(ToolName.DESCRIBE_SCHEMA.value, arguments={})
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    table_names = [t["table_name"] for t in data["tables"]]
    assert "customers" in table_names


async def test_full_wiring_query_database(test_settings: Settings) -> None:
    """Full-wiring test: query_database executes read-only SQL with PII masking."""
    res = await mcp.call_tool(
        ToolName.QUERY_DATABASE.value,
        arguments={"sql": "SELECT name, email FROM customers LIMIT 2"},
    )
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    assert data["rows_returned"] == 2
    assert data["data"][0]["email"] == "[REDACTED EMAIL]"


async def test_full_wiring_explain_query(test_settings: Settings) -> None:
    """Full-wiring test: explain_query returns query execution plan."""
    res = await mcp.call_tool(
        ToolName.EXPLAIN_QUERY.value,
        arguments={"sql": "SELECT * FROM products"},
    )
    data = json.loads(_extract_text(res))
    assert data["status"] == "success"
    assert "query_plan" in data


async def test_full_wiring_fetch_url_ssrf_blocked(test_settings: Settings) -> None:
    """Full-wiring test: fetch_url blocks metadata IP through protocol layer."""
    res = await mcp.call_tool(
        ToolName.FETCH_URL.value,
        arguments={"url": "http://169.254.169.254/latest/meta-data"},
    )
    data = json.loads(_extract_text(res))
    assert data["status"] == "error"
    assert data["error_type"] == "SSRFBlockedError"


async def test_unmapped_tool_fails_closed() -> None:
    """Verify invoking an unmapped or hallucinated tool name fails closed."""
    with pytest.raises(Exception):
        await mcp.call_tool("hallucinated_admin_tool", arguments={})
