"""Unit tests for all 7 MCP tool functions and strict input schema validation."""

import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.tools import (
    FilePathInput,
    SearchInput,
    SQLInput,
    URLInput,
    describe_schema,
    explain_query,
    fetch_url,
    list_directory,
    query_database,
    read_file,
    search_files,
)


def test_extra_arguments_forbidden_schema() -> None:
    """Verify Pydantic schemas reject hallucinated parameters with extra='forbid'."""
    with pytest.raises(ValidationError):
        FilePathInput.model_validate({"path": "doc.txt", "hallucinated_param": True})

    with pytest.raises(ValidationError):
        SQLInput.model_validate({"sql": "SELECT 1", "role": "admin"})

    with pytest.raises(ValidationError):
        SearchInput.model_validate({"query": "target", "regex": True})

    with pytest.raises(ValidationError):
        URLInput.model_validate({"url": "https://example.com", "method": "POST"})


def test_max_length_enforcement() -> None:
    """Verify input schemas enforce max_length bounds."""
    with pytest.raises(ValidationError):
        FilePathInput(path="a" * 1025)

    with pytest.raises(ValidationError):
        SQLInput(sql="a" * 10_001)

    with pytest.raises(ValidationError):
        SearchInput(query="a" * 501)

    with pytest.raises(ValidationError):
        URLInput(url="https://example.com/" + "a" * 2050)


def test_list_directory_tool(test_settings: Settings) -> None:
    """Verify list_directory returns JSON with sandboxed files."""
    res_str = list_directory(FilePathInput(path="."), settings=test_settings)
    res = json.loads(res_str)
    assert res["status"] == "success"
    names = [e["name"] for e in res["entries"]]
    assert "policies.md" in names
    assert "notes.txt" in names


def test_list_directory_traversal_rejected(test_settings: Settings) -> None:
    """Verify path traversal in list_directory returns error JSON."""
    res_str = list_directory(FilePathInput(path="../"), settings=test_settings)
    res = json.loads(res_str)
    assert res["status"] == "error"
    assert res["error_type"] == "PathTraversalError"


def test_read_file_tool(test_settings: Settings) -> None:
    """Verify read_file reads sandboxed content and masks inline email."""
    res_str = read_file(FilePathInput(path="notes.txt"), settings=test_settings)
    res = json.loads(res_str)
    assert res["status"] == "success"
    assert "security@example.com" not in res["content"]
    assert "[REDACTED EMAIL]" in res["content"]


def test_read_file_sensitive_rejected(test_settings: Settings, tmp_path: Path) -> None:
    """Verify read_file denies access to sensitive files."""
    env_file = test_settings.documents_path / ".env"
    env_file.write_text("SECRET=xyz", encoding="utf-8")

    res_str = read_file(FilePathInput(path=".env"), settings=test_settings)
    res = json.loads(res_str)
    assert res["status"] == "error"
    assert res["error_type"] == "SensitiveFileError"


def test_search_files_tool(test_settings: Settings) -> None:
    """Verify literal search finds occurrences without regex."""
    res_str = search_files(
        SearchInput(query="Zero trust", path="."), settings=test_settings
    )
    res = json.loads(res_str)
    assert res["status"] == "success"
    assert res["matches_count"] >= 1
    assert "policies.md" in res["matches"][0]["file"]


def test_describe_schema_tool(test_settings: Settings) -> None:
    """Verify describe_schema returns tables and sensitivity markers."""
    res_str = describe_schema(settings=test_settings)
    res = json.loads(res_str)
    assert res["status"] == "success"
    table_names = [t["table_name"] for t in res["tables"]]
    assert "customers" in table_names
    assert "products" in table_names


def test_query_database_tool_success(test_settings: Settings) -> None:
    """Verify query_database executes read-only query and masks customer PII."""
    res_str = query_database(
        SQLInput(sql="SELECT name, email, phone FROM customers LIMIT 2"),
        settings=test_settings,
    )
    res = json.loads(res_str)
    assert res["status"] == "success"
    assert res["rows_returned"] == 2
    row = res["data"][0]
    assert row["email"] == "[REDACTED EMAIL]"
    assert row["phone"] == "[REDACTED PHONE]"


def test_query_database_mutation_rejected(test_settings: Settings) -> None:
    """Verify query_database rejects mutation commands."""
    res_str = query_database(
        SQLInput(sql="DROP TABLE customers"), settings=test_settings
    )
    res = json.loads(res_str)
    assert res["status"] == "error"
    assert res["error_type"] == "SecurityViolationError"


def test_explain_query_tool(test_settings: Settings) -> None:
    """Verify explain_query returns query execution plan."""
    res_str = explain_query(
        SQLInput(sql="SELECT * FROM products WHERE price > 100"),
        settings=test_settings,
    )
    res = json.loads(res_str)
    assert res["status"] == "success"
    assert "query_plan" in res


def test_fetch_url_success(test_settings: Settings) -> None:
    """Verify fetch_url retrieves content through outermost MockTransport seam."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Welcome! Contact us at support@service.com.")

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    res_str = fetch_url(
        URLInput(url="https://api.example.com/info"),
        settings=test_settings,
        client=mock_client,
    )
    res = json.loads(res_str)
    assert res["status"] == "success"
    assert res["status_code"] == 200
    assert "support@service.com" not in res["content"]
    assert "[REDACTED EMAIL]" in res["content"]


def test_fetch_url_ssrf_blocked(test_settings: Settings) -> None:
    """Verify fetch_url blocks cloud metadata targets."""
    res_str = fetch_url(
        URLInput(url="http://169.254.169.254/latest/meta-data"),
        settings=test_settings,
    )
    res = json.loads(res_str)
    assert res["status"] == "error"
    assert res["error_type"] == "SSRFBlockedError"
