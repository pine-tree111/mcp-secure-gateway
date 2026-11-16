"""Tool registry, permissions mapping, and unified exports for mcp-secure-gateway."""

from enum import StrEnum

from app.tools.database import (
    SQLInput,
    describe_schema,
    explain_query,
    query_database,
)
from app.tools.files import (
    FilePathInput,
    SearchInput,
    list_directory,
    read_file,
    search_files,
)
from app.tools.web import URLInput, fetch_url


class ToolName(StrEnum):
    """Hardcoded tool name registry. Any unmapped name fails closed."""

    LIST_DIRECTORY = "list_directory"
    READ_FILE = "read_file"
    SEARCH_FILES = "search_files"
    DESCRIBE_SCHEMA = "describe_schema"
    QUERY_DATABASE = "query_database"
    EXPLAIN_QUERY = "explain_query"
    FETCH_URL = "fetch_url"


class ToolPermission(StrEnum):
    """RBAC permission levels for tool execution."""

    READ = "read"


TOOL_PERMISSIONS: dict[ToolName, ToolPermission] = {
    tool: ToolPermission.READ for tool in ToolName
}

__all__ = [
    "TOOL_PERMISSIONS",
    "FilePathInput",
    "SQLInput",
    "SearchInput",
    "ToolName",
    "ToolPermission",
    "URLInput",
    "describe_schema",
    "explain_query",
    "fetch_url",
    "list_directory",
    "query_database",
    "read_file",
    "search_files",
]
