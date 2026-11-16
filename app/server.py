"""FastMCP 4.x server entrypoint and protocol dispatcher.

Implements stateless streamable-http and stdio transports with full tool dispatch.
"""

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings
from app.logging import configure_logging
from app.tools import (
    FilePathInput,
    SearchInput,
    SQLInput,
    ToolName,
    URLInput,
)
from app.tools import (
    describe_schema as _describe_schema,
)
from app.tools import (
    explain_query as _explain_query,
)
from app.tools import (
    fetch_url as _fetch_url,
)
from app.tools import (
    list_directory as _list_directory,
)
from app.tools import (
    query_database as _query_database,
)
from app.tools import (
    read_file as _read_file,
)
from app.tools import (
    search_files as _search_files,
)

mcp = FastMCP(
    name="mcp-secure-gateway",
    version="0.1.0",
)


@mcp.tool(name=ToolName.LIST_DIRECTORY)
def list_directory(path: str = ".") -> str:
    """List files and subdirectories within the sandboxed path."""
    return _list_directory(FilePathInput(path=path))


@mcp.tool(name=ToolName.READ_FILE)
def read_file(path: str) -> str:
    """Read contents of a sandboxed file with PII redaction and size limits."""
    return _read_file(FilePathInput(path=path))


@mcp.tool(name=ToolName.SEARCH_FILES)
def search_files(query: str, path: str = ".") -> str:
    """Search for a literal text pattern across sandboxed files (ReDoS-immune)."""
    return _search_files(SearchInput(query=query, path=path))


@mcp.tool(name=ToolName.DESCRIBE_SCHEMA)
def describe_schema() -> str:
    """Describe database tables and columns with sensitivity flags."""
    return _describe_schema()


@mcp.tool(name=ToolName.QUERY_DATABASE)
def query_database(sql: str) -> str:
    """Validate, clamp, and execute read-only SQL query with PII redaction."""
    return _query_database(SQLInput(sql=sql))


@mcp.tool(name=ToolName.EXPLAIN_QUERY)
def explain_query(sql: str) -> str:
    """Return EXPLAIN QUERY PLAN execution steps for a query."""
    return _explain_query(SQLInput(sql=sql))


@mcp.tool(name=ToolName.FETCH_URL)
def fetch_url(url: str) -> str:
    """Fetch content from a public web URL with SSRF protection."""
    return _fetch_url(URLInput(url=url))


def health_check() -> dict[str, str]:
    """Plain HTTP liveness probe endpoint"""
    return {"status": "healthy", "service": "mcp-secure-gateway"}


@mcp.custom_route("/health", methods=["GET"])
async def health_endpoint(request: Request) -> Response:
    """HTTP liveness probe route for health checking."""
    return JSONResponse(health_check())


def suppress_core_dumps() -> None:
    """Disable process core dumps to prevent secret leakage in crash dumps."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, AttributeError, OSError, ValueError):
        pass


def run() -> None:
    """Server entrypoint executing stdio or streamable-http transport."""
    suppress_core_dumps()
    settings = get_settings()
    configure_logging(log_level=settings.log_level)

    if settings.transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=settings.host,
            port=settings.port,
            path="/mcp",
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
