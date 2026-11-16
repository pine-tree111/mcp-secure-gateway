# Setup & Client Connection Guide

Connect **Claude Desktop** or **Cursor IDE** to `mcp-secure-gateway`.

---

## 1. Local Developer Connection (Stdio Transport)

Add this configuration to your client configuration file:

- **macOS (Claude Desktop)**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux (Claude Desktop)**: `~/.config/Claude/claude_desktop_config.json`
- **Windows (Claude Desktop)**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "secure-gateway": {
      "command": "/path/to/mcp-secure-gateway/.venv/bin/python",
      "args": ["-m", "app.server"],
      "cwd": "/path/to/mcp-secure-gateway",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

---

## 2. Remote / Network Connection (Streamable HTTP Transport)

When running the gateway as an HTTP service:

```bash
uv run python -m app.server
```

Connect your client using Streamable HTTP (`/mcp`):

```json
{
  "mcpServers": {
    "secure-gateway": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer dev-secret-token-change-in-production"
      }
    }
  }
}
```

---

## 3. Docker Deployment

Run with Docker Compose:

```bash
docker compose up -d
```

Check health:
```bash
curl -s http://127.0.0.1:8000/health
```
```json
{"status": "healthy", "service": "mcp-secure-gateway"}
```
