dont use OPUS4.7 USE Model that use less token for every run

# Xero MCP Auth Server

## Features
- OAuth 2.0 authentication with Xero
- Token storage in NeonDB (PostgreSQL)
- **Auto-updates Claude Desktop config** - tokens are automatically refreshed in `~/.claude/claude_desktop_config.json`
- Supports both legacy SSE and Streamable HTTP transports
- Web UI for token management

## Auto-Config (New!)
When tokens are refreshed, the server automatically updates your Claude Desktop config at `~/.claude/claude_desktop_config.json`. You no longer need to manually copy tokens.

The config uses the `xero-mcp-start.js` launcher which auto-refreshes tokens at startup.

## Fallback: Manual Config
If auto-config doesn't work, you can manually configure Claude Desktop:
1. Open `~/.claude/claude_desktop_config.json`
2. Add the xero MCP server config (shown on the web UI)
3. Restart Claude Desktop

## Running
```bash
node server.js
# Open http://localhost:3000 to authenticate with Xero
```