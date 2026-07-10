# MCP Server

HALO exposes its 29-tool arsenal as a spec-compliant **Model Context Protocol
(MCP)** server, so any MCP-capable client — Claude Desktop, IDE agents, the MCP
Inspector, or a registry — can drive the same tools the autonomous agent uses.

## Layout

The tool set, argument schemas, and execution logic live in one engine,
`halo_tools.py`. Two thin transports sit on top of it:

| File | Transport | Used by |
|------|-----------|---------|
| `mcp_server.py` | MCP over stdio (JSON-RPC 2.0) | MCP clients / registries |
| `tool_server.py` | HTTP (Flask, port 8000) | the HALO agent loop |

Because both transports share `halo_tools.py`, the arsenal is defined exactly
once. Add or change a tool in the `TOOLS` registry (and `ToolExecutor`) in
`halo_tools.py` and both servers pick it up.

## Running the MCP server

```bash
python3 mcp_server.py
```

It speaks MCP on stdio and implements `initialize`, `tools/list`, and
`tools/call`. Input arguments are validated against each tool's `inputSchema`
before execution.

### Registering with an MCP client

```jsonc
{
  "mcpServers": {
    "halo": { "command": "python3", "args": ["/abs/path/to/mcp_server.py"] }
  }
}
```

A registry-ready manifest is provided at [`server.json`](../server.json).

### Quick check with the MCP Inspector

```bash
npx @modelcontextprotocol/inspector python3 mcp_server.py
```

## Tool result contract

Every tool returns a JSON object with a stable shape:

```json
{ "status": "success", "stdout": "...", "stderr": "..." }
```

On failure, `status` is `"error"` and the object also carries `error_type`,
`message`, and usually a `recovery_suggestion`. Consumers rely on `status` and
`stdout`, so that shape is the contract.

## Security considerations

- Every tool executes real offensive tooling on the host. Only register this
  server with clients you trust, and only run it in an environment you are
  authorized to operate from.
- Never expose the HTTP tool server to an untrusted network.
- All tool execution is logged; pair with host monitoring (e.g. Suricata) as
  described in [SETUP.md](SETUP.md).
