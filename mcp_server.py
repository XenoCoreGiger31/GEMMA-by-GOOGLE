#!/usr/bin/env python3
"""
mcp_server.py — HALO's Model Context Protocol server.

A spec-compliant MCP server that exposes HALO's offensive-security arsenal to
any MCP-capable client (Claude Desktop, IDE agents, registries, inspectors)
over the stdio transport. It speaks JSON-RPC 2.0 per the MCP specification:
`initialize`, `tools/list`, and `tools/call`.

The tool set, argument schemas, and execution logic all live in halo_tools;
this file is purely the MCP transport binding, so the arsenal is defined once
and shared with the local HTTP tool server.

Run standalone:

    python3 mcp_server.py

or register it with an MCP client, e.g. in a client config:

    {
      "mcpServers": {
        "halo": { "command": "python3", "args": ["/abs/path/to/mcp_server.py"] }
      }
    }

Because every tool actually executes offensive tooling on the host, only
register this server with clients you trust and run it in an environment you
are authorized to operate from.
"""

import asyncio
import json

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from halo_tools import TOOLS, ToolExecutor

SERVER_NAME = "halo"
SERVER_VERSION = "1.0.0"

server = Server(SERVER_NAME)
executor = ToolExecutor()


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """Advertise the full arsenal, built from the shared schema registry."""
    return [
        types.Tool(
            name=t["name"],
            description=t["description"],
            inputSchema=t["inputSchema"],
        )
        for t in TOOLS
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Execute one tool and return its result dict as JSON text content.

    Tool execution is blocking (subprocesses), so it runs in a worker thread to
    keep the server's event loop responsive.
    """
    result = await asyncio.to_thread(executor.execute_tool, name, arguments or {})
    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def _serve() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
