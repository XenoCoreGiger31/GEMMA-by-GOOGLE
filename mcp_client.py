"""
Thin, shared MCP client for the specialist agents (stdio transport).

Every specialist agent (attacker_agent, vuln_discovery_agent, …) routes tool
calls through this one function, so the transport, request shape, and result
adaptation live in a single place — matching agent_loop.py exactly.

`call_tool` spawns `python3 mcp_server.py` as a stdio subprocess, speaks JSON-RPC
2.0 to it, runs one tool, adapts the reply back to the tool's result dict, and
tears the subprocess down. The signature and return shape are unchanged from the
old HTTP client, so callers keep working as-is — call, respond, resolve.

There is no HTTP tool server / port 8000 anymore, and mcp_server.py must NOT be
launched manually in another terminal: each call owns the server subprocess's
lifecycle. (One subprocess is spawned per call. Specialist calls are sporadic
and each wraps a multi-second scan, so per-call spawn overhead is negligible and
buys full isolation between calls — no shared state to hang on.)
"""

import asyncio
import json
import os
import threading
from datetime import timedelta

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from halo_config import TOOL_TIMEOUT

_REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# Inherit the current environment so .env-sourced HALO_* vars reach the tools;
# StdioServerParameters otherwise defaults to a minimal env that would drop them.
_SERVER_PARAMS = StdioServerParameters(
    command="python3",
    args=[os.path.join(_REPO_DIR, "mcp_server.py")],
    cwd=_REPO_DIR,
    env=dict(os.environ),
)


def _result_to_dict(result) -> dict:
    """Adapt an MCP ``CallToolResult`` back into the ``{status, stdout, …}`` dict.

    mcp_server.py returns each tool's result dict JSON-encoded in a single text
    content block, so concatenate the text blocks and decode. Preserves the exact
    shape callers read (``result["stdout"]`` / ``result["status"]``).
    """
    text = "".join(
        b.text for b in (result.content or [])
        if getattr(b, "type", None) == "text" and getattr(b, "text", None)
    )
    if not text:
        return {"status": "error", "stdout": "", "stderr": "",
                "message": "empty MCP response"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"status": "error", "stdout": text, "stderr": "",
                "message": "non-JSON MCP response"}
    if getattr(result, "isError", False) and isinstance(data, dict):
        data.setdefault("status", "error")
    return data


async def _call_tool_async(tool: str, params: dict, timeout: int) -> dict:
    """Spawn the server, run one tool over a fresh MCP session, return its dict."""
    async with stdio_client(_SERVER_PARAMS) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                tool, params or {},
                read_timeout_seconds=timedelta(seconds=timeout),
            )
            return _result_to_dict(result)


def _run_sync(coro):
    """Drive a coroutine to completion from sync code, even under a running loop.

    Normally there is no event loop in these synchronous agents, so asyncio.run
    handles it. If a caller ever invokes us from inside a running loop, we run the
    coroutine in a dedicated worker thread instead of raising — no hangups.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box = {}

    def _worker():
        box["value"] = asyncio.run(coro)

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    return box["value"]


def call_tool(tool: str, params: dict, timeout: int = TOOL_TIMEOUT) -> dict:
    """Send one tool call to the MCP server and return its JSON result dict.

    Synchronous, blocking, same signature and return contract as before. On any
    transport failure it returns a normalized error dict rather than raising, so
    a single tool hiccup never takes down a specialist agent.
    """
    try:
        return _run_sync(_call_tool_async(tool, params, timeout))
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": "",
                "error_type": "mcp_transport_error", "message": str(e)}
