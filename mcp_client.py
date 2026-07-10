"""
Thin, shared client for the MCP tool-execution server.

Every specialist agent routes tool calls through this one function, so the
request shape and endpoint live in a single place instead of being copied
into each agent module.
"""

import requests

from halo_config import MCP_URL, TOOL_TIMEOUT


def call_tool(tool: str, params: dict, timeout: int = TOOL_TIMEOUT) -> dict:
    """Send one tool call to the MCP server and return its JSON result."""
    step = {"tool": tool, **params}
    response = requests.post(MCP_URL, json=step, timeout=timeout)
    return response.json()
