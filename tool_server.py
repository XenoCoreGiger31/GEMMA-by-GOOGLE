#!/usr/bin/env python3
"""
tool_server.py — local HTTP tool-execution server for the HALO agent loop.

This is the transport the autonomous agent (agent_loop.py) and the specialist
agents (via mcp_client.py) drive: a small Flask service that accepts a
`{"tool": ..., <params>}` POST and returns the tool's result dict. The tools
themselves live in halo_tools, shared with the MCP server (mcp_server.py).

    python3 tool_server.py        # listens on :8000 (override with HALO_* env)

Endpoints:
    POST /        execute a tool         -> result dict (see halo_tools contract)
    GET  /status  liveness + arsenal     -> {"status", "supported_tools", ...}
"""

import os
from datetime import datetime

from flask import Flask, jsonify, request

from halo_logging import setup_logger
from halo_tools import SUPPORTED_TOOLS, ToolExecutor

# Default preserves the original author's environment; override via HALO_LOG_DIR.
LOG_DIR = os.environ.get("HALO_LOG_DIR", os.path.expanduser("~/security-agent/logs"))
os.makedirs(LOG_DIR, exist_ok=True)
SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"{LOG_DIR}/tool_server_{SESSION_ID}.log"

log = setup_logger("tool_server", LOG_FILE)

app = Flask(__name__)
executor = ToolExecutor()


@app.route("/", methods=["POST"])
def execute():
    """Execute one tool call described by the posted JSON body."""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({
                "status": "error",
                "error_type": "invalid_request",
                "message": "No JSON data provided",
            }), 400

        tool = data.get("tool")
        if not tool:
            return jsonify({
                "status": "error",
                "error_type": "missing_tool",
                "message": "No 'tool' parameter specified",
            }), 400

        if tool not in SUPPORTED_TOOLS:
            return jsonify({
                "status": "error",
                "error_type": "unsupported_tool",
                "message": f"Tool '{tool}' not supported",
                "recovery_suggestion": f"Use one of: {', '.join(SUPPORTED_TOOLS)}",
            }), 400

        params = {k: v for k, v in data.items() if k != "tool"}
        result = executor.execute_tool(tool, params)
        executor.execution_log.append(tool)
        return jsonify(result), 200

    except Exception as e:
        log.error(f"[ERROR] Server error: {e}")
        return jsonify({
            "status": "error",
            "error_type": "server_error",
            "message": str(e),
        }), 500


@app.route("/status", methods=["GET"])
def status():
    """Report liveness, the advertised arsenal, and how many calls have run."""
    return jsonify({
        "status": "running",
        "supported_tools": SUPPORTED_TOOLS,
        "execution_log_count": len(executor.execution_log),
    }), 200


def main() -> None:
    host = os.environ.get("HALO_TOOL_SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("HALO_TOOL_SERVER_PORT", "8000"))
    log.info(f"[START] HALO HTTP tool server on {host}:{port}")
    log.info(f"[TOOL] {len(SUPPORTED_TOOLS)} tools available")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
