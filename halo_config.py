"""
Centralized, environment-overridable configuration for HALO.

Every network endpoint the agents depend on is resolved here so the source
carries no machine-specific defaults. Override any value with the matching
HALO_* environment variable; the defaults target a standard local setup
(LM Studio on :1234, the MCP tool server on :8000).
"""

import os

# Local LLM chat-completions endpoint (LM Studio / any OpenAI-compatible server).
MODEL_URL = os.environ.get("HALO_MODEL_URL", "http://localhost:1234/v1/chat/completions")

# Model identifier sent with each request. LM Studio routes "local-model" to
# whatever model is currently loaded, so this works without editing code.
MODEL_NAME = os.environ.get("HALO_MODEL_NAME", "local-model")

# HTTP tool-execution server (tool_server.py) that the agent loop drives.
# Kept as HALO_MCP_URL / MCP_URL for backward compatibility with existing setups.
MCP_URL = os.environ.get("HALO_MCP_URL", "http://localhost:8000")

# Seconds to wait on a single tool call before giving up. A hung tool (e.g.
# enum4linux on an SMB null session) must not stall the whole engagement, so
# this is a tight default; long-running tools pass their own explicit timeout.
TOOL_TIMEOUT = int(os.environ.get("HALO_TOOL_TIMEOUT", "300"))

# Seconds to wait on a single LLM inference call. Kept well under TOOL_TIMEOUT: the
# 300s catch-all is for long scans, and letting a model call inherit it means one hung
# LM Studio request stalls the whole engagement for 5 minutes (observed live). Local
# chain generations return in seconds, so this bounds the hang without cutting real work.
MODEL_TIMEOUT = int(os.environ.get("HALO_MODEL_TIMEOUT", "90"))
