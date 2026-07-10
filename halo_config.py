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

# MCP tool-execution server.
MCP_URL = os.environ.get("HALO_MCP_URL", "http://localhost:8000")

# Seconds to wait on a single tool call before giving up.
TOOL_TIMEOUT = int(os.environ.get("HALO_TOOL_TIMEOUT", "7200"))
