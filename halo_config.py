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

# Seconds to wait on a single LLM inference call. Kept under TOOL_TIMEOUT (the 300s
# catch-all is for long scans), but sized for the REAL latency of the local reasoning
# 12B: it emits a ~1,200-token think phase *before* the JSON, and at the measured
# ~13.5 tok/s on this box a full pass is ~100s (probed 1,339 tokens in 99s). The old
# 90s ceiling killed legitimate calls mid-think. This bounds a genuinely hung request
# while leaving room for an honest thinking pass; raise it if a heavier think truncates.
MODEL_TIMEOUT = int(os.environ.get("HALO_MODEL_TIMEOUT", "180"))

# Max output tokens per LLM inference call. This is a runaway CEILING, not a speed lever.
# The local model is a reasoning model: it spends ~1,200 tokens THINKING (returned in a
# separate reasoning_content field), then ~150 tokens on the JSON action it owes us. A
# cap below the think budget (the 512 tried on 2026-08-18) starves the answer — the model
# hits the ceiling mid-think and returns an EMPTY content string, so every port without a
# curated PoC parsed to "No JSON found". Capping output cannot speed a reasoning model up;
# only fewer thinking tokens can, and that is not API-controllable for this model. So this
# sits above a full observed pass (1,339) with headroom, purely to stop a true runaway.
MODEL_MAX_TOKENS = int(os.environ.get("HALO_MODEL_MAX_TOKENS", "2048"))

# Attacker callback address for Metasploit REVERSE payloads (LHOST/LPORT). Tier-2
# select_payload prefers BIND payloads (target listens, we connect — no callback
# needed), so these are used only when a module offers no bind payload. LHOST must be
# the attacker's IP as reachable FROM the target (e.g. the box's address on the target
# network). Empty LHOST → the reverse payload can't call back, so bind stays preferred.
LHOST = os.environ.get("HALO_LHOST", "")
LPORT = os.environ.get("HALO_LPORT", "4444")
