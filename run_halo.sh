#!/usr/bin/env bash
# HALO launcher — pins the model endpoint at the Mac's LM Studio across the bridge,
# so a fresh deddy shell never falls back to localhost:1234.
# Override either var inline if the bridge IP or loaded model changes.
export HALO_MODEL_URL="${HALO_MODEL_URL:-http://203.0.113.1:1234/v1/chat/completions}"
export HALO_MODEL_NAME="${HALO_MODEL_NAME:-huihui-gemma-4-12b-it-abliterated-i1}"

cd "$(dirname "$0")" || exit 1
exec python3 agent_loop.py "$@"
