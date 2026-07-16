"""Runtime adapters bridging the next-generation engine to HALO's backends.

Provides the concrete collaborators the engine injects:
  * LMStudioModelClient — queries the local LLM endpoint, injecting the
    engagement preamble and just-in-time skills into the system prompt.
  * HTTPToolExecutor    — dispatches tool steps to the HTTP tool server.

A shared parse_model_response repairs the common defects in locally hosted
model output. `requests` is imported lazily so this module loads without it.
"""

from __future__ import annotations

import json
import re

from halo_config import MODEL_URL, MODEL_NAME, MCP_URL, TOOL_TIMEOUT
from skills import load_skills, select_relevant_skills


def parse_model_response(raw: str) -> dict:
    """Extract a ``{"chain": [...]}`` object from a raw model reply.

    Repairs code fences, smart quotes, and trailing commas, then decodes the
    first well-formed object. If the array structure is mangled, salvages every
    standalone tool object. Returns ``{"chain": []}`` when nothing is usable.
    """
    try:
        cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
        cleaned = cleaned.replace("“", '"').replace("”", '"')
        cleaned = cleaned.replace("‘", "'").replace("’", "'")
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
        start = cleaned.find("{")
        if start == -1:
            return {"chain": []}
        try:
            obj, _ = json.JSONDecoder().raw_decode(cleaned, start)
            if isinstance(obj, dict) and "chain" in obj:
                return obj
        except json.JSONDecodeError:
            pass
        dec = json.JSONDecoder()
        idx, steps = 0, []
        while idx < len(cleaned):
            brace = cleaned.find("{", idx)
            if brace == -1:
                break
            try:
                o, end = dec.raw_decode(cleaned, brace)
                if isinstance(o, dict) and "tool" in o:
                    steps.append(o)
                idx = end
            except json.JSONDecodeError:
                idx = brace + 1
        return {"chain": steps}
    except Exception:
        return {"chain": []}


class LMStudioModelClient:
    """Model client for an OpenAI-compatible local endpoint (for example LM Studio).

    Satisfies the engine's ModelClient protocol. Prepends the engagement preamble
    and appends skills relevant to the goal, then returns a parsed tool chain.
    """

    def __init__(self, engagement_preamble: str = "", post=None):
        self.preamble = engagement_preamble
        self._post = post

    def _resolve_post(self):
        if self._post is not None:
            return self._post
        import requests  # lazy: not required to import this module
        return requests.post

    def complete(self, system: str, user: str) -> dict:
        names = select_relevant_skills(user)
        skill_text = load_skills(names) if names else ""
        parts = [self.preamble, system]
        if skill_text:
            parts.append(f"# Relevant Skills\n{skill_text}")
        full_system = "\n\n".join(p for p in parts if p)
        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": full_system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
            "top_p": 0.9,
        }
        try:
            response = self._resolve_post()(MODEL_URL, json=payload, timeout=TOOL_TIMEOUT)
            raw = response.json()["choices"][0]["message"]["content"]
            return parse_model_response(raw)
        except Exception:
            return {"chain": []}
