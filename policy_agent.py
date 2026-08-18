"""
policy_agent.py

The planner-as-policy — the brain HALO's closed loop re-invokes each iteration.

`planner_agent.plan()` decomposes a goal into a frozen list ONCE. This module is
its closed-loop successor: a policy that is called every controller iteration with
the current belief state and the full failure history, and returns the SINGLE next
action. Feeding failures back is the whole point — it is what lets the model stop
re-running dead vectors instead of reshuffling a plan fixed at t=0.

Decision-making is delegated to the local model; this module is a prompt wrapper
plus a defensive parser. The model HTTP call is injected via `model_call`, so the
policy is unit-testable offline and production supplies the real LM Studio call.

Action shape returned to the controller:
    {"kind": "attack", "port": <int>, "rationale": <str>}   # exploit one port
    {"kind": "recon",  "rationale": <str>}                   # refresh recon
    {"kind": "done",   "rationale": <str>}                   # goal met, stop
    {"kind": "noop",   "rationale": <str>}                   # parse failure — the
                                                             # controller's stall
                                                             # guard retires it
"""

import json
import re

import requests

from halo_config import MODEL_URL, MODEL_NAME, MODEL_TIMEOUT, MODEL_MAX_TOKENS

POLICY_SYSTEM_PROMPT = """You are the Policy brain of an autonomous penetration-testing loop called Halo.

You are called ONCE PER STEP. Each call you are given the current engagement state and the full history of what has already FAILED. Your job is to choose the SINGLE best next action — not a whole plan, just the one next move — and then you will be called again with the updated state.

Rules:
- Do NOT repeat an action that already failed. The failures are listed for you; pick something different.
- Prefer attacking an untried open port over re-attacking a tried one.
- When there is no productive move left, or the goal is clearly met, return kind "done".

Respond with ONLY a single JSON object, no prose, no markdown fences, in exactly this shape:

{"kind": "attack", "port": 23, "rationale": "short reason"}

Valid kinds:
- "attack" (requires an integer "port") — run the best exploit against that port
- "recon" — gather more information about the target
- "done" — stop; nothing productive remains or the goal is met
"""

# Recover the first JSON object embedded in a possibly-chatty model reply.
_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def _render_user_prompt(goal, state, completed, failed) -> str:
    """Lay the goal, belief state, and — critically — the failure history in front
    of the model so its next choice is conditioned on what has already not worked."""
    lines = [
        f"ENGAGEMENT GOAL: {goal}",
        "",
        "CURRENT STATE:",
        f"  open ports:      {state.get('open_ports', [])}",
        f"  tried ports:     {state.get('tried', [])}",
        f"  breached ports:  {state.get('successes', [])}",
        f"  findings:        {state.get('findings', [])}",
        f"  flags captured:  {state.get('flags', [])}",
        "",
        "ALREADY FAILED (do NOT repeat these):",
    ]
    if failed:
        for f in failed:
            port = f.get("port", "?")
            why = f.get("rationale", "") or f.get("reason", "")
            lines.append(f"  - port {port}: {why}".rstrip())
    else:
        lines.append("  (nothing failed yet)")
    lines += ["", "Choose the single next action as JSON."]
    return "\n".join(lines)


def _default_model_call(system_prompt: str, user_prompt: str) -> str:
    """Production model call: the local LM Studio chat endpoint. Injected in tests."""
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": MODEL_MAX_TOKENS,
    }
    response = requests.post(MODEL_URL, json=payload, timeout=MODEL_TIMEOUT)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def _parse_action(raw: str) -> dict:
    """Turn a raw model reply into an action dict, defensively.

    A 12B routinely wraps JSON in prose or fences, so we extract the first JSON
    object before parsing. Anything we cannot parse into a known-kind action becomes
    a "noop" — never a fabricated breach and never a false "done" — so a single bad
    generation costs one stall tick, not a crashed engagement or a phantom result.
    """
    match = _JSON_OBJECT.search(raw or "")
    if match:
        try:
            action = json.loads(match.group(0))
            if isinstance(action, dict) and action.get("kind") in {"attack", "recon", "done"}:
                return action
        except json.JSONDecodeError:
            pass
    return {"kind": "noop",
            "rationale": f"unparseable model output: {(raw or '')[:120]!r}"}


def build_policy(model_call=None):
    """Return a policy_fn(goal, state, completed, failed) -> action for the controller.

    `model_call(system_prompt, user_prompt) -> str` is injected so the policy is
    testable offline; production defaults to the local LM Studio endpoint.
    """
    model_call = model_call or _default_model_call

    def policy(goal, state, completed, failed):
        user_prompt = _render_user_prompt(goal, state, completed, failed)
        try:
            raw = model_call(POLICY_SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            # The policy runs inside a long async engagement; a timed-out or dropped
            # model call must degrade to a no-op the controller's stall guard retires,
            # never propagate and crash the whole loop (as an uncaught ReadTimeout did
            # live on 2026-08-17). Mirrors the parse-failure and call_model contracts.
            return {"kind": "noop", "rationale": f"model call failed: {e}"}
        return _parse_action(raw)

    return policy
