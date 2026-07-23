# Phase 3 — Rebuild the Attacker on the honest, gated engine

**Date:** 2026-07-23
**Status:** design, approved (Approach A)
**Parent:** multi-agent-integration (Phase 3 of 6). Phase 1 (exploitation_core) + Phase 2 (validator) done.

## Problem

The multi-agent `attacker_agent.run_attacker` selects one tool by keyword and fires it
through `mcp_client.call_tool`. That path **bypasses the operator gate**: it spawns
`mcp_server.py` directly, skipping the `ENGAGEMENT` authorization gate and the
two-phase sandbox approval (`_run_exploit_gated`) that every exploit in the
single-agent loop passes through. It also never uses the curated-PoC / gated-msf
selection (`plan_exploit_step`) or evidence-based confirmation (`breach_confirmed`).

Meanwhile the single-agent loop already contains a complete, async, gated attack
engine (`run_attack_loop` → `plan_exploit_step` → `execute_step`[gated] →
`breach_confirmed`), but it is not exposed as a reusable agent.

## Solution (Approach A)

Add a new **async, gated** attacker entry to `attacker_agent.py` that reuses the
Phase-1 engine and the spine's gated executor via **dependency injection** — never
`mcp_client`.

```python
async def run_attacker_gated(
    session, port, target, service, memory,
    execute_fn, model_fn, select_fn=None,
) -> AgentMessage
```

Behaviour, per port:
1. `data = model_fn(goal)`; `chain = data.get("chain", [])` — the model's proposed
   tool chain (injected; defaults to `agent_loop.call_model` when wired in Phase 4).
2. `chain = plan_exploit_step(port, target, service, chain, memory, select_fn)` —
   curated PoC → gated msf module → model chain (Phase-1 engine; leads with the
   real exploit, drops duplicate model-authored exploit steps).
3. For each `step` in `chain`:
   - skip if `not tool_fits_port(step["tool"], port)` (deterministic fit gate),
   - `output, ok = await execute_fn(session, step)` — the **injected gated executor**
     (defaults to the spine's `execute_step`, so exploits hit the ENGAGEMENT gate +
     two-phase operator approval),
   - if `breach_confirmed(step["tool"], output, ok)`: record the breach and stop.
4. Return an `AgentMessage(agent=ATTACKER, status=SUCCESS if breached else FAILED,
   result={...})`.

**Result shape** (aligned with the Phase-2 validator's reads — `tool_used`,
`attempts`, `ok`):
```python
{
    "port": port,
    "breached": bool,
    "tool_used": tool | "",     # the breaching step's tool, or last attempted, or ""
    "attempts": output,          # that step's raw output (validator reads "attempts")
    "ok": ok,                    # that step's success flag
}
```
So `validator_agent.validate_finding(result, target)` independently re-derives the
same verdict via `breach_confirmed` — attacker and validator stay consistent.

## Why injection (not `import agent_loop`)

`execute_fn` and `model_fn` are passed in so the agent is unit-testable with a fake
gated executor and fake model — no real sandbox, stdin, MCP session, or LLM in tests.
It also honors the Phase-1 principle: **the spine stays in `agent_loop.py`; agents
reuse it through a hook.** `attacker_agent` imports only `exploitation_core` +
`agent_schema` at module load → no import cycle (`agent_loop` does not import
`attacker_agent`).

## Scope

- **Add** `run_attacker_gated` (+ any small private helper) to `attacker_agent.py`.
- **Add** `from exploitation_core import plan_exploit_step, breach_confirmed,
  tool_fits_port`.
- **Leave the existing sync `run_attacker` and its `mcp_client` import in place,
  untouched** — it is not live (not reachable from `engage`) and Phase 4 retires it
  when it rewires the orchestrator. Additive-only; no behaviour change to existing code.
- No changes to `orchestrator_agent.py`, `validator_agent.py`, `agent_loop.py`,
  `exploitation_core.py`, `agent_schema.py`.

## Testing / acceptance

New `test_attacker_gated.py` (drives the coroutine with `asyncio.run`, no
`pytest-asyncio` dependency; `execute_fn` is an `async def` fake that records calls,
`model_fn` is a plain fake):

1. **Curated port routes through the gated executor.** port `21`, service
   `"vsftpd 2.3.4"`, `model_fn` returns an empty chain. Assert the fake `execute_fn`
   is called with a `run_exploit` step whose `code` is the curated vsftpd PoC (proves
   `plan_exploit_step` led with the curated PoC and it went through the injected gate,
   not `mcp_client`).
2. **Real evidence confirms.** same as (1) with `execute_fn` returning
   `("uid=0(root) gid=0(root)", True)` → `status == SUCCESS`, `result["breached"] is
   True`, `result["tool_used"] == "run_exploit"`, `"uid=0(root)"` in
   `result["attempts"]`.
3. **No evidence does NOT confirm.** non-curated port `9999`, `model_fn` returns
   `{"chain": [{"tool": "run_nuclei", "target": "t"}]}`, `execute_fn` returns
   `("[info] banner", True)` → `status == FAILED`, `result["breached"] is False`.
4. **Fit gate skips wrong tool.** port `80`, `model_fn` returns
   `{"chain": [{"tool": "run_hydra", "target": "t"}]}` → `tool_fits_port` is False →
   the fake `execute_fn` is **never called** for it; `breached is False`.
5. **Attacker→validator consistency.** feed the SUCCESS `result` from (2) into
   `validator_agent.validate_finding(result, target)` → `confirmed is True`; feed the
   FAILED `result` from (3) → `confirmed is False`.

Primary gate: full suite stays green (`python3 -m pytest -q`; baseline **206 passed**)
plus the new attacker tests.

## Out of scope (Phase 4)

- Wiring `run_attacker_gated` + an async orchestrator into the real `engage` flow
  (defaulting `execute_fn=execute_step`, `model_fn=call_model`, one shared
  `mcp_session`, the `ENGAGEMENT` global).
- Retiring the old sync `run_attacker` and its `mcp_client` exploit path.
- NegativeCache gating and the per-port loop across the whole AttackState (the
  orchestrator will drive per-port dispatch).
