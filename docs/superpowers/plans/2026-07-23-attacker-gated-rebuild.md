# Attacker Gated-Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add an async, gated attacker (`run_attacker_gated`) to `attacker_agent.py` that reuses the Phase-1 engine (`plan_exploit_step` + `breach_confirmed` + `tool_fits_port`) and executes through an INJECTED gated executor — never `mcp_client`, which bypasses the operator gate.

**Architecture:** Additive. New async function + one new import in `attacker_agent.py`. The existing sync `run_attacker` and its `mcp_client` import stay untouched (retired in Phase 4). Dependencies (`execute_fn`, `model_fn`) are injected so the agent is unit-testable with fakes — no real sandbox/stdin/LLM.

**Tech Stack:** Python 3, asyncio, pytest.

## Global Constraints

- Modify ONLY `attacker_agent.py`; add ONE new test file. Do NOT touch `orchestrator_agent.py`, `validator_agent.py`, `agent_loop.py`, `exploitation_core.py`, `agent_schema.py`, `mcp_client.py`.
- Do NOT modify or remove the existing `run_attacker` function or the `from mcp_client import call_tool` line — additive only.
- The new agent must NEVER call `mcp_client`/`call_tool`. Execution goes only through the injected `execute_fn`.
- Result dict keys must be exactly: `port, breached, tool_used, attempts, ok` (so the Phase-2 validator's `validate_finding` re-confirms consistently).
- Full suite green: `python3 -m pytest -q`, baseline **206 passed** → expected **211**.
- Not a git repo — skip commits. Confirm `test_attacker_gated.py` does not already exist before creating it.

---

### Task 1: Add `run_attacker_gated` (async, gated) + tests

**Files:**
- Create: `test_attacker_gated.py`
- Modify: `attacker_agent.py` (add one import; append one async function)

**Interfaces:**
- Consumes: `exploitation_core.plan_exploit_step(port, target, service, chain, memory, select_fn=None) -> list`, `exploitation_core.breach_confirmed(tool, output, ok) -> bool`, `exploitation_core.tool_fits_port(tool, port) -> bool`, `agent_schema.{AgentMessage, AgentName, TaskStatus}`.
- Injected params: `execute_fn(session, step) -> (output: str, ok: bool)` (an `async` callable; defaults in Phase 4 to `agent_loop.execute_step`), `model_fn(goal: str) -> dict` with a `"chain"` list (defaults in Phase 4 to `agent_loop.call_model`).
- Produces: `run_attacker_gated(session, port, target, service, memory, execute_fn, model_fn, select_fn=None) -> AgentMessage` with `result` keys `port, breached, tool_used, attempts, ok`.

- [ ] **Step 1: Write the failing tests**

Create `test_attacker_gated.py`:

```python
"""Tests for the honest, gated attacker (Phase 3).

run_attacker_gated reuses the Phase-1 engine (plan_exploit_step + breach_confirmed)
and executes through an INJECTED gated executor — never mcp_client. These tests use a
fake async execute_fn (records the steps it was handed) and a fake model_fn, so no
real sandbox/stdin/LLM is involved.
"""
import asyncio

from agent_schema import TaskStatus
from attacker_agent import run_attacker_gated
from exploitation_core import AgentMemory
from validator_agent import validate_finding


class FakeExecutor:
    """Async gated-executor stand-in: records every step, returns a scripted result."""
    def __init__(self, output="", ok=True):
        self.calls = []
        self._output = output
        self._ok = ok

    async def __call__(self, session, step):
        self.calls.append(step)
        return self._output, self._ok


def _model(chain):
    def _fn(goal):
        return {"chain": list(chain)}
    return _fn


def test_curated_port_routes_through_gated_executor():
    ex = FakeExecutor(output="uid=0(root) gid=0(root)", ok=True)
    asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex, model_fn=_model([]),
    ))
    assert ex.calls, "gated executor was never called"
    first = ex.calls[0]
    assert first["tool"] == "run_exploit"
    code = first.get("code", "").lower()
    assert "vsftpd" in code or "backdoor" in code


def test_real_evidence_confirms_breach():
    ex = FakeExecutor(output="uid=0(root) gid=0(root)", ok=True)
    msg = asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex, model_fn=_model([]),
    ))
    assert msg.status == TaskStatus.SUCCESS
    assert msg.result["breached"] is True
    assert msg.result["tool_used"] == "run_exploit"
    assert "uid=0(root)" in msg.result["attempts"]


def test_no_evidence_does_not_confirm():
    ex = FakeExecutor(output="[info] service banner", ok=True)
    msg = asyncio.run(run_attacker_gated(
        session=None, port="9999", target="10.0.0.5", service="unknown",
        memory=AgentMemory(),
        execute_fn=ex, model_fn=_model([{"tool": "run_nuclei", "target": "10.0.0.5"}]),
    ))
    assert msg.status == TaskStatus.FAILED
    assert msg.result["breached"] is False


def test_fit_gate_skips_wrong_tool():
    ex = FakeExecutor(output="whatever", ok=True)
    msg = asyncio.run(run_attacker_gated(
        session=None, port="80", target="10.0.0.5", service="http",
        memory=AgentMemory(),
        execute_fn=ex, model_fn=_model([{"tool": "run_hydra", "target": "10.0.0.5"}]),
    ))
    assert ex.calls == [], "hydra on port 80 should be skipped by tool_fits_port"
    assert msg.result["breached"] is False


def test_attacker_result_feeds_validator_consistently():
    ex_hit = FakeExecutor(output="uid=0(root) gid=0(root)", ok=True)
    hit = asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex_hit, model_fn=_model([]),
    ))
    assert validate_finding(hit.result, "10.0.0.5")["confirmed"] is True

    ex_miss = FakeExecutor(output="[info] banner", ok=True)
    miss = asyncio.run(run_attacker_gated(
        session=None, port="9999", target="10.0.0.5", service="unknown",
        memory=AgentMemory(),
        execute_fn=ex_miss, model_fn=_model([{"tool": "run_nuclei", "target": "10.0.0.5"}]),
    ))
    assert validate_finding(miss.result, "10.0.0.5")["confirmed"] is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest test_attacker_gated.py -q`
Expected: FAIL — `ImportError: cannot import name 'run_attacker_gated' from 'attacker_agent'`.

- [ ] **Step 3: Add the import to `attacker_agent.py`**

Below the existing `from mcp_client import call_tool` line, add:

```python
from exploitation_core import plan_exploit_step, breach_confirmed, tool_fits_port
```

- [ ] **Step 4: Append the new async function to `attacker_agent.py`**

Add this function (place it after the existing `run_attacker`, before the `if __name__ == "__main__":` block):

```python
async def run_attacker_gated(session, port, target, service, memory,
                             execute_fn, model_fn, select_fn=None) -> AgentMessage:
    """Honest, gated exploitation of ONE port for the multi-agent pipeline.

    Reuses the Phase-1 engine: plan_exploit_step chooses the exploit (curated PoC →
    gated Metasploit module → the model's own chain), and breach_confirmed decides
    success on real evidence only. Execution goes through the INJECTED execute_fn —
    the spine's gated execute_step (ENGAGEMENT gate + two-phase operator approval) in
    production — never mcp_client, which would bypass the operator gate. model_fn and
    execute_fn are injected so this agent is unit-testable with fakes.

    The result carries tool_used/attempts/ok so validator_agent.validate_finding can
    independently re-confirm the same verdict via breach_confirmed.
    """
    goal = (f"Target: {target}  Port: {port}  Service: {service}. "
            f"Select and run the best exploit for this service.")
    data = model_fn(goal) or {}
    chain = data.get("chain", [])
    chain = plan_exploit_step(port, target, service, chain, memory, select_fn)

    last_tool, last_output, last_ok = "", "", False
    breached = False

    for step in chain:
        tool = step.get("tool", "")
        if not tool_fits_port(tool, port):
            continue
        output, ok = await execute_fn(session, step)
        last_tool, last_output, last_ok = tool, output, ok
        if breach_confirmed(tool, output, ok):
            breached = True
            break

    status = TaskStatus.SUCCESS if breached else TaskStatus.FAILED
    return AgentMessage(
        agent=AgentName.ATTACKER,
        engagement_id="",
        task_id=f"attack_{port}",
        status=status,
        result={
            "port": port,
            "breached": breached,
            "tool_used": last_tool,
            "attempts": last_output,
            "ok": last_ok,
        },
    )
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `python3 -m pytest test_attacker_gated.py -q`
Expected: PASS (5 passed).

- [ ] **Step 6: Run the full suite**

Run: `python3 -m pytest -q`
Expected: `211 passed` (206 baseline + 5 new), zero failures. If any prior test fails, something out of scope was touched — revert and fix.

---

## Self-Review

**1. Spec coverage:** async gated attacker using plan_exploit_step + breach_confirmed + tool_fits_port (Step 4); injected execute_fn/model_fn (Step 4 signature); never mcp_client (Step 4 uses only execute_fn); result keys port/breached/tool_used/attempts/ok (Step 4); old run_attacker + mcp_client import untouched (Global Constraints + additive Steps 3–4); 5 tests incl. gated-routing, evidence, no-evidence, fit-gate, validator-consistency (Step 1); full-suite gate (Step 6). ✓
**2. Placeholder scan:** No TBD/TODO; complete code in every code step. ✓
**3. Type consistency:** `run_attacker_gated` signature identical in spec, plan Interfaces, and tests; `execute_fn` awaited returns `(output, ok)` matching `execute_step`; `model_fn(goal) -> {"chain": [...]}`; result keys match the Phase-2 validator's reads (`tool_used`, `attempts`, `ok`). ✓
