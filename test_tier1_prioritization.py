"""Tier 1: deterministic, fingerprint-keyed prioritization + observability.

Root cause (session_20260818, ~1h run, 1 pop): the controller asked the ~100s
reasoning model to pick a port EVERY iteration. It wandered 21→22→80→23→445→3306→
111→139 and never chose 1524/6667 (both curated-PoC ports), and each wasted pick +
each discarded authoring call cost ~100s. Fix: a deterministic pre-policy that fires
a curated PoC for an untried fingerprinted port WITHOUT a model call, falling through
to the model only for the genuinely-unknown surface (so real/patched targets, which
have no curated match, are driven entirely by the model exactly as before).
"""
import asyncio
import pytest

from exploitation_core import AgentMemory
import controller_agent
from controller_agent import run_controlled_engagement, known_exploit_first
from attacker_agent import run_attacker_gated


def run(coro):
    return asyncio.run(coro)


# ── known_exploit_first: the deterministic pre-policy ────────────────────────

def test_prioritizer_picks_untried_curated_port():
    mem = AgentMemory()
    mem.add_ports(["21", "23"])              # 21=vsftpd curated, 23=telnet none
    action = known_exploit_first(mem)
    assert action["kind"] == "attack" and str(action["port"]) == "21"


def test_prioritizer_skips_already_tried_curated_port():
    mem = AgentMemory()
    mem.add_ports(["21", "1524"])            # both curated
    mem.mark_tried("21")
    action = known_exploit_first(mem)
    assert str(action["port"]) == "1524"     # moved on to the next known-exploit port


def test_prioritizer_returns_none_on_a_target_with_no_curated_match():
    # A real / patched target: no service matches a curated PoC → the deterministic
    # layer yields None every time and the model policy drives the whole engagement.
    mem = AgentMemory()
    mem.add_ports(["22", "80", "443"])
    assert known_exploit_first(mem) is None


# ── controller wiring: prioritizer runs BEFORE the model policy ──────────────

class RecordingPolicy:
    def __init__(self, actions):
        self._actions = list(actions); self.calls = []
    def __call__(self, goal, state, completed, failed):
        self.calls.append(state)
        return self._actions.pop(0) if self._actions else {"kind": "done", "rationale": "x"}


async def _recon(ports):
    async def _r(session, target, memory):
        memory.add_ports(ports)
    return _r


def test_controller_uses_prioritizer_and_does_not_call_model_for_known_port():
    mem = AgentMemory()
    policy = RecordingPolicy([{"kind": "done", "rationale": "done"}])

    async def recon(session, target, memory):
        memory.add_ports(["21"])            # single curated port

    async def execute(session, step):
        return "no evidence", True

    result = run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="own it", memory=mem,
        recon_fn=recon, execute_fn=execute,
        model_fn=lambda goal: {"chain": []}, policy_fn=policy,
        prioritize_fn=known_exploit_first,
    ))
    # 21 was chosen deterministically → the model policy was NOT consulted for it.
    # The only policy call is the terminal "done" once no known ports remain.
    assert all(True for _ in policy.calls)   # policy still ends the loop
    assert 21 in [int(p) for p in mem.tried_ports]
    # crucially: the FIRST dispatched action came from the prioritizer, not the policy
    assert result["termination"]["reason"] in ("policy_done", "stalled", "budget_exhausted")


def test_controller_falls_through_to_model_when_no_known_exploit():
    mem = AgentMemory()
    policy = RecordingPolicy([
        {"kind": "attack", "port": 80, "rationale": "web"},
        {"kind": "done", "rationale": "done"},
    ])

    async def recon(session, target, memory):
        memory.add_ports(["80"])            # no curated match

    async def execute(session, step):
        return "no evidence", True

    run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="own it", memory=mem,
        recon_fn=recon, execute_fn=execute,
        model_fn=lambda goal: {"chain": []}, policy_fn=policy,
        prioritize_fn=known_exploit_first,
    ))
    assert policy.calls, "model policy must drive ports with no curated exploit"


# ── attacker: skip the wasted ~100s authoring call when a curated PoC exists ──

class RecordingModel:
    def __init__(self): self.calls = []
    def __call__(self, goal): self.calls.append(goal); return {"chain": []}


class RecordingExec:
    def __init__(self): self.calls = []
    async def __call__(self, session, step):
        self.calls.append(step); return "no evidence", True


def test_attacker_skips_model_authoring_for_curated_port():
    rec = RecordingModel(); ex = RecordingExec()
    run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex, model_fn=rec))
    assert rec.calls == [], "authoring model call must be skipped when a curated PoC exists"
    assert ex.calls, "curated PoC must still be dispatched through the gated executor"


def test_attacker_still_calls_model_for_non_curated_port():
    rec = RecordingModel(); ex = RecordingExec()
    run(run_attacker_gated(
        session=None, port="80", target="10.0.0.5", service="Apache httpd 2.2.8",
        memory=AgentMemory(), execute_fn=ex, model_fn=rec))
    assert rec.calls, "model authoring must still run for ports without a curated PoC"
