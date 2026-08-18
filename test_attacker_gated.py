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
    # The hardened curated PoC proves the pop through the nonce-bound HALO-EVIDENCE
    # line, not a raw uid=0 banner (which, post-nonce-hardening, no longer confirms a
    # run_exploit on its own — the single-agent path enforces the same).
    ex = NonceEchoExecutor()
    msg = asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex, model_fn=_model([]),
    ))
    assert msg.status == TaskStatus.SUCCESS
    assert msg.result["breached"] is True
    assert msg.result["tool_used"] == "run_exploit"
    assert "HALO-EVIDENCE" in msg.result["attempts"]


class NonceEchoExecutor:
    """Behaves like the REAL hardened curated PoC: it proves a breach ONLY through the
    nonce-bound HALO-EVIDENCE line (pocs/_delivery), never a raw uid=0 banner. So it
    confirms iff run_attacker_gated actually minted a challenge nonce and injected it
    into the run_exploit step — exactly what the single-agent run_attack_loop does.
    This is the shape the live 2026-08-17 engage-loop run failed on: it picked port 21
    / vsftpd 2.3.4 correctly but the gated attacker never nonced the step, so the pop
    could not be confirmed ('Nothing worked on port 21')."""
    def __init__(self):
        self.calls = []

    async def __call__(self, session, step):
        self.calls.append(step)
        nonce = step.get("nonce", "")
        if nonce:
            return f"HALO-EVIDENCE nonce={nonce} level=exec", True
        return "backdoor opened, but no HALO_NONCE was provided to prove it", True


def test_curated_run_exploit_confirmed_via_nonce_evidence():
    ex = NonceEchoExecutor()
    msg = asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex, model_fn=_model([]),
    ))
    assert msg.status == TaskStatus.SUCCESS
    assert msg.result["breached"] is True
    # a nonce was actually minted and injected into the executed run_exploit step
    assert ex.calls[0].get("nonce"), "run_attacker_gated must mint+inject a challenge nonce"


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
    ex_hit = NonceEchoExecutor()
    hit = asyncio.run(run_attacker_gated(
        session=None, port="21", target="10.0.0.5", service="vsftpd 2.3.4",
        memory=AgentMemory(), execute_fn=ex_hit, model_fn=_model([]),
    ))
    # attacker confirmed via the single-use nonce; validator re-confirms the same pop
    # via the structured HALO-EVIDENCE artifact (the nonce is already consumed).
    assert validate_finding(hit.result, "10.0.0.5")["confirmed"] is True

    ex_miss = FakeExecutor(output="[info] banner", ok=True)
    miss = asyncio.run(run_attacker_gated(
        session=None, port="9999", target="10.0.0.5", service="unknown",
        memory=AgentMemory(),
        execute_fn=ex_miss, model_fn=_model([{"tool": "run_nuclei", "target": "10.0.0.5"}]),
    ))
    assert validate_finding(miss.result, "10.0.0.5")["confirmed"] is False
