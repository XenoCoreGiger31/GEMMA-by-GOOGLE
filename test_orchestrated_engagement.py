"""Tests for the Approach-A orchestrated engagement (Phase 4).

run_orchestrated_engagement is the multi-agent `engage` path built on the SAME honest
engine the single-agent loop uses: a gated recon populates AgentMemory, then every
untried open port is worked by run_attacker_gated (curated-PoC → gated-msf → model
chain, breach_confirmed on real evidence only), each attacker result is re-confirmed by
the validator, and a client report is generated.

Every dependency that touches the real world — recon, tool execution, the model — is
INJECTED, so these tests use fakes: no MCP session, no sandbox, no LLM, and crucially no
mcp_client (the ungated path). That injection is also the gate-safety invariant: the
orchestrated path executes ONLY through the gated execute_fn it is handed.
"""
import asyncio

import mcp_client
from agent_schema import TaskStatus, AgentName
from exploitation_core import AgentMemory
from orchestrator_agent import run_orchestrated_engagement


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


def _recon_with_ports(ports, fingerprints=None):
    """A fake, already-gated recon that records its call and seeds memory like the
    spine's run_recon does (open ports + optional fingerprints)."""
    calls = []

    async def _fn(session, target, memory):
        calls.append(target)
        memory.add_ports(list(ports))
        if fingerprints:
            memory.add_fingerprints(fingerprints)

    _fn.calls = calls
    return _fn


def test_confirmed_breach_flows_recon_attack_validate_report():
    ex = FakeExecutor(output="uid=0(root) gid=0(root)", ok=True)
    memory = AgentMemory()
    out = asyncio.run(run_orchestrated_engagement(
        session=None, target="10.0.0.5", memory=memory,
        recon_fn=_recon_with_ports(["21"]), execute_fn=ex, model_fn=_model([]),
    ))
    # Port worked exactly once and filed as a success.
    assert memory.tried_ports == ["21"]
    assert memory.successful_attacks == ["21"]
    # Attacker fired the curated vsftpd PoC through the injected gated executor.
    assert ex.calls and ex.calls[0]["tool"] == "run_exploit"
    # Report is client-ready and reflects the one confirmed finding.
    assert "- Confirmed findings: 1" in out["report"]
    # Pipeline surfaced both an attacker and a validator message for the port.
    agents = [m.agent for m in out["results"]]
    assert AgentName.ATTACKER in agents
    assert AgentName.VALIDATOR in agents


def test_no_evidence_port_is_tried_but_not_confirmed():
    ex = FakeExecutor(output="[info] just a service banner", ok=True)
    memory = AgentMemory()
    out = asyncio.run(run_orchestrated_engagement(
        session=None, target="10.0.0.5", memory=memory,
        recon_fn=_recon_with_ports(["9999"]), execute_fn=ex,
        model_fn=_model([{"tool": "run_nuclei", "target": "10.0.0.5"}]),
    ))
    assert memory.tried_ports == ["9999"]
    assert memory.failed_attacks == ["9999"]
    assert "- Confirmed findings: 0" in out["report"]


def test_every_open_port_worked_once_and_loop_terminates():
    ex = FakeExecutor(output="[info] banner", ok=True)
    memory = AgentMemory()
    recon = _recon_with_ports(["21", "22", "80"])
    asyncio.run(run_orchestrated_engagement(
        session=None, target="10.0.0.5", memory=memory,
        recon_fn=recon, execute_fn=ex,
        model_fn=_model([{"tool": "run_httpx", "target": "10.0.0.5"}]),
    ))
    assert recon.calls == ["10.0.0.5"], "recon must run exactly once, first"
    assert sorted(memory.tried_ports) == ["21", "22", "80"]
    assert memory.has_untried_ports() is False


def test_no_open_ports_means_no_attack_and_empty_report():
    ex = FakeExecutor(output="whatever", ok=True)
    memory = AgentMemory()
    out = asyncio.run(run_orchestrated_engagement(
        session=None, target="10.0.0.5", memory=memory,
        recon_fn=_recon_with_ports([]), execute_fn=ex, model_fn=_model([]),
    ))
    assert ex.calls == [], "no ports => nothing executed"
    assert memory.tried_ports == []
    assert "- Confirmed findings: 0" in out["report"]


def test_gate_safety_never_touches_ungated_mcp_client(monkeypatch):
    """The orchestrated path must execute ONLY through the injected gated execute_fn.
    If any stage reaches for mcp_client.call_tool (the ungated path the attacker was
    rebuilt to avoid), this blows up."""
    def _boom(*a, **k):
        raise AssertionError("orchestrated path used ungated mcp_client.call_tool")
    monkeypatch.setattr(mcp_client, "call_tool", _boom)

    ex = FakeExecutor(output="uid=0(root) gid=0(root)", ok=True)
    memory = AgentMemory()
    asyncio.run(run_orchestrated_engagement(
        session=None, target="10.0.0.5", memory=memory,
        recon_fn=_recon_with_ports(["21"]), execute_fn=ex, model_fn=_model([]),
    ))
    assert ex.calls, "execution went through the injected gated executor"
