"""
test_controller_agent.py

The closed-loop controller — HALO's replanning policy engine.

These tests pin the monster's contract: recon seeds the belief state once, then
every iteration the policy is re-invoked with the FULL state plus what has failed,
picks a single next action, and the controller dispatches it through the honest,
gated engine (run_attacker_gated → breach_confirmed → validator). The loop stops
on real teeth — policy-done, budget, wall-clock scope-expiry, kill-switch, or a
no-progress stall — and never on the model's unverified say-so.

Every world-touching dependency (recon_fn, execute_fn, model_fn, policy_fn) is a
fake so the whole loop runs offline and deterministically.
"""

import asyncio

import pytest

from agent_schema import TaskStatus
from exploitation_core import AgentMemory
import controller_agent
from controller_agent import run_controlled_engagement, state_fingerprint


# ── Fakes ────────────────────────────────────────────────────────────────────

class ScriptedPolicy:
    """A fake planner-as-policy: returns a scripted action per call, and records
    the (goal, state, completed, failed) it was handed each time so tests can
    assert the failure-feedback contract."""

    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = []

    def __call__(self, goal, state, completed, failed):
        self.calls.append({"goal": goal, "state": state,
                           "completed": list(completed), "failed": list(failed)})
        if self._actions:
            return self._actions.pop(0)
        return {"kind": "done", "rationale": "nothing left"}


def make_recon(ports_to_add, fingerprints=None):
    """A fake recon that seeds the memory with open ports (and optional fps)."""
    async def _recon(session, target, memory):
        memory.add_ports(ports_to_add)
        if fingerprints:
            memory.add_fingerprints(fingerprints)
    return _recon


def make_model_chain():
    """Fake model_fn: always offers a single generic run_exploit step so the
    gated attacker path has something to execute for any port."""
    def _model(goal):
        return {"chain": [{"tool": "run_exploit", "code": "payload",
                           "target": "t"}]}
    return _model


BREACH = "__BREACH__"   # sentinel: prove the breach via the nonce the attacker injects
NO_EVIDENCE = "connection established, banner: hello"    # not a breach


def make_execute(outcomes):
    """Fake gated execute_fn. `outcomes` maps port -> (output, ok). A BREACH sentinel
    is turned into the real proof shape: the hardened curated PoC confirms ONLY via a
    HALO-EVIDENCE line echoing the single-use nonce the gated attacker mints and
    injects into the run_exploit step — so a breach lands iff that nonce plumbing
    works end to end. The step carries no port, so we thread it via a mutable box."""
    box = {"port": None}

    async def _execute(session, step):
        out, ok = outcomes.get(box["port"], (NO_EVIDENCE, True))
        if out == BREACH:
            nonce = step.get("nonce", "")
            return (f"HALO-EVIDENCE nonce={nonce} level=exec" if nonce
                    else "backdoor opened but no nonce to prove it"), ok
        return out, ok
    return _execute, box


def run(coro):
    return asyncio.run(coro)


# ── 1. Recon seeds the belief state before any planning ──────────────────────

def test_recon_runs_once_before_first_policy_call():
    mem = AgentMemory()
    recon = make_recon([21])
    policy = ScriptedPolicy([{"kind": "done", "rationale": "done"}])

    run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="own it", memory=mem,
        recon_fn=recon, execute_fn=make_execute({})[0],
        model_fn=make_model_chain(), policy_fn=policy,
    ))

    # recon populated ports, and the policy's first call already saw them.
    assert mem.open_ports == [21]
    assert policy.calls[0]["state"]["open_ports"] == [21]


# ── 2. One action per iteration, driven by the policy ────────────────────────

def test_policy_is_reinvoked_each_iteration_with_current_state():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "ftp"},
        {"kind": "attack", "port": 23, "rationale": "telnet"},
        {"kind": "done", "rationale": "done"},
    ])
    execute, box = make_execute({21: (NO_EVIDENCE, True), 23: (NO_EVIDENCE, True)})

    # attack dispatch must set the current port on the box so execute answers per-port
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="own it", memory=mem,
            recon_fn=make_recon([21, 23]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    assert len(policy.calls) == 3            # two attacks + the done
    assert result["termination"]["reason"] == "policy_done"


# ── 3. Honest breach: real shell evidence marks success, validator re-confirms ─

def test_confirmed_breach_marks_port_success_and_validates():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "ftp backdoor"},
        {"kind": "done", "rationale": "popped"},
    ])
    execute, box = make_execute({21: (BREACH, True)})
    box["port"] = 21

    result = run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="own it", memory=mem,
        recon_fn=make_recon([21]), execute_fn=execute,
        model_fn=make_model_chain(), policy_fn=policy,
    ))

    assert 21 in mem.successful_attacks
    # a validator message independently re-confirmed the same verdict
    validator_msgs = [m for m in result["results"] if m.agent.value == "validator"]
    assert any(m.status == TaskStatus.SUCCESS for m in validator_msgs)


# ── 4. HONESTY INVARIANT: ok=True with no evidence is NOT a breach ───────────

def test_unverified_success_is_not_counted_as_breach():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "claims success"},
        {"kind": "done", "rationale": "done"},
    ])
    # execute returns ok=True but the output has NO shell/cred evidence.
    execute, box = make_execute({21: (NO_EVIDENCE, True)})
    box["port"] = 21

    run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="own it", memory=mem,
        recon_fn=make_recon([21]), execute_fn=execute,
        model_fn=make_model_chain(), policy_fn=policy,
    ))

    assert 21 not in mem.successful_attacks
    assert 21 in mem.failed_attacks


# ── 5. Policy 'done' terminates cleanly ──────────────────────────────────────

def test_policy_done_terminates():
    mem = AgentMemory()
    policy = ScriptedPolicy([{"kind": "done", "rationale": "goal met"}])

    result = run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="g", memory=mem,
        recon_fn=make_recon([80]), execute_fn=make_execute({})[0],
        model_fn=make_model_chain(), policy_fn=policy,
    ))
    assert result["termination"]["reason"] == "policy_done"


# ── 6. Budget teeth: max_iterations caps the loop ────────────────────────────

def test_budget_exhaustion_stops_the_loop():
    mem = AgentMemory()
    # policy would attack a fresh port forever; only the budget can stop it.
    ports = list(range(1000, 2000))

    class Forever:
        def __init__(self):
            self.calls = 0

        def __call__(self, goal, state, completed, failed):
            self.calls += 1
            return {"kind": "attack", "port": ports[self.calls], "rationale": "more"}

    policy = Forever()
    execute, box = make_execute({})
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy, max_iterations=5,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    assert result["termination"]["reason"] == "budget_exhausted"
    assert result["termination"]["iterations"] == 5


# ── 7. Scope-expiry teeth: the wall-clock deadline (the sqlmap bug) ──────────

def test_wall_clock_deadline_stops_before_next_action():
    mem = AgentMemory()
    dispatched = {"count": 0}

    class CountingPolicy:
        def __call__(self, goal, state, completed, failed):
            return {"kind": "attack", "port": 21, "rationale": "keep going"}

    # a clock that jumps PAST the deadline on the 2nd read, so iteration 1 runs
    # and iteration 2's guard trips before dispatch.
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0])

    def fake_clock():
        return next(ticks)

    execute, box = make_execute({21: (NO_EVIDENCE, True)})
    box["port"] = 21
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        dispatched["count"] += 1
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([21]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=CountingPolicy(),
            deadline=10.0, now_fn=fake_clock, max_iterations=50,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    assert result["termination"]["reason"] == "scope_expired"
    assert dispatched["count"] == 1     # exactly one action ran before the wall


# ── 8. Kill-switch teeth ─────────────────────────────────────────────────────

class FakeHaltedEngagement:
    class _Kill:
        def is_halted(self):
            return True
    kill_switch = _Kill()


def test_killswitch_halt_stops_the_loop():
    mem = AgentMemory()
    policy = ScriptedPolicy([{"kind": "attack", "port": 21, "rationale": "x"}])

    result = run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="g", memory=mem,
        recon_fn=make_recon([21]), execute_fn=make_execute({})[0],
        model_fn=make_model_chain(), policy_fn=policy,
        engagement=FakeHaltedEngagement(),
    ))
    assert result["termination"]["reason"] == "halted"


# ── 9. Stall detection: no progress for stall_limit iterations → honest stop ──

def test_stall_when_state_stops_changing():
    mem = AgentMemory()
    # policy keeps asking to re-recon, but recon adds nothing new → state frozen.
    class ReconForever:
        def __call__(self, goal, state, completed, failed):
            return {"kind": "recon", "rationale": "look again"}

    async def barren_recon(session, target, memory):
        pass   # adds nothing

    result = run(run_controlled_engagement(
        session=None, target="10.0.0.1", goal="g", memory=mem,
        recon_fn=barren_recon, execute_fn=make_execute({})[0],
        model_fn=make_model_chain(), policy_fn=ReconForever(),
        stall_limit=3, max_iterations=50,
    ))
    assert result["termination"]["reason"] == "stalled"
    assert result["termination"]["iterations"] <= 4


# ── 10. Reshuffle detector: re-emitting a tried port is not re-dispatched ────

def test_already_tried_port_is_not_redispatched():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "first try"},
        {"kind": "attack", "port": 21, "rationale": "same again"},  # reshuffle
        {"kind": "attack", "port": 21, "rationale": "and again"},
        {"kind": "attack", "port": 21, "rationale": "again"},
    ])
    execute, box = make_execute({21: (NO_EVIDENCE, True)})
    box["port"] = 21
    dispatched = {"count": 0}
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        dispatched["count"] += 1
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([21]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy,
            stall_limit=3, max_iterations=50,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    assert dispatched["count"] == 1                         # only the first ran
    assert result["adaptation"]["repeats"] >= 1
    assert result["termination"]["reason"] == "stalled"     # reshuffles → stall


# ── 11. Failure feedback: failed actions are handed to the policy ────────────

def test_failed_action_feeds_back_into_policy():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "try"},
        {"kind": "attack", "port": 23, "rationale": "pivot"},
        {"kind": "done", "rationale": "done"},
    ])
    execute, box = make_execute({21: (NO_EVIDENCE, True), 23: (NO_EVIDENCE, True)})
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([21, 23]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    # by the 2nd policy call, port 21's failure is in the `failed` argument.
    second_call_failed = policy.calls[1]["failed"]
    assert any(f.get("port") == 21 for f in second_call_failed)


# ── 12. Decision trace + adaptation score ────────────────────────────────────

def test_trace_and_adaptation_score_recorded():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "a"},
        {"kind": "attack", "port": 23, "rationale": "b"},
        {"kind": "done", "rationale": "done"},
    ])
    execute, box = make_execute({21: (NO_EVIDENCE, True), 23: (NO_EVIDENCE, True)})
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([21, 23]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    trace = result["trace"]
    assert len(trace) >= 2
    assert all("action" in t and "differs_from_last" in t for t in trace)
    # two distinct attacks → both novel → adaptation score 1.0
    assert result["adaptation"]["novel"] == 2
    assert result["adaptation"]["score"] == pytest.approx(1.0)


# ── 13. Report is generated and honest ───────────────────────────────────────

def test_report_reflects_confirmed_and_unconfirmed():
    mem = AgentMemory()
    policy = ScriptedPolicy([
        {"kind": "attack", "port": 21, "rationale": "real"},
        {"kind": "attack", "port": 23, "rationale": "fake"},
        {"kind": "done", "rationale": "done"},
    ])
    execute, box = make_execute({21: (BREACH, True), 23: (NO_EVIDENCE, True)})
    orig = controller_agent._dispatch_attack

    async def spy(session, action, target, memory, execute_fn, model_fn, select_fn):
        box["port"] = action["port"]
        return await orig(session, action, target, memory, execute_fn, model_fn, select_fn)
    controller_agent._dispatch_attack = spy
    try:
        result = run(run_controlled_engagement(
            session=None, target="10.0.0.1", goal="g", memory=mem,
            recon_fn=make_recon([21, 23]), execute_fn=execute,
            model_fn=make_model_chain(), policy_fn=policy,
        ))
    finally:
        controller_agent._dispatch_attack = orig

    report = result["report"]
    assert "Confirmed findings: 1" in report
    assert "Unconfirmed" in report


# ── state_fingerprint helper ─────────────────────────────────────────────────

def test_state_fingerprint_changes_with_state():
    mem = AgentMemory()
    before = state_fingerprint(mem)
    mem.add_ports([21])
    after = state_fingerprint(mem)
    assert before != after
