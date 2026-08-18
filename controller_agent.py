"""
controller_agent.py

The Controller — HALO's closed-loop replanning engine.

This is the piece the pipeline was missing. `planner_agent.plan()` fires once and
emits a frozen subtask list; `orchestrator_agent.run_engagement` walks that list in
order and never re-plans. The loop is open: when a step fails or recon reveals
something the plan never anticipated, nothing revises the plan.

The Controller closes that loop. Each iteration it re-invokes a POLICY (the planner
promoted from one-shot decomposer to a per-step policy) with the FULL evolving
belief state plus everything that has already failed, takes the single next action
it returns, dispatches it through the honest gated engine, folds the verified
result back into the belief state, and re-plans. It stops only on real teeth:

  - policy_done       the policy itself signals the goal is met
  - budget_exhausted  the iteration budget is spent
  - scope_expired     the wall-clock deadline passed (the guard sqlmap blew past)
  - halted            the engagement kill-switch is thrown
  - stalled           the belief state stopped changing (no progress / reshuffling)

Honesty is preserved end to end: exploitation runs through the INJECTED gated
execute_fn (never the ungated mcp_client), success is decided by
exploitation_core.breach_confirmed on real evidence only, and every attacker result
is independently re-confirmed by the validator. The loop cannot self-grade.

Every world-touching dependency (recon_fn, execute_fn, model_fn, policy_fn) is
injected, so the entire loop is unit-testable offline with fakes.
"""

import hashlib
import json
import logging
import time

from agent_schema import AgentMessage, AgentName, TaskStatus
from attacker_agent import run_attacker_gated
from validator_agent import run_validator, generate_report
from poc_library import select_poc

# Shares the "agent" logger configured by halo_logging.setup_logger in the spine, so
# controller decisions land in the same session log with the same formatting. Before
# this, every policy decision was invisible — the 7.5-min gaps in session_20260818
# were unlogged model calls re-picking already-tried ports.
log = logging.getLogger("agent")


def known_exploit_first(memory):
    """Deterministic pre-policy: prefer an untried open port whose fingerprint matches
    a curated PoC, and return that attack action WITHOUT a model call. Returns None
    when no known exploit remains — so on a real / patched target (nothing matches a
    curated PoC) this yields None every iteration and the model policy drives the whole
    engagement exactly as before. Fingerprint-keyed via select_poc, never a hardcoded
    port list, so it generalizes past Metasploitable: it only short-circuits where we
    genuinely hold a known-good exploit for the fingerprinted service."""
    for port in memory.open_ports:
        if port in memory.tried_ports:
            continue
        if select_poc(port, memory.service_hint(port)):
            hint = memory.service_hint(port) or f"port {port}"
            return {"kind": "attack", "port": port,
                    "rationale": f"curated PoC matches {hint} — deterministic, no model call"}
    return None


def state_fingerprint(memory) -> str:
    """A stable hash of the belief state. Two calls return the same value iff the
    engagement has learned nothing new in between — this is how the loop tells
    progress from spinning (a policy that only reshuffles known facts)."""
    snapshot = json.dumps(memory.summary(), sort_keys=True, default=str)
    return hashlib.sha256(snapshot.encode()).hexdigest()


def _action_key(action: dict):
    """Identity of an action for the repeat detector. Attacks are keyed by port so
    re-emitting the same port is caught; recon is intentionally un-keyed (a fresh
    recon can legitimately repeat — the stall guard, not the repeat guard, retires
    fruitless recon)."""
    if action.get("kind") == "attack":
        return ("attack", action.get("port"))
    return (action.get("kind"), None)


async def _dispatch_attack(session, action, target, memory,
                           execute_fn, model_fn, select_fn):
    """Run ONE attack action through the honest, gated exploitation path.

    Thin seam over run_attacker_gated so the controller reads at one altitude and
    tests can spy on / stub dispatch without reaching into the attacker internals.
    """
    port = action["port"]
    service = memory.service_hint(port)
    return await run_attacker_gated(
        session, port, target, service, memory,
        execute_fn=execute_fn, model_fn=model_fn, select_fn=select_fn,
    )


def _is_halted(engagement) -> bool:
    if engagement is None:
        return False
    kill = getattr(engagement, "kill_switch", None)
    return bool(kill and kill.is_halted())


async def run_controlled_engagement(
    session, target, goal, memory,
    recon_fn, execute_fn, model_fn, policy_fn,
    engagement=None, engagement_id="", select_fn=None,
    max_iterations=25, stall_limit=4,
    deadline=None, now_fn=time.monotonic,
    prioritize_fn=None,
) -> dict:
    """Drive a target with a closed replanning loop over the shared honest engine.

    Args:
        session, target, goal: the engagement's MCP session, host, and objective.
        memory: an AgentMemory — the belief state the loop grows and reasons over.
        recon_fn(session, target, memory): seeds the belief state once, up front.
        execute_fn(session, step) -> (output, ok): the GATED executor (operator
            approval + scope gate in production). The only thing that touches the
            target during exploitation.
        model_fn(goal) -> dict: the local model call the gated attacker uses to
            propose an exploit chain.
        policy_fn(goal, state, completed, failed) -> action: the planner-as-policy.
            Returns one action dict: {"kind": "attack"|"recon"|"done", "port": int?,
            "rationale": str}. `state` is memory.summary(); `failed` is the list of
            failed action records so the policy can avoid repeating them.
        engagement: optional Engagement — consulted for the kill-switch.
        max_iterations: hard cap on replans (budget teeth).
        stall_limit: consecutive no-progress iterations tolerated before stopping.
        deadline: optional wall-clock value (same units as now_fn) after which the
            loop refuses to dispatch another action (scope-expiry teeth).
        now_fn: clock, injectable for tests.

    Returns a dict:
        {
          "results":     [AgentMessage, ...],      # attacker + validator envelopes
          "report":      "<markdown>",             # honest confirmed/unconfirmed
          "trace":       [ {iter, state_hash, action, differs_from_last,
                            repeat, dispatched}, ... ],
          "adaptation":  {"replans", "novel", "repeats", "score"},
          "termination": {"reason", "iterations"},
          "memory":      memory,
        }
    """
    await recon_fn(session, target, memory)

    results: list[AgentMessage] = []
    validated_findings: list[dict] = []
    failed_actions: list[dict] = []
    completed_actions: list[dict] = []
    trace: list[dict] = []

    last_key = None
    novel = 0
    repeats = 0
    stall = 0
    iterations = 0
    reason = "budget_exhausted"

    def _deadline_passed() -> bool:
        return deadline is not None and now_fn() >= deadline

    while True:
        # ── Termination teeth, checked BEFORE spending another action ──────────
        if _is_halted(engagement):
            reason = "halted"
            break
        if _deadline_passed():
            reason = "scope_expired"
            break
        if iterations >= max_iterations:
            reason = "budget_exhausted"
            break
        if stall >= stall_limit:
            reason = "stalled"
            break

        iterations += 1
        state_before = state_fingerprint(memory)

        # Deterministic pre-policy first: fire a curated PoC for a known-vulnerable
        # untried port with NO model call. Only when it declines (None) — the whole
        # unknown surface — do we spend a ~100s reasoning call on the model policy.
        action = prioritize_fn(memory) if prioritize_fn else None
        source = "known-exploit"
        if not action:
            action = policy_fn(goal, memory.summary(), completed_actions, failed_actions) or {}
            source = "model"
        kind = action.get("kind")
        log.info(f"[POLICY] iter {iterations}: [{source}] kind={kind}"
                 + (f" port={action.get('port')}" if kind == "attack" else "")
                 + (f" — {action.get('rationale', '')}" if action.get("rationale") else ""))

        if kind == "done":
            reason = "policy_done"
            trace.append({"iter": iterations, "state_hash": state_before,
                          "action": action, "differs_from_last": True,
                          "repeat": False, "dispatched": False})
            break

        key = _action_key(action)
        differs = key != last_key
        last_key = key

        # ── Repeat detector: never re-dispatch an attack already tried ─────────
        already_tried = kind == "attack" and action.get("port") in memory.tried_ports
        if already_tried:
            log.info(f"[POLICY] iter {iterations}: repeat — port {action.get('port')} "
                     f"already tried, skipping (stall {stall + 1}/{stall_limit})")
            repeats += 1
            stall += 1
            trace.append({"iter": iterations, "state_hash": state_before,
                          "action": action, "differs_from_last": differs,
                          "repeat": True, "dispatched": False})
            continue

        if differs:
            novel += 1

        # ── Dispatch the single action ─────────────────────────────────────────
        dispatched = True
        if kind == "attack":
            attack_msg = await _dispatch_attack(
                session, action, target, memory,
                execute_fn, model_fn, select_fn)
            attack_msg.engagement_id = engagement_id
            results.append(attack_msg)

            port = action["port"]
            success = attack_msg.status == TaskStatus.SUCCESS
            memory.mark_tried(port, success=success)
            record = {"port": port, "kind": "attack",
                      "rationale": action.get("rationale", ""),
                      "status": attack_msg.status.value}
            (completed_actions if success else failed_actions).append(record)

            validation_msg = run_validator(
                {"task_id": f"validate_{port}"}, engagement_id, target,
                attack_msg.result)
            results.append(validation_msg)
            validated_findings.append(validation_msg.result)

        elif kind == "recon":
            await recon_fn(session, target, memory)
            completed_actions.append({"kind": "recon",
                                      "rationale": action.get("rationale", "")})
        else:
            # Unknown action kind — record and let the stall guard retire it.
            dispatched = False
            failed_actions.append({"kind": kind, "reason": "unknown action kind"})

        trace.append({"iter": iterations, "state_hash": state_before,
                      "action": action, "differs_from_last": differs,
                      "repeat": False, "dispatched": dispatched})

        # ── Progress check: did the belief state actually change? ──────────────
        if state_fingerprint(memory) == state_before:
            stall += 1
        else:
            stall = 0

    report = generate_report(engagement_id, target, validated_findings)
    replans = novel + repeats
    adaptation = {
        "replans": replans,
        "novel": novel,
        "repeats": repeats,
        "score": (novel / replans) if replans else 0.0,
    }
    return {
        "results": results,
        "report": report,
        "trace": trace,
        "adaptation": adaptation,
        "termination": {"reason": reason, "iterations": iterations},
        "memory": memory,
    }
