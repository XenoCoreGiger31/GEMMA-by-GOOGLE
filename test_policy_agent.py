"""
test_policy_agent.py

The planner-as-policy — the brain the closed loop re-invokes each iteration.

Unlike planner_agent.plan() (one-shot goal decomposition into a frozen list), this
policy is called once per controller iteration with the FULL belief state plus the
list of what has already failed, and returns a SINGLE next action. These tests pin
that contract and its defenses: the failure history reaches the prompt (so the model
can stop repeating dead vectors), well-formed model JSON becomes an action, and
malformed model output degrades to a safe no-op rather than crashing the loop.

The model HTTP call is injected, so these run offline.
"""

import json

from policy_agent import build_policy


def _capture_model(response):
    """A fake model call that records the prompts it was handed and returns a
    canned response string."""
    calls = []

    def _call(system_prompt, user_prompt):
        calls.append({"system": system_prompt, "user": user_prompt})
        return response
    return _call, calls


STATE = {"open_ports": [21, 23], "tried": [21], "successes": [],
         "failures": [21], "findings": [], "flags": []}


def test_wellformed_model_json_becomes_an_action():
    model, _ = _capture_model(json.dumps(
        {"kind": "attack", "port": 23, "rationale": "telnet default creds"}))
    policy = build_policy(model)

    action = policy("own the host", STATE, [], [{"port": 21}])

    assert action["kind"] == "attack"
    assert action["port"] == 23
    assert action["rationale"]


def test_failure_history_is_included_in_the_prompt():
    model, calls = _capture_model(json.dumps({"kind": "done", "rationale": "x"}))
    policy = build_policy(model)

    policy("own the host", STATE, [],
           [{"port": 21, "rationale": "ftp backdoor", "status": "failed"}])

    prompt = calls[0]["user"]
    assert "21" in prompt                      # the failed port is shown to the model
    assert "ftp backdoor" in prompt            # ...along with what was tried


def test_state_is_included_in_the_prompt():
    model, calls = _capture_model(json.dumps({"kind": "done", "rationale": "x"}))
    policy = build_policy(model)

    policy("own the host", STATE, [], [])

    prompt = calls[0]["user"]
    assert "23" in prompt                      # untried open port is visible


def test_done_action_passes_through():
    model, _ = _capture_model(json.dumps({"kind": "done", "rationale": "goal met"}))
    policy = build_policy(model)
    action = policy("g", STATE, [], [])
    assert action["kind"] == "done"


def test_malformed_model_output_degrades_to_noop():
    model, _ = _capture_model("I think you should probably try port 23 next!")
    policy = build_policy(model)

    action = policy("g", STATE, [], [])

    # A parse failure must NOT crash the loop and must NOT fabricate a breach or a
    # 'done'. It yields a no-op the controller's stall guard can retire.
    assert action["kind"] == "noop"
    assert "unparseable" in action["rationale"].lower()


def test_model_call_exception_degrades_to_noop():
    # A model timeout / connection drop must NOT crash the loop — the policy is
    # called inside a long async engagement, so one failed call has to degrade to a
    # no-op the stall guard retires, exactly like an unparseable reply does.
    # (Live 2026-08-17: an uncaught ReadTimeout here killed a 40-minute run.)
    def boom(system_prompt, user_prompt):
        raise ConnectionError("Read timed out. (read timeout=90)")

    policy = build_policy(boom)
    action = policy("g", STATE, [], [])

    assert action["kind"] == "noop"
    assert "model call failed" in action["rationale"].lower()


def test_json_wrapped_in_prose_is_still_parsed():
    # 12B models routinely wrap JSON in chatter/fences; the policy should recover it.
    raw = 'Sure! Here is the next step:\n```json\n{"kind": "attack", "port": 23, "rationale": "telnet"}\n```\nHope that helps.'
    model, _ = _capture_model(raw)
    policy = build_policy(model)

    action = policy("g", STATE, [], [])
    assert action["kind"] == "attack"
    assert action["port"] == 23
