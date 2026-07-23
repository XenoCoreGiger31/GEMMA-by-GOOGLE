# Validator Honest-Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Replace `validator_agent.validate_finding`'s per-tool string heuristics with the honest, evidence-based `breach_confirmed` from `exploitation_core`, and fix the `"attempts"`-vs-`"findings"` field mismatch — killing the false-positive class in the multi-agent validator.

**Architecture:** Single-file change to `validator_agent.py`. `run_validator` and `generate_report` keep their exact signatures (drop-in for the orchestrator). First-ever tests for this module are added.

**Tech Stack:** Python 3, pytest.

## Global Constraints

- Modify ONLY `validator_agent.py`. Do NOT touch `orchestrator_agent.py`, `attacker_agent.py`, or `agent_schema.py`.
- `run_validator(task, engagement_id, target, attacker_result) -> AgentMessage` and `generate_report(engagement_id, target, validated_findings) -> str` keep exact signatures and behaviour (SUCCESS when confirmed else FAILED; report renders confirmed + unconfirmed sections).
- `validate_finding`'s return dict must keep keys: `tool_used, confirmed, confidence, evidence, raw_findings`.
- Full suite must stay green: `python3 -m pytest -q`, baseline **200 passed**.
- This is not a git repo — skip commits.
- Confirm `test_validator_agent.py` does not already exist before creating it.

---

### Task 1: Rebuild `validate_finding` on `breach_confirmed`

**Files:**
- Create: `test_validator_agent.py`
- Modify: `validator_agent.py` (add one import; replace the `validate_finding` body)

**Interfaces:**
- Consumes: `exploitation_core.breach_confirmed(tool: str, output: str, ok: bool) -> bool`; `agent_schema.TaskStatus`.
- Produces (unchanged public surface): `validate_finding(attacker_result, target) -> dict`, `run_validator(...) -> AgentMessage`, `generate_report(...) -> str`.

- [ ] **Step 1: Write the failing tests**

Create `test_validator_agent.py`:

```python
"""Tests for validator_agent — honest, evidence-based finding confirmation.

Phase 2 of the multi-agent integration: the validator now delegates to
exploitation_core.breach_confirmed instead of per-tool string heuristics. First tests
this module has had. They pin that real breach evidence confirms, that the historical
false positives (hydra-zero, searchsploit "Shellcodes:") do NOT, and that the
Attacker's real output field ("attempts") is the one read.
"""
from agent_schema import TaskStatus
from validator_agent import validate_finding, run_validator, generate_report


def _attacker_result(tool, output):
    return {"tool_used": tool, "attempts": output}


def test_real_credential_hit_confirmed():
    out = "[21][ftp] host: 203.0.113.3   login: msfadmin   password: msfadmin"
    v = validate_finding(_attacker_result("run_hydra", out), "203.0.113.3")
    assert v["confirmed"] is True


def test_hydra_zero_is_not_confirmed():
    out = "[STATUS] attack finished ... 0 valid password found"
    v = validate_finding(_attacker_result("run_hydra", out), "203.0.113.3")
    assert v["confirmed"] is False


def test_searchsploit_shellcodes_footer_not_confirmed():
    out = "Exploits: 3\nShellcodes: 0\n"
    v = validate_finding(_attacker_result("run_searchsploit", out), "203.0.113.3")
    assert v["confirmed"] is False


def test_real_root_shell_under_attempts_field_confirmed():
    # Field-mismatch regression: output lives under "attempts", not "findings".
    out = "uid=0(root) gid=0(root) groups=0(root)"
    v = validate_finding(_attacker_result("run_exploit", out), "203.0.113.3")
    assert v["confirmed"] is True


def test_run_validator_status_maps_to_confirmation():
    task = {"task_id": "task_005"}
    confirmed = run_validator(task, "eng1", "203.0.113.3",
                              _attacker_result("run_exploit", "uid=0(root)"))
    assert confirmed.status == TaskStatus.SUCCESS
    unconfirmed = run_validator(task, "eng1", "203.0.113.3",
                                _attacker_result("run_searchsploit", "Shellcodes: 0"))
    assert unconfirmed.status == TaskStatus.FAILED


def test_generate_report_renders_both_sections():
    findings = [
        {"tool_used": "run_exploit", "confirmed": True, "confidence": "high",
         "evidence": "shell", "raw_findings": "uid=0(root)"},
        {"tool_used": "run_nuclei", "confirmed": False, "confidence": "low",
         "evidence": "none", "raw_findings": "info"},
    ]
    report = generate_report("eng1", "203.0.113.3", findings)
    assert "Confirmed Findings" in report
    assert "Manual Review" in report
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest test_validator_agent.py -q`
Expected: FAIL — the current `validate_finding` reads `"findings"` (not `"attempts"`) and uses string heuristics, so `test_real_credential_hit_confirmed`, `test_real_root_shell_under_attempts_field_confirmed`, and `test_run_validator_status_maps_to_confirmation` fail.

- [ ] **Step 3: Add the import**

In `validator_agent.py`, below the existing `from agent_schema import ...` line, add:

```python
from exploitation_core import breach_confirmed
```

- [ ] **Step 4: Replace the `validate_finding` body**

Replace the entire existing `def validate_finding(attacker_result: dict, target: str) -> dict:` function (its whole body, through the `return {...}`) with exactly:

```python
def validate_finding(attacker_result: dict, target: str) -> dict:
    """Confirm an Attacker finding using the honest, evidence-based breach check.

    Delegates to exploitation_core.breach_confirmed rather than per-tool substring
    heuristics (the old approach confirmed non-breaches — hydra's "0 valid password
    found", searchsploit's "Shellcodes:" footer — the same false-positive class that
    produced HALO's fake 23/23). Reads the Attacker's real output field ("attempts"),
    with forward-compatible fallbacks for the Phase-3 attacker rebuild.
    """
    tool = attacker_result.get("tool_used", "")
    output = (attacker_result.get("attempts")
              or attacker_result.get("output")
              or attacker_result.get("findings")
              or "")
    ok = attacker_result.get("ok", True)

    confirmed = breach_confirmed(tool, output, ok)

    return {
        "tool_used": tool,
        "confirmed": confirmed,
        "confidence": "high" if confirmed else "low",
        "evidence": ("breach evidence confirmed (code execution, shell, or recovered "
                     "credential)" if confirmed
                     else "no breach evidence — finding needs manual review"),
        "raw_findings": (output or "")[:500],
    }
```

Leave `run_validator` and `generate_report` untouched.

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `python3 -m pytest test_validator_agent.py -q`
Expected: PASS (6 passed).

- [ ] **Step 6: Run the full suite**

Run: `python3 -m pytest -q`
Expected: `206 passed` (200 baseline + 6 new), zero failures. If any prior test fails, something outside scope was touched — revert and fix.

---

## Self-Review

**1. Spec coverage:** breach_confirmed delegation (Step 4), field-mismatch fix via `"attempts"` (Step 4 + test 4), signatures unchanged (Steps 3–4 leave run_validator/generate_report), import (Step 3), tests for all 6 spec cases (Step 1), full-suite gate (Step 6). ✓
**2. Placeholder scan:** No TBD/TODO; complete code in every code step. ✓
**3. Type consistency:** `validate_finding` returns the 5 keys `generate_report` consumes; `run_validator` reads `validation["confirmed"]` which is always present; test helper `_attacker_result` matches the Attacker's real `{tool_used, attempts}` shape. ✓
