# Phase 2 — Rebuild the Validator on `breach_confirmed`

**Date:** 2026-07-23
**Status:** design, approved
**Parent:** multi-agent-integration (Phase 2 of 6). Phase 1 (exploitation_core extraction) done + deployed.

## Problem

`validator_agent.validate_finding` decides whether an Attacker finding is real using
per-tool string heuristics — e.g. `run_hydra` → `"login:" in output` → "confirmed,
high confidence". This is the **same false-positive class** that produced HALO's fake
"23/23 breached": a substring match is not evidence. Phase 1 already put the honest,
evidence-based check (`breach_confirmed`) in `exploitation_core.py`; the validator
must use it.

Two concrete defects today:
1. **String heuristics confirm non-breaches** (hydra's `"0 valid password found"`
   contains `"login:"`-adjacent text; searchsploit's `"Shellcodes:"` footer, etc.).
2. **Field mismatch:** Attacker writes its output under `result["attempts"]`
   (`attacker_agent.py:65`), but `validate_finding` reads `result["findings"]` — so
   for real Attacker results it reads an empty string and confirms *nothing*.

## Solution

Rewrite `validate_finding(attacker_result, target)` to delegate to
`breach_confirmed(tool, output, ok)` from `exploitation_core`:

- `tool`   = `attacker_result.get("tool_used", "")`
- `output` = `attacker_result.get("attempts")` or `.get("output")` or
  `.get("findings")` or `""` (reads the field the Attacker actually writes today,
  with forward-compatible fallbacks for the Phase-3 attacker rebuild)
- `ok`     = `attacker_result.get("ok", True)` — the Orchestrator only invokes the
  validator on `status == SUCCESS` (`orchestrator_agent.py:64`), so `ok` defaults
  True today; Phase 3 will thread the real value. `breach_confirmed` ignores `ok`
  for the recon/credential classes anyway, so the default is safe.

Confirmation becomes binary (evidence or not), so:
- `confirmed`  = the `breach_confirmed` boolean
- `confidence` = `"high"` when confirmed else `"low"` (honest: `breach_confirmed`
  only returns True on real code-exec / shell / recovered-credential evidence)
- `evidence`   = a fixed honest string for each branch
- `raw_findings` = `output[:500]` (unchanged key, so `generate_report` still works)

## Scope

- **Modify only `validator_agent.py`.** `run_validator(task, engagement_id, target,
  attacker_result) -> AgentMessage` and `generate_report(engagement_id, target,
  validated_findings) -> str` keep their exact signatures — drop-in for
  `orchestrator_agent.py:16,66,71`.
- Add `from exploitation_core import breach_confirmed`.
- **No changes** to `orchestrator_agent.py`, `attacker_agent.py`, or `agent_schema.py`.

## Contract / compatibility

- `run_validator` still returns an `AgentMessage` with `status = SUCCESS` when
  confirmed else `FAILED`, `result` = the validate_finding dict. Unchanged for the
  orchestrator.
- `validate_finding`'s return dict keeps keys `tool_used, confirmed, confidence,
  evidence, raw_findings` (the keys `generate_report` reads).
- No import cycle: `validator_agent` → `exploitation_core` → `{engagement,
  poc_library, msf_selector}`; none import `validator_agent`.

## Testing / acceptance

New `test_validator_agent.py` (the first test coverage this file has ever had):

1. hydra output with a real credential line (`[21][ftp] host: X login: y password: z`)
   → `confirmed is True`.
2. hydra `"[STATUS] 0 valid password found"` → `confirmed is False` (the killed
   false positive).
3. searchsploit output containing the `"Shellcodes: 0"` footer → `confirmed is False`.
4. output containing `uid=0(root)` under the `"attempts"` key → `confirmed is True`
   (also the field-mismatch regression: proves `"attempts"` is read).
5. `run_validator(...)` on a confirmed result → `AgentMessage.status == SUCCESS`;
   on an unconfirmed result → `FAILED`.
6. `generate_report` with one confirmed + one unconfirmed finding renders both
   sections and does not raise.

Primary gate: full suite stays green (`python3 -m pytest -q`; baseline **200 passed**)
plus the new validator tests.

## Out of scope (Phase 3)

- Rebuilding `attacker_agent` on `plan_exploit_step`.
- Routing exploit execution through the gated spine (the `mcp_client` path bypasses
  the operator gate — the attacker must NOT fire exploits through it).
- Threading the real `ok`/status from Attacker → Validator via the Orchestrator.
