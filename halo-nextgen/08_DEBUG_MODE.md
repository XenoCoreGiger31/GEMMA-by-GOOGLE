# 08 — Debug Mode: separate, bridged, sandboxed

The debugging capability you flagged. Built to the design we agreed:
**separate + bridged + sandboxed.** Code: `src/debug_mode.py`. **Staged, not shipped.**

---

## Why this shape (the reasoning you asked for)
A debugger's whole job is to **freely write and run code**. The security loop's
whole job is to **gate everything**. Those two instincts are opposites, so the
safe design keeps them apart while still letting the security side borrow the
debugger when it needs one:

- **SEPARATE (primary).** Debug Mode is a standalone mode behind an explicit
  toggle, **off by default**. It has its own state — it does not run inside the
  attack loop, share its autonomy gating, or touch the negative cache. Flip it on
  when you want HALO to fix code; flip it off and it's inert.
- **BRIDGED.** The security engagement can still *call* the debugger for its own
  failures — repair a failed exploit PoC, diagnose a broken tool run (the job the
  repo's existing `debugger_agent.py` already does, upgraded) — **without**
  flipping the whole system into debug mode. One method: `repair_poc()`.
- **SANDBOXED.** Writing-and-running code is the same risk class as `run_exploit`.
  Every execution goes through a sandbox (the repo's `sandbox/` Docker runner in
  deployment). **No sandbox → it refuses to run.** Enforced in code.

## The debug loop
`run → read error → propose fix → apply → re-run`, up to N attempts, every run
sandboxed. Returns a full trace (each attempt, pass/fail, whether the code
changed) so you can see exactly what it did — no black box.

## Two entry points
| Method | Who uses it | Requires toggle? | Gated? | Sandboxed? |
|---|---|---|---|---|
| `debug(code)` | you, deliberately | **yes** (`enable()`) | — | yes |
| `repair_poc(code)` | the security loop, mid-engagement | no | yes (approver) | yes |

## Verified behavior (from the module demo)
```
off      -> refused: "debug mode is off — enable() first"
on       -> attempt 1 FAIL (ZeroDivisionError) -> attempt 2 PASS (fixed)
bridge   -> repaired a failed PoC without enabling debug mode
no-sandbox -> refused: code exec is gated behind the sandbox by design
```

## What makes it "scary-good" and still safe
- Isolated by default → it can't be co-opted by a live engagement or an injection.
- Sandboxed always → arbitrary code never runs on the host unguarded.
- Bridged → the engagement gets a real debugger exactly when a PoC or tool breaks,
  which is a big part of why HALO would *work perfectly* in the field.
- Full trace → auditable, not a mystery.

## Interfaces (injected — testable offline)
- `Sandbox.run(code) -> {ok, stdout, stderr}` (real impl: `sandbox/run_sandbox.py`).
- `FixModel.propose_fix(code, stderr) -> code` (isolated; code is data, not orders).
- `approver(reason) -> bool` (autonomy gate for any code execution).

## Deploy hook (later)
Expose the toggle in the operator UI/REPL; wire `Sandbox` to the Docker runner;
wire `repair_poc()` into the engagement loop's failure paths (where
`debugger_agent.py` sits today).
