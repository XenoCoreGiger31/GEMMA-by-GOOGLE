# Engagement Safety Spine — Integration Design

## Context

`halo-nextgen/src/engagement.py` implements four guarantees — authorization,
scope guard, kill switch, chain of custody — as designed in
`halo-nextgen/09_ENGAGEMENT_SAFETY.md`. The module is complete and
self-tested (`python3 halo-nextgen/src/engagement.py` passes today), but
nothing in the running harness calls it. `agent_loop.py` executes tool steps
through `execute_step()` (agent_loop.py:305) with no authorization or scope
check beyond the ad hoc two-gate `input()` flow that `run_exploit` alone goes
through (`_run_exploit_gated`, agent_loop.py:252). Every other tool — recon,
active scan, credential attack — runs unauthorized and unscoped today.

This is Phase 1 of a five-phase plan to bring the `halo-nextgen` package into
the live harness (loop swap, TTP-chain orchestrator specialist, ASM tools,
and self-audit/debug-mode/reporting are Phases 2–5, each its own design
cycle). Phase 1 is the foundation: it is the single gate every later phase's
tool execution should also pass through.

## Goals

- Every tool call `agent_loop.py` makes — not just `run_exploit` — passes
  through one authorization gate before it runs.
- HALO physically cannot start an engagement without a written-authorization
  reference and a non-empty target scope.
- Out-of-scope targets are refused before any recon or attack runs against
  them, not discovered mid-engagement.
- A kill switch halts all further authorized action for the rest of the
  session.
- Every authorize/deny decision is logged to a chain-of-custody record
  exportable for client review.

## Non-goals

- Replacing or restructuring `agent_loop.py`'s model-driving loop
  (`agent_loop_ng.py` swap-in) — that is Phase 2.
- Wiring `engagement.py` into `orchestrator_agent.py`'s pipeline — the
  orchestrator pipeline is a separate runtime from `agent_loop.py` and gets
  its own gating decision alongside the Phase 3 TTP-chain specialist work.
- A UI or web form for engagement setup — config is a local file only.
- Multi-engagement or multi-tenant support — one `engagement.yaml`, one
  engagement in flight, matching how `agent_loop.py` runs today (single REPL
  process, single target at a time via `engage <target>`).

## Architecture

`execute_step()` is the only place a tool step actually executes today
(agent_loop.py:305) — it dispatches `run_exploit` through the two-gate flow
and everything else straight to the MCP tool server. `Engagement.authorize()`
becomes a call inside `execute_step()`, before dispatch, for every tool —
so the existing two-gate exploit approval and every other tool call share one
authorization mechanism instead of two.

The tool→`ActionClass` classification table currently lives only in
`halo-nextgen/src/agent_loop_ng.py` (`_TOOL_CLASS`, `ActionClass`,
`DEFAULT_POLICY`). It moves to `engagement.py` (or a small new
`autonomy_policy.py` imported by both) since Phase 1 and the Phase 2 loop
swap both need the same tool classification and neither should own it.

## Components

### 1. `engagement.yaml` (new)

Repo ships `engagement.example.yaml` (committed, placeholder values) and
adds `engagement.yaml` to `.gitignore` — the real file is local-only,
per-deployment, never committed (it names real authorized targets).

Fields, matching `EngagementContext`:

```yaml
role: "Senior Security Researcher"
task: "Authorized penetration testing for defensive hardening"
authorization: "Written CISO approval #2026-07-13"
purpose: "Identify vulnerabilities so the client can patch them"
scope_targets:
  - "10.0.0.0/24"
  - "app.client.example"
operator: "chris"
```

### 2. Config loader (new, `engagement_config.py` or a function in
`halo_config.py`)

Reads `engagement.yaml`, constructs `EngagementContext`. Missing file or a
field that fails `EngagementContext.__post_init__`'s validation
(`AuthorizationError`) propagates up — `agent_loop.py` catches it at
startup, prints the required fields, and exits. No flag or env var
bypasses this.

### 3. Shared tool classification (moved into `engagement.py`)

`ActionClass` enum and the tool→class table (`_TOOL_CLASS` in
`agent_loop_ng.py` today) move here. `agent_loop_ng.py` imports them from
their new home in Phase 2; Phase 1 only needs them to build the `autonomy`
dict passed to `Engagement()`.

### 4. `agent_loop.py` changes

- **Startup**: load `engagement.yaml` → `EngagementContext` → construct
  `Engagement(ctx, autonomy=..., approver=<REPL input() prompt>)`. Failure
  here is fatal (matches "physically cannot start" goal).
- **System prompt**: `build_engagement_system_prompt(ctx)` replaces the
  current static system prompt built elsewhere in `agent_loop.py`.
- **`execute_step(step)` (line 305)**: before dispatch, call
  `eng.authorize("halo", classify(tool), step.get("target"))`. `False` →
  log the existing-style `[GATE]` denial line and return a
  `{"status": "blocked", ...}` result without calling the tool. This is a
  new outer gate for every tool, `run_exploit` included — `_run_exploit_gated`
  itself is untouched, so a `run_exploit` step that clears `authorize()`
  still goes through its existing, unmodified entry gate and fire gate
  before anything runs. Three checks total for `run_exploit`: the new shared
  `authorize()`, then entry, then fire — lower risk than editing the
  existing two-gate function.
- **New REPL command** `killswitch` → `eng.kill.halt("operator")`. Every
  subsequent `execute_step` call denies for the rest of the process.
- **On exit** (normal return from `main()` or `KeyboardInterrupt`): write
  `eng.custody.export()` to `<HALO_LOG_DIR>/<engagement_id>_custody.json`.

### 5. Scope check on `engage <target>`

Before `run_full_engagement(target)` (agent_loop.py:390) starts recon, check
`eng.scope.in_scope(target)` directly and refuse with a clear message if the
target isn't in `scope_targets` — don't wait for the first `execute_step`
call to discover it mid-recon.

## Data flow

```
REPL start
  → load engagement.yaml → EngagementContext (raises + exits if invalid)
  → Engagement(ctx, autonomy, approver)
  → system prompt = build_engagement_system_prompt(ctx)

user: engage <target>
  → eng.scope.in_scope(target)?  no → refuse, custody-logged, no recon runs
  → yes → run_full_engagement(target)
       → each execute_step(step)
            → eng.authorize("halo", classify(step["tool"]), step["target"])
            → False → [GATE] denial, no tool call
            → True  → existing dispatch (MCP call, or run_exploit's
                       unmodified entry-gate + fire-gate flow)

user: killswitch  → eng.kill.halt() → all further authorize() calls False

REPL exit (normal or Ctrl-C)
  → eng.custody.export() written to <HALO_LOG_DIR>/<engagement_id>_custody.json
```

## Error handling

- Missing/malformed `engagement.yaml`, or a field that fails
  `EngagementContext` validation → fatal at startup, message states which
  field is missing (reuses `AuthorizationError`'s existing message text).
- Target not in scope at `engage <target>` time → refused, custody-logged,
  REPL stays up (operator can `engage` a different, in-scope target).
- `authorize()` returning `False` inside `execute_step` → step result is
  `{"status": "blocked", "reason": ...}`, same shape the rest of
  `agent_loop.py` already expects from a failed step (no new error type
  needed downstream).
- Kill switch engaged → same `{"status": "blocked"}` path, reason
  `"kill switch engaged"`.

## Testing

- `engagement.py`'s own `__main__` self-test already covers: refuse
  unauthorized construction, refuse out-of-scope, refuse destructive
  (never-policy), refuse after kill switch, custody log export. No changes
  needed there.
- New: a fixture `engagement.yaml` (or env-var-pointed path) for test runs,
  since the mandatory-config requirement would otherwise break any
  automated test that imports `agent_loop.py`.
- New: unit coverage for `execute_step()` — currently `agent_loop.py` has no
  test file at all (`test_report_generator.py` is the only test in the
  repo). Add tests asserting a step is not dispatched to the tool layer when
  `authorize()` returns `False`, and that `run_exploit`'s existing two-gate
  flow still runs (fire gate) once the shared entry gate (`authorize()`)
  passes.
- Manual check: run `agent_loop.py` with no `engagement.yaml` present →
  confirm it refuses to start rather than silently proceeding unscoped.

## Open questions for later phases (not blocking Phase 1)

- Whether `orchestrator_agent.py`'s pipeline gets its own `Engagement`
  instance or shares state with `agent_loop.py`'s — deferred to Phase 3
  alongside the TTP-chain specialist design, since the two runtimes don't
  currently share process state.
- Where `build_engagement_system_prompt` output interacts with
  `skills.py`-selected prompt content — deferred to Phase 2 (loop swap).
