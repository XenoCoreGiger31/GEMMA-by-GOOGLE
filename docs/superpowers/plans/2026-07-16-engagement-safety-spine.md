# Engagement Safety Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `engagement.py`'s authorization/scope/kill-switch/custody gate the single choke point every `agent_loop.py` tool call passes through, so HALO physically cannot run a tool against an unauthorized or out-of-scope target.

**Architecture:** `engagement.py` moves from `halo-nextgen/src/` (disconnected staging area) to the repo root (alongside `agent_loop.py`, `halo_config.py`, etc. — the same place every other wired-in module lives) and gains a YAML config loader and a tool→action-class classifier. `agent_loop.py`'s single tool-dispatch chokepoint, `execute_step()`, gates every call through `Engagement.authorize()` before it runs.

**Tech Stack:** Python 3, stdlib + PyYAML (already a runtime dependency in `requirements.txt`), `unittest` for tests (matches the repo's existing `test_report_generator.py` convention — no pytest, no new test framework).

## Global Constraints

- No new third-party dependencies — PyYAML is already required (`requirements.txt`); `engagement.py` itself stays pure stdlib otherwise.
- No bypass flag or environment variable for the authorization gate. Missing/invalid `engagement.yaml` is fatal at startup, by design (source: `docs/superpowers/specs/2026-07-16-engagement-safety-spine-design.md`, Goals section).
- `engagement.yaml` (the real, per-deployment file with actual scope targets) is never committed — only `engagement.example.yaml` is tracked.
- Don't modify `_run_exploit_gated`'s internals — the new gate wraps it, it doesn't replace any part of it (spec's self-review correction).
- Don't touch `halo-nextgen/src/agent_loop_ng.py`, `orchestrator_agent.py`, or any Phase 2–5 surface — out of scope for this plan (spec's Non-goals section).

Note: this plan's exact code snippets predate one in-flight correction made during implementation — the `engage <target>` scope check (Task 3, Step 8) ended up routed through `ENGAGEMENT.authorize("halo", "recon", target, detail="engagement start")` rather than a bare `ENGAGEMENT.scope.in_scope(target)` call, so that refusal is chain-of-custody logged like every other gate decision. See the actual `agent_loop.py` source for the shipped version.

---

### Task 1: Graduate `engagement.py` to the repo root with a config loader and classifier

**Files:**
- Move: `halo-nextgen/src/engagement.py` → `engagement.py` (repo root)
- Create: `test_engagement.py`

**Interfaces:**
- Produces: `engagement.load_engagement_context(path: str = "engagement.yaml") -> EngagementContext` (raises `AuthorizationError` if the file is missing or fails `EngagementContext` validation)
- Produces: `engagement.classify(tool: str) -> str` (returns one of `"recon"`, `"active_scan"`, `"credential_attack"`, `"exploitation"`, `"destructive"`; unknown tools default to `"exploitation"`)
- Everything already in `engagement.py` today (`Engagement`, `EngagementContext`, `AuthorizationError`, `ScopeGuard`, `KillSwitch`, `CustodyLog`, `build_engagement_system_prompt`) is unchanged and still exported from the same module, just at a new path.

See the shipped `test_engagement.py` and `engagement.py` in the repo root for the exact, verified implementation (7 tests, all passing).

### Task 2: Ship the engagement config template

**Files:**
- Create: `engagement.example.yaml`
- Modify: `.gitignore` (added `engagement.yaml`)

See the shipped `engagement.example.yaml` and `.gitignore` in the repo root.

### Task 3: Wire the authorization gate into agent_loop.py

**Files:**
- Modify: `agent_loop.py`
- Create: `test_agent_loop_gating.py`

**Interfaces:**
- Consumes: `engagement.Engagement`, `engagement.EngagementContext`, `engagement.AuthorizationError`, `engagement.load_engagement_context`, `engagement.build_engagement_system_prompt`, `engagement.classify`
- Produces: module-level `agent_loop.ENGAGEMENT` (an `Engagement` instance or `None`), read by `execute_step()`

See the shipped `agent_loop.py` and `test_agent_loop_gating.py` in the repo root for the exact, verified implementation (7 tests, all passing, plus the full existing suite with no regressions). Manually smoke-tested: refuses to start with no `engagement.yaml`; starts and gates correctly with one present; out-of-scope `engage` refused and custody-logged; `killswitch` blocks all further action including in-scope targets, also custody-logged.

### Task 4: Document the integration in halo-nextgen's README

**Files:**
- Modify: `halo-nextgen/README.md`

See the shipped `halo-nextgen/README.md` — component table row updated, Integration points list item 5 added marking this phase done.

### Task 5: Push to main

Pushed directly to `main` via the `github` MCP plugin (authenticated as the repo owner), per explicit operator direction — no local git credentials are available in this environment, so a bare `git push` was not an option.
