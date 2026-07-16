# HALO Next-Gen — Harness Upgrade

> **What this is.** A self-contained design + code package that upgrades the
> HALO harness: faster and more goal-directed, with better memory, hardened
> against prompt injection, and continuously aware of its own attack surface.
> Each component is defined against a design doc in this directory and composes
> into the next-gen agent loop (`src/agent_loop_ng.py`).

This package addresses the four prompts from "10 Prompts That Benefit from the
Smartest Models" and the follow-on requirements, toward one goal: make HALO
**faster, stronger, with better memory**, harder to hijack, and continuously
aware of its own attack surface — using current reasoning/model technology.

## What's here

| File | Screen / ask it satisfies | Type |
|------|---------------------------|------|
| [`01_HARNESS_OPTIMIZATION.md`](01_HARNESS_OPTIMIZATION.md) | Goal Orientation + Bitter Lesson (Screen 1/4) | Analysis + redesign |
| [`02_PROMPT_INJECTION.md`](02_PROMPT_INJECTION.md) | Prompt Injection Handling (Screen 2) — defense **and** as a test methodology | Threat model + defense design |
| [`03_LLM_DEEP_DIVE.md`](03_LLM_DEEP_DIVE.md) | "Deep dive on every LLM ever built" — architectures + harness structures, incl. Claude Code's own | Reference |
| [`04_attacksurface.md`](04_attacksurface.md) | #5 **outward** — Attack-Surface Management HALO runs on authorized targets | Methodology + record |
| [`05_TTP_CHAIN_VALIDATION.md`](05_TTP_CHAIN_VALIDATION.md) | TTP-chain validation on MITRE ATT&CK — prove exploitability without launching | Decision memo + design |
| [`06_JSPACE_INTROSPECTION.md`](06_JSPACE_INTROSPECTION.md) | Introspective/internal-state audit inspired by the "J-Space" article — detect when the model privately flags manipulation while outwardly compliant | Design + caveat |
| [`07_SELF_AUDIT.md`](07_SELF_AUDIT.md) | #5 **inward** — HALO self-audits (tool currency, arsenal integrity, framework currency) so it never goes stale/broken | Design |
| [`08_DEBUG_MODE.md`](08_DEBUG_MODE.md) | Isolated + bridged + sandboxed debugger (the "clickable debug mode") | Design |
| [`09_ENGAGEMENT_SAFETY.md`](09_ENGAGEMENT_SAFETY.md) | Safety spine (authorization + scope guard + kill switch + chain of custody) and field-grade reporting | Design |
| `src/agent_loop_ng.py` | **Next-gen agent loop** — composes everything below into one loop, better than `agent_loop.py` on every axis in `01` | Code (stdlib) |
| `src/tiered_memory.py` | **Phase 1+2:** persistent `CaseFile` (session log, read/write) + tiered bi-directional memory (negative/positive/environmental) | Code (stdlib) |
| `src/prompt_injection_guard.py` | Trust-tiered prompt-injection filter at the input boundary | Code (stdlib) |
| `src/continuous_scanner.py` | Continuous vuln/open-port/attack-surface scanner | Code (stdlib) |
| `src/asm_inventory.py` | Reads/writes `attacksurface.md` as structured data | Code (stdlib) |
| `src/ttp_chain.py` | TTP-chain decomposition + validate→decide→fix→re-validate loop | Code (stdlib) |
| `src/introspection_audit.py` | Internal-state / self-signal audit (J-Space-inspired); black-box + optional white-box J-lens approximation | Code (stdlib) |
| `src/self_audit.py` | #5 inward — self-audit engine (tool currency, arsenal integrity, framework backlog, anti-obsolescence) | Code (stdlib) |
| `src/debug_mode.py` | Isolated + bridged + sandboxed debug loop (toggle-gated) | Code (stdlib) |
| [`../engagement.py`](../engagement.py) | **Graduated — wired into `agent_loop.py`.** Safety spine: authorization gate, scope guard, kill switch, chain of custody, engagement prompt | Code (stdlib) |
| `src/security_report.py` | Steps 1–4: web-vuln knowledge base (safe examples + patches) + audit-ready report builder | Code (stdlib) |

### The composed loop (`agent_loop_ng.py`)

`agent_loop_ng.py` is the next-gen successor to the current `agent_loop.py`. It
folds the whole package into one loop and is better on every axis in `01`:

| | `agent_loop.py` (current) | `agent_loop_ng.py` (next-gen) |
|---|---|---|
| Goal framing | static tool-manual prompt | goal-first prompt (decide, don't just run) |
| Success detection | substring grep (`"found"`) | evidence-based validator hook |
| Memory | negative-only; **deletes** successes | tiered: negative + **positive** + environmental |
| Engagement state | re-derived every call | persistent `CaseFile` (read/write) |
| Prompt injection | tool output re-enters raw | trust-tier guard on every output |
| Autonomy / gating | `run_exploit` only, all-or-nothing | per-action-class policy |
| Exploitability | implicit | TTP-chain validation (decide) |

Every collaborator (model client, tool executor, control oracle, approver) is
**injected**, so it runs and is testable offline — `python3 src/agent_loop_ng.py`
exercises the entire loop with stubs, including a live prompt-injection attempt in
tool output (caught + quarantined) and an evidence-backed finding.

## The one goal everything serves

**HALO's characterized goal:** *a fully-local, autonomous offensive-security
operator that decides which exposures are genuinely exploitable in a given
environment, proves it with evidence, and never re-learns the same dead end.*

Everything below is measured against that sentence. The redesign pushes HALO from
a **tool-runner** ("run nmap, run sqlmap") toward a **decision engine** ("is this
exploitable here, with evidence, within the guardrails I was given") — which is
exactly what the TTP-chain / continuous-validation material formalizes.

## Integration points

The wiring points into the running harness are:
1. `prompt_injection_guard.py` → call at every **input boundary** enumerated in `02`.
2. `continuous_scanner.py` + `asm_inventory.py` → run on a schedule; write findings to `attacksurface.md`.
3. `ttp_chain.py` → new specialist alongside `validator_agent.py`, gated by the tunable-autonomy policy.
4. New tools register in `halo_tools.py`'s `TOOLS` registry so both transports expose them.
5. `engagement.py` (graduated to repo root) — **done.** `agent_loop.py`'s
   `execute_step()` calls `Engagement.authorize()` before every tool
   dispatch; `engage <target>` checks scope before recon starts. See
   `docs/superpowers/specs/2026-07-16-engagement-safety-spine-design.md`.

Each component integrates independently; none require the others.

---
*Not affiliated with Google LLC. For authorized security testing on systems you
own or have written permission to test.*
