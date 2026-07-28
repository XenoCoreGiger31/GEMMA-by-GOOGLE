# 07 — Self-Audit: HALO's Inward Eye (anti-obsolescence)

The inward half of #5. HALO turns its eyes on ITSELF on a schedule so it never
goes stale, broken, or behind the frontier. Sibling to the outward/offensive
attack-surface half (`04`). Code: `self_audit.py`.

---

## Why this exists
You run HALO on Kali. Kali ships **tool upgrades** constantly (not just new tools
— upgrades to nmap, sqlmap, nuclei, hydra…). Meanwhile Anthropic / DeepSeek /
OpenAI ship model + technique advances. Left alone, any agent rots: its tools
fall behind, an upgrade silently breaks one, and its architecture drifts toward
obsolete. This module is HALO refusing to rot.

Runs on a cadence (default ~30 days) once the MCP server is on.

## The four checks

| Check | Question | Detects |
|---|---|---|
| **Tool currency** | Are my Kali tools behind the latest? | "nuclei 3.1 installed, 3.3 available" |
| **Arsenal integrity** | Did an upgrade *break* one of the 29 tools? | "sqlmap fails its smoke test" — caught before an engagement |
| **Framework currency** | What has the frontier shipped that I haven't adopted? | a prioritized "modernize me" backlog (adaptive thinking, R1-distill decider, latest ATT&CK…) |
| **Self health** | Do my own modules still import / pass self-tests? | internal breakage |

Verdict rolls up to one of: **CURRENT** / **UPDATES_AVAILABLE** / **ATTENTION**
(something broken now).

## The deliberate safety line
- **Tools** may be **auto-updated**, under the autonomy policy (`auto` / `ask` /
  `never` — default `ask`). Updating a scanner is low-risk and reversible.
- **Architecture** is **never auto-changed.** Frontier-currency items are surfaced
  as a backlog for you to approve. HALO does **not** rewrite its own framework
  unsupervised — a security agent that silently re-architects itself is a
  liability. This boundary is enforced in code: `apply_tool_updates()` touches
  only tools; backlog items have no auto-apply path.

## How the "stay current with the frontier" part actually works (honest)
It is **semi-automated**, not magic self-evolution:
- When online, the `FrontierFeed` fetches changelogs / release notes (Anthropic,
  DeepSeek, OpenAI, MITRE ATT&CK).
- It diffs them against what HALO already uses and produces the backlog.
- You (the operator) decide what to adopt. HALO can then be *told* to implement an
  approved item — it doesn't do structural self-surgery on its own.

## Interfaces (all injected — testable offline)
- `PackageOracle` — installed vs latest tool versions (real impl: dpkg/apt/`--version`).
- `Prober` — per-tool smoke test (real impl: run `<tool> --version`, check exit).
- `FrontierFeed` — recent advances (real impl: changelog fetch; offline: static list).
- `HealthProbe` — HALO's own module health.

## Verified behavior (from the module demo)
```
verdict=ATTENTION  outdated=[nuclei]  missing=[hydra]  broken=[sqlmap]
modernize_backlog: adaptive thinking (high), R1-distill decider (high), ATT&CK (med)
applied tool updates: [nuclei, hydra]     # architecture items NOT auto-applied
```

## Deploy hook (later)
Scheduled via the harness (cron / a 30-day timer) once the MCP server runs.
Report goes to the operator; approved tool updates apply under policy; the
modernize backlog feeds your roadmap.
