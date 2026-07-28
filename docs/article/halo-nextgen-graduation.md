# From Tool-Runner to Decision Engine: Upgrading an Autonomous Security Agent's Harness

#agents
#ai
#cybersecurity
#pentesting

Yesterday I did something that sounds like paperwork and is actually the whole point: I *graduated* a batch of next-gen modules out of a staging package and into the running harness of HALO, the local, autonomous offensive-security agent I've been building. "Graduated" is the operative word. These weren't new files landing in a repo — they were designs that had earned their way from a shelved `halo-nextgen/` package into the live agent loop, each one wired to the parts of the system it was always meant to touch.

The interesting part isn't the diff. It's what the batch was *for*. Taken together, these upgrades push HALO across a line I've been circling for months: from a **tool-runner** to a **decision engine**.

## The reframe

A tool-runner is what most "AI hacking" demos actually are. You give it a target, it runs nmap, it runs sqlmap, it greps the output for the word "found," and it reports back. It's a shell with a language model taped to the front. It doesn't know whether the thing it found is exploitable *here*, in *this* environment, and it cheerfully forgets everything the moment the session ends.

The characterized goal for HALO is the opposite of that: a fully-local operator that decides which exposures are genuinely exploitable in a given environment, proves it with evidence, and never re-learns the same dead end. Every module in yesterday's batch is measured against that one sentence. Here's the before/after that the redesign is chasing:

| | Old loop | Next-gen loop |
|---|---|---|
| Goal framing | static tool-manual prompt | goal-first ("decide, don't just run") |
| Success detection | substring grep (`"found"`) | evidence-based validator |
| Memory | negative-only; deletes successes | tiered: negative + positive + environmental |
| Engagement state | re-derived every call | persistent case file (read/write) |
| Prompt injection | tool output re-enters raw | trust-tier guard on every output |
| Autonomy | all-or-nothing | per-action-class policy |

Substring grep versus an evidence-based validator is the entire distance between a script and an operator. Everything else is in service of making that judgment reliable, safe, and repeatable.

## The spine comes first

You don't get to build an autonomous offensive agent and bolt safety on at the end. The arsenal does genuinely sensitive work, and the difference between "professional weapon" and "liability" is entirely one layer: the engagement spine. So it's the first thing every action passes through, not the last.

The spine gives four guarantees, and they're enforced by construction rather than by good intentions:

- **Authorization** — you cannot construct an engagement context without a written-approval reference and a non-empty scope. Miss either, and it throws at construction time. There is no "just this once."
- **Scope guard** — every target is matched against an allowlist of hosts and CIDRs. Out of scope is refused and logged.
- **Kill switch** — one call halts all further authorized action mid-run.
- **Chain of custody** — every decision, authorized or blocked, is appended to a custody log you can export for the client.

One gate answers one question — *is this actor allowed to take this class of action against this target, right now?* — and it answers "yes" only when the run isn't halted, the target is in scope, and the autonomy policy permits it. Either way, it writes down what it decided. An offensive agent that can't produce that log has no business in front of a client.

## Three upgrades, at the architecture level

With the spine in place, three of yesterday's modules are worth describing — in terms of shape, not offensive specifics.

**Self-audit: the agent refusing to rot.** You run an agent like this on a security distro that ships tool upgrades constantly, while the model labs ship technique advances on their own cadence. Left alone, any agent decays: its tools fall behind, an upgrade silently breaks one before an engagement, and its architecture drifts toward obsolete. The self-audit module is HALO turning its eyes inward on a schedule — checking tool currency, arsenal integrity (did an upgrade *break* something?), framework currency, and its own module health. It rolls up to one verdict: current, updates-available, or attention-needed.

The deliberate line here matters more than the checks. **Tools** may auto-update under policy — bumping a scanner is low-risk and reversible. **Architecture** is never auto-changed. Frontier advances are surfaced as a backlog for me to approve, and that boundary is enforced in code: the update path touches tools only; backlog items have no auto-apply route. A security agent that silently re-architects itself is a liability, full stop.

**Debug mode: separate, bridged, sandboxed.** A debugger's whole job is to freely write and run code. A security loop's whole job is to gate everything. Those instincts are opposites, so the design keeps them apart. Debug mode is a standalone mode behind an explicit toggle, off by default, with its own state — it doesn't run inside the attack loop or share its gating. But the engagement can still *borrow* it mid-run to repair a broken proof-of-concept, without flipping the whole system into debug mode. And every execution goes through a sandbox: no sandbox, no run, enforced in code. Writing-and-running code is the same risk class as the arsenal's most sensitive actions, and it's treated that way.

**Continuous attack-surface awareness.** The scanner that keeps a live picture of a target's exposure draws its authorization from exactly one place — the engagement scope. There's no second definition of "what am I allowed to touch" to drift out of sync. Findings flow into a structured inventory the report builder can read later. Single-sourcing authorization sounds like a footnote; it's the difference between one guardrail and two guardrails that disagree.

## The honest part

Here's where I'll disappoint anyone hoping for self-evolving-AI mythology: the "stay current with the frontier" capability is **semi-automated, not magic.** When online, a feed pulls changelogs and release notes, diffs them against what HALO already uses, and produces a prioritized backlog. Then *I* decide what to adopt. The agent can be told to implement an approved item; it does not perform structural self-surgery on its own. That's not a limitation I'm apologizing for — it's the design. Unsupervised self-modification in an offensive tool is precisely the thing you don't want.

Every collaborator in the loop — model client, tool executor, control oracle, approver — is injected, which means the whole thing runs and is testable offline with stubs. The next-gen loop exercises end to end without touching a network, including a simulated prompt-injection attempt in tool output that gets caught and quarantined. If it can't be verified on my laptop with no target in sight, it isn't done.

## The takeaway

A while back I wrote up Jason Haddix's forecast for where autonomous pentesting is heading: a small pool of elite humans on genuinely novel work, and a much larger layer of continuous agents absorbing the well-documented bug classes. Nothing in yesterday's batch changes that picture — it's an attempt to build the *responsible* version of the second layer. An agent that decides instead of greps, that starts from authorization instead of ending at it, that keeps itself current without letting itself off the leash.

The worst-case use of a tool like this is real. But worst-case is also a spec: the same reasoning that lets you imagine the misuse is the reasoning that builds the guardrails before it's a live problem. That's the work. Purposeful risk analysis, hard boundaries in code, and a chain of custody for every decision — not panic, and not hype.

---

*HALO is for authorized security testing on systems you own or have written permission to test. Not affiliated with Google LLC.*
