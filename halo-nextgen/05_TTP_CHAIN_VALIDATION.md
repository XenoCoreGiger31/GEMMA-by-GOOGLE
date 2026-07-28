# 05 — TTP-Chain Validation: Evaluation + Design

This is the decision memo and design for the "ground testing / TTP-chain
validation" material: whether it is worth implementing alongside the rest of the
next-gen package, and how.

---

## Part A — Verdict: **YES, worth implementing. Adopt it as the spine.**

It isn't a nice-to-have bolted onto the four screens — it's the **missing
organizing principle** that makes the other four cohere. Recall the core gap from
`01`: HALO today optimizes for *coverage* ("did we run the scanners?") but its
real goal is *decision* ("is this exploitable **here**, with evidence, within
guardrails?"). TTP-chain validation is precisely a framework for answering that
question. The rocket analogy is exactly right:

> You can't always fire the rocket (can't safely run the live exploit on a
> production/air-gapped/one-of-a-kind asset, or on a brand-new CVE nobody has
> weaponized). So you **prove each component on the ground**: decompose the
> exploit into its chain of techniques, and test each link against your actual
> deployed controls. If any *required* link is broken by your environment, the
> exposure **isn't exploitable here** — and you have that answer, with evidence,
> without launching.

Why it fits HALO specifically:
- HALO already has the arsenal to *exercise* individual techniques (29 tools).
- HALO already has cross-session **learning** (the negative cache) — TTP
  validation extends it into **environmental learning** (`01` C2 tier 3: "which
  control stopped which technique here").
- It directly satisfies the deepest reading of every screen: harness goal
  (decide, don't just run), attack-surface management (validate exposures, don't
  just list them), and even prompt injection (a PI probe *is* a TTP to chain-test).
- It answers **Gartner's caution** the material quotes — *automation alone is
  risky; you want **tunable autonomy with a chain of custody***. That maps 1:1
  onto the autonomy policy (`01` C3) and the chain-of-custody logging already
  designed here.

### The one caveat that makes it responsible, not reckless
"Orchestrate, don't sprawl" is the right mantra — but HALO already *is* a pile of
29 tools. The risk is adding a 30th thing. So the design below is explicitly **an
orchestration layer that reuses existing tools and agents**, not a new tool
stack. It's a *loop*, not another scanner. That's the whole point of the material
and it's the discipline we hold to.

---

## Part B — What we're building: the loop, not another tool

The material names three components of a continuous offensive-security loop.
Mapped to HALO:

| Loop component (from the material) | What it means | HALO realization |
|---|---|---|
| **Autonomous penetration testing** | AI agents chain real attacks to find what's *genuinely* exploitable, within guardrails | HALO's existing `agent_loop` + multi-agent layer, gated by the autonomy policy (`01` C3) |
| **Exposure validation (TTP-chaining)** | prove exploitability *without a live exploit*, incl. restricted/air-gapped assets and day-0 CVEs | **new:** `ttp_chain.py` — decompose CVE→technique chain, validate each link against controls |
| **Breach & attack simulation (BAS)** | continuously re-test prevention/detection against the newest techniques; catch control drift | **new orchestration:** run the technique library on a cadence via `continuous_scanner.py`; diff results over time |

The unifying cycle is **validate → decide → fix → re-validate**:
```
        ┌─────────── re-validate ───────────┐
        ▼                                    │
   VALIDATE ──► DECIDE ──► FIX ──────────────┘
  (exercise    (exploitable  (ticket + remediation;
   each TTP     here? y/n     evidence attached)
   vs controls) w/ evidence)
```
- **Validate:** for a given exposure/CVE, decompose into its TTP chain (e.g.
  initial access → execution → cred access → lateral movement → objective), and
  test each *required* link against the deployed controls (EDR policy, hardening,
  LSASS protection, app allow-listing, firewall).
- **Decide:** if the environment **breaks any required link**, the exposure is
  **not exploitable here** — recorded with evidence. If every required link
  passes, it **is** exploitable — recorded with evidence.
- **Fix:** the finding lands as a ticket (Jira/ServiceNow) **with evidence and
  chain of custody attached** — Gartner's requirement. Not "a scanner said so."
- **Re-validate:** after remediation (or after controls/assets drift), re-run the
  chain to confirm the fix and catch regressions. This is the BAS half.

---

## Part C — Design detail

### C1. TTP model
- **Technique library:** small, extensible catalog of techniques, each with:
  `id`, `name`, ATT&CK-style tactic, the HALO tool(s)/action that *exercises* it,
  the control(s) that would *break* it, and the evidence that proves pass/fail.
  Ships with a starter set; grows over time (the Bitter-Lesson-friendly move: the
  library is *data*, not code).
- **Chain:** an ordered list of `(technique, required?)`. A chain is *broken* if
  any **required** technique fails validation against controls. Optional links
  failing just means "harder here," not "safe."
- **CVE decomposition:** map a CVE to its required technique chain (from the
  advisory + `searchsploit`/`nuclei` context). Day-0 / un-weaponized CVEs are
  handled exactly because we validate *component techniques*, not a finished
  exploit — the rocket principle.

### C2. Validation against controls (the "ground test")
Each technique's validator answers: *would this link succeed against the controls
actually deployed on this asset?* Sources of "controls actually deployed":
- the `attacksurface.md` inventory (`04`) — what's there, versions, configs;
- observed behavior — run the *technique* (not the live exploit) in a safe/probe
  mode and observe whether the control stops it;
- the **environmental memory tier** (`01` C2) — what stopped this technique here
  before.
This is where "restricted / air-gapped / can't-touch" assets are served: you
validate the *component* against the *known control set* even when you can't fire
the full exploit at the asset.

### C3. Tunable autonomy + chain of custody (Gartner)
- Every TTP validation is an action with an **autonomy class** (`01` C3):
  passive technique checks → `auto`; anything that actually exercises an exploit
  primitive → `ask`/`never`. So the loop runs continuously where safe and stops
  for a human where it must — *tunable* autonomy, not full automation.
- **Chain of custody:** every step logs `{who/what, action, input, output,
  timestamp, evidence-ref}`. Findings carry this record end-to-end into the
  ticket. `ttp_chain.py` emits it; it's the defensible audit trail.

### C4. Ticketing / outcome (Jira / ServiceNow)
Findings land as tickets with evidence + chain of custody attached. Integration
is a thin adapter (create-issue API) behind an interface — not built here,
because it needs the deployment's instance + credentials (an ops item, not code
to hard-code). `ttp_chain.py` produces the structured finding; the adapter maps
it to the tracker's fields.

### C5. How it ties the whole package together
| Component | Role in the loop |
|---|---|
| `01` harness redesign | provides the decision-first goal, memory tiers, autonomy policy the loop needs |
| `02` prompt injection | PI probes are TTPs the loop can chain-validate; the guard protects the loop's own inputs |
| `03` LLM deep dive | picks the reasoning model for the **decide** step |
| `04` attacksurface.md | the asset+control inventory the **validate** step tests against; the loop feeds findings back |
| `ttp_chain.py` | the validate→decide→fix→re-validate engine itself |
| `continuous_scanner.py` | the cadence/BAS driver that keeps re-validating |

---

## Part D — What I did *not* do (scope discipline)
- Did **not** add tools to `halo_tools.TOOLS` or touch the running harness.
- Did **not** build the Jira/ServiceNow adapter (needs your instance + creds).
- Did **not** build a full ATT&CK technique library — shipped a starter catalog
  in `ttp_chain.py` designed to grow as data.
- Kept it a **loop over existing capability**, honoring "orchestrate, don't
  sprawl."

**Bottom line:** the TTP-chain / continuous-validation material is the best
single idea in the batch for HALO, because it converts HALO from a tool-runner
into the decision engine its own goal already implies. Adopt it as the spine;
deploy deliberately.
