# 01 — Harness Optimization (Goal Orientation + Bitter Lesson)

Answers Screen 1/4: *characterize the goal, find the parts of the harness working
against it, and redesign toward one cohesive direction* — plus the follow-up:
**faster, stronger, better memory, latest reasoning tech.**

---

## Part A — Goal Orientation

### A1. What HALO is ultimately trying to accomplish

> **A fully-local, autonomous offensive-security operator that decides which
> exposures are genuinely exploitable in a given environment, proves it with
> evidence, and never re-learns the same dead end — all within operator-defined
> guardrails.**

Three load-bearing words in that sentence, and how today's harness scores:

| Goal property | Where it lives today | Grade |
|---|---|---|
| **Autonomous** | `agent_loop.run_full_engagement` (recon → attack loop) | Strong |
| **Local / sovereign** | `halo_config` (LM Studio, no cloud), abliterated Gemma | Strong |
| **Learns / never repeats dead ends** | `agent_cache.NegativeCache` (cross-session fingerprint blacklist) | Good but one-directional |
| **Decides exploitability** | *implicit* — the loop runs tools and greps output for `"password/shell/success"` | **Weak — this is the gap** |
| **Proves with evidence** | `validator_agent.py` exists but isn't in the autonomous path | **Weak** |
| **Within guardrails** | Two-gate human approval for `run_exploit` only | Partial |

**Diagnosis:** HALO is characterized in its README as an *autonomous pentest
agent*, and it is one — but its center of gravity is **"run the tool"**, not
**"decide the answer."** The single most valuable upgrade is to move the goal
from *coverage* (did we run the scanners?) to *decision* (is this exploitable
here, with evidence?). That reframing is what `05_TTP_CHAIN_VALIDATION.md`
operationalizes, and it's why the TTP-chain idea is worth adopting.

### A2. Parts of the harness working *against* the goal

Concrete, file-anchored friction points, each with a fix.

1. **The system prompt is a static tool manual, not a goal statement.**
   `agent_loop.py:22-90` — `SYSTEM_PROMPT` enumerates tools and rigid workflows
   ("RECON WORKFLOW - follow this order..."). It hard-codes *procedure*. The
   Bitter Lesson (Part B) says procedure baked into the prompt is the first thing
   to lose to scaling. It should state the **goal and the decision criteria**, and
   let search + the cache discover procedure.
   *Fix:* goal-first system prompt (draft in §C1).

2. **Success is detected by substring grep, not evidence.**
   `agent_loop.py:330` — `any(x in output.lower() for x in ["password","login",
   "session","shell","success","found","valid"])`. A `nikto` banner containing the
   word "found" counts as a breach; a real RCE that doesn't print "success" does
   not. This directly undercuts *"proves with evidence."*
   *Fix:* route candidate findings through `validator_agent.py` before they count
   (it already exists and is documented as "confirms findings against real
   evidence before they count" — it's just not in the loop).

3. **Memory is negative-only and never consolidated.**
   `agent_cache.NegativeCache` remembers *failures* forever but throws away
   *successes* (`record_success` **deletes** the fingerprint, `agent_cache.py:196`).
   HALO forgets what worked. For "better memory," the cache should be **bi-directional
   and tiered** (§B2, §C2): negative (avoid), positive (prefer), and environmental
   (what this target's controls stopped last time — the chain-of-custody input to
   TTP validation).

4. **No context management for long engagements.**
   Each `call_model` (`agent_loop.py:177`) sends the full static prompt + a
   one-line goal. There is no running case-file, no compaction, no carry-over of
   what's been established. The agent re-derives the target's state every call.
   *Fix:* a persistent per-engagement **case file** (§C2) the model reads and
   writes — the "better memory" ask, and the substrate the TTP loop decides on.

5. **Guardrails are all-or-nothing and cover one tool.**
   Only `run_exploit` is gated (`agent_loop.py:220`). Brute-force, `sqlmap`,
   destructive `run_command` run ungated. Gartner's caution (quoted on the
   TTP screen) is *automation-alone is risky; you want tunable autonomy with a
   chain of custody.* Today's autonomy dial has two positions.
   *Fix:* a per-action-class autonomy policy (§C3), the same policy the TTP loop
   consults.

6. **Skill selection is keyword-substring and shallow.**
   `skills.py:35-45` matches skills whose name/description words appear in the
   goal string, caps at 3, and only one skill ships (`skills/vulnerabilities/
   sql_injection.md`). Real adaptive playbook injection needs embedding/relevance
   ranking and a fuller library — but this is low priority vs. 1–5.

7. **Fragile model-output contract.**
   `parse_model_response` (`agent_loop.py:133`) heroically salvages malformed JSON.
   That's a symptom of asking a small local model for strict JSON with no schema
   enforcement. Structured-output/tool-call schemas (see `03` §Harnessing) remove
   the whole failure class where the serving stack supports it.

### A3. Do we have a clear single direction? 

Yes — but it's **implicit and diluted by procedure**. The harness reads as "a
box of 29 tools with a loop around it." The interview questions below exist to
confirm the *decision-first* reframing before any of this is deployed.

**Interview me about (blocking questions for deployment, not for building):**
- **Q1 — Guardrail floor:** In a real engagement, which action classes must
  *always* stop for human approval, which are auto-approved, and which are
  *never* allowed? (Drives the autonomy policy in §C3.)
- **Q2 — Evidence bar:** What counts as "proven exploitable" to you — a shell? a
  read of a canary file? a specific tool exit condition? (Drives the validator
  contract in item 2.)
- **Q3 — Environment scope:** Is the continuous scanner (`04`) pointed only at
  *your own* infrastructure inventory, or also at client engagement scopes? These
  need different authorization handling.
- **Q4 — Local model ceiling:** Is Gemma-4-12B the permanent target, or is a
  larger local model (or a hosted frontier model for the *planning/decision*
  layer only) acceptable? This changes how much reasoning we push into the model
  vs. the harness (see Bitter Lesson trade-off, §B3).

---

## Part B — Bitter Lesson Optimization

Richard Sutton's *Bitter Lesson* (2019): **general methods that scale with
computation — search and learning — beat methods that bake in human domain
knowledge, over the long run.** Hand-engineered cleverness wins in the short term
and is repeatedly overtaken. Re-derived here specifically for an AI security
harness:

> **For HALO: prefer a general decide-act-learn loop driven by model reasoning
> (search) and accumulated experience (learning) over hand-coded tool workflows,
> keyword heuristics, and fixed attack orders. Every place we hard-code "how a
> pentester does it" is a place a bigger model + more search will outgrow.**

### B1. Where HALO currently bets *against* the Bitter Lesson (hand-coded knowledge)

| Hand-coded knowledge | File | Bitter-Lesson replacement |
|---|---|---|
| Fixed "RECON WORKFLOW" 1–8 order | `agent_loop.py:52` | Let the model plan order from the goal + case file; keep the list only as a *hint* |
| Hydra service-name / wordlist ladders | `agent_loop.py:62-77` | Move to a tool-side default; let the model escalate by reasoning, not by a baked ladder |
| Substring success detection | `agent_loop.py:330` | Learned/validated evidence, not a keyword list |
| Keyword skill matching | `skills.py:41` | Relevance ranking (embeddings) — search, not string match |
| Fixed retry counts by failure type | `agent_cache.py:124-138` | Keep as a floor; let outcomes tune it |

### B2. Where HALO already *honors* the Bitter Lesson (keep + amplify)

- **The negative-experience cache is the right idea** — it's *learning* that
  scales with sessions and needs no human to encode "don't brute-force telnet."
  Amplify it: make it bi-directional (learn successes too) and
  environment-aware (learn which *controls* blocked which *techniques* — that's
  the learning signal the TTP-validation loop consumes).
- **Tool-once schema registry** (`halo_tools.TOOLS`) — general, transport-agnostic.
  Good. New capabilities should land here, not in bespoke glue.
- **Model-driven tool chaining** — the `{"chain":[...]}` contract already lets the
  model compose, rather than us scripting fixed combos. Keep; harden the schema.

### B3. The scaling trade-off to decide (ties to Interview Q4)

The Bitter Lesson says push reasoning into the scalable component. For a
*local* harness the scalable component is constrained by Gemma-4-12B. Two viable
directions:
- **(a) Keep everything local**, and invest the "search" budget in the harness
  loop: more validation passes, more cache learning, TTP decomposition run as
  many small model calls. Slower per step, fully sovereign.
- **(b) Two-tier reasoning:** a frontier model (local-large or, if policy allows,
  hosted) does *planning and exploitability decisions*; Gemma drives the fast
  tool loop. More capable decisions, weaker sovereignty guarantee.

This is a values call (sovereignty vs. capability), which is why it's an
interview question, not a code decision.

---

## Part C — The Redesign (faster, stronger, better memory)

Three concrete artifacts, each defined here with its integration point.

### C1. Goal-first system prompt (replaces the tool-manual prompt)

Draft intent (not final copy):
```
You are HALO, an autonomous offensive-security operator running fully locally.

YOUR GOAL, in priority order:
1. Decide which exposures are GENUINELY EXPLOITABLE in THIS environment.
2. Prove each finding with concrete evidence a human can verify.
3. Never spend effort on an approach your experience cache has already
   disproven for a comparable target.
4. Stay inside the operator's autonomy policy. When an action exceeds your
   authorized autonomy level, request approval instead of proceeding.

You have a tool arsenal and an experience cache. You decide order and
composition from the goal and the case file — the workflow hints below are
starting points, not rules. Reason first; act to gather evidence; record what
you learn (both dead ends and confirmed techniques).

RESPONSE CONTRACT: <same strict {"chain":[...]} JSON, schema-validated>
```
Why it serves the goal: states the *decision*, demotes procedure to a hint
(Bitter Lesson), and names the autonomy policy and case file as first-class.

### C2. Tiered, bi-directional memory ("better memory")

Replace the negative-only `failure_cache.json` with three tiers. Same
fingerprint mechanism (`agent_cache._fingerprint`), extended:

| Tier | Learns | Effect on the loop |
|---|---|---|
| **Negative** (exists today) | tool calls that failed | skip / de-prioritize |
| **Positive** (new) | tool calls + contexts that produced *validated* findings | prefer / try first |
| **Environmental / chain-of-custody** (new) | which control stopped which technique on which target class (e.g. "LSASS protection blocked credential-dump chain on host-type X") | feed the TTP-validation decision directly — this *is* the exposure-validation evidence |

Plus a per-engagement **case file** (`case_<session>.json`): open ports,
confirmed services, findings-with-evidence, techniques-tried, controls-observed.
The model reads it at the top of every `call_model` and appends to it after every
validated step. This is the "better memory" ask and removes the re-derivation
tax (item A2.4). Positive-tier + case file = **stronger**; skipping known dead
ends + reading state instead of re-scanning = **faster**.

### C3. Tunable autonomy policy (chain-of-custody-friendly)

A single policy object the loop consults before every step, replacing the
`run_exploit`-only gate:

```
autonomy:
  recon:            auto          # httpx, nmap, subfinder, ...
  active_scan:      auto          # nuclei, nikto
  credential_attack: ask          # hydra, medusa, ncrack, john
  exploitation:     ask           # sqlmap payloads, run_exploit  (two-gate as today)
  destructive:      never         # rm-ish run_command, setoolkit
evidence_required_before_marking_exploitable: true
record_chain_of_custody: true     # every step logs actor, input, output, ts
```
Maps 1:1 onto Gartner's "tunable autonomy with a chain of custody" and onto the
TTP loop's decide step. `never`/`ask`/`auto` are per action-class, not per-tool,
so new tools inherit a default by class.

### C4. Expected effect against the goal

| Change | faster | stronger | better memory | safer |
|---|:--:|:--:|:--:|:--:|
| Goal-first prompt (C1) | | ✅ | | |
| Validator in the loop (A2.2) | | ✅ | | |
| Tiered bi-dir memory + case file (C2) | ✅ | ✅ | ✅ | |
| Skip known dead ends (existing, amplified) | ✅ | | ✅ | |
| Autonomy policy (C3) | | | | ✅ |
| TTP decision layer (`05`) | | ✅ | ✅ | ✅ |

Integration points for these components are described in the package README.
