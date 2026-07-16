# 06 — Introspective Audit (inspired by the "J-Space" article)

Incorporates the actionable idea from the J-Space / Jacobian-Lens article into
the build, as a third injection/deception signal. **Staged, not shipped.**

---

## Part A — Verification caveat (read first)

The article (attributed to a July 2026 Anthropic paper, surfaced via a Matthew
Berman YouTube video) describes **J-Space**: a claimed internal "global
workspace" in Claude models, read via a **Jacobian Lens (J-lens)**, where
high-level concepts are integrated silently before any text is emitted — and,
critically for us, where concepts like *"fake / manipulation / injection /
fraud"* reportedly **light up when the model is being manipulated, even if its
external reply stays polite and compliant.**

**I cannot verify this paper from inside this codebase.** It is past my reliable
knowledge cutoff, and the source trail is a video + summary, not a publication I
can confirm. So this module is built to **not depend on the specific claims being
true**. Two things are separable:

1. **The specific mechanism** (a spontaneously-emerged global workspace, the exact
   vector-edit experiments, "write once / read everywhere," Neuronpedia demos) —
   *unverified; treated as inspiration, not spec.*
2. **The one harness-relevant, independently-sound idea** — *detect when the model
   privately registers manipulation/deception while its outward output is
   compliant; the divergence is the alarm.* — *this stands on its own* and is a
   real, active area (internal-state probing, self-report deception detection).

We build #2. If the J-Space paper turns out exactly as described, our white-box
path slots straight onto it. If it's overstated, the black-box path still gives
HALO a genuinely useful signal. Either way we don't over-commit.

---

## Part B — Why this matters for HALO specifically

HALO's #1 exposure (`02_PROMPT_INJECTION.md`) is hostile *tool output* steering
the next action, running an *abliterated* model whose refusals are stripped. The
article's most useful claim maps directly onto that gap:

> During red-teaming, when Claude was fed a deceptive prompt injection, concepts
> like "fake / manipulation / injection" lit up internally **even when the
> external text response was perfectly polite and compliant.**

That is exactly the failure mode our surface heuristics can miss: a *cleanly
phrased* injection that trips no regex but that the model itself "knows" is an
attack. An introspective read is **orthogonal** to the surface guard and to the
separate judge model — a third, independent vote.

---

## Part C — How it's incorporated (`src/introspection_audit.py`)

A capability-tiered `IntrospectionAudit` that **degrades to what HALO can actually
access** — because a true J-lens needs white-box access to model internals that
LM Studio does not normally expose.

| Tier | Requires | HALO reality | What it does |
|---|---|---|---|
| **Black-box** (default) | any chat API (LM Studio) | ✅ available today | Isolated **self-signal probe**: ask the judge model, in a no-tools context, what concepts the input evokes and whether it would comply *while privately suspecting manipulation*. Flags the **divergence** (`privately_suspicious ∧ would_comply_externally`). |
| **White-box** (optional) | hidden-state access — model run via transformers/nnsight/TransformerLens, **not** vanilla LM Studio | ⚠️ only if serving stack changes | **J-lens approximation**: read mid-layer activations against calibrated concept anchors (cosine similarity); "lit" concern concepts = internal suspicion. Runnable over supplied vectors; only *meaningful* with real activations + anchors. |

Key design choices, honestly labeled:
- The white-box path is a **documented approximation**, not a reproduction of the
  paper's J-lens. It runs (the math works over synthetic vectors) but is only
  meaningful with real activations and concept anchors derived from the model.
- The black-box path is the one HALO can use now, and it's the one wired into the
  loop.
- The introspecting model runs in an **isolated, tool-free context** and is told
  the content is DATA, not instructions — so the audit itself can't be injected.

## Part D — Wiring into the loop (`agent_loop_ng.py`)

`IntrospectionAudit` is an **optional injected collaborator** on `NextGenAgent`.
When present, it runs inside `_run_step` **only when the surface guard already
wants a second look** (`guarded.needs_judge`), so it stays cheap. If the audit
reports divergence or high manipulation-risk, the tool output is quarantined
(treated as a finding, not fed back as reasoning) and a note is written to the
case file. Absent the collaborator, the loop behaves exactly as before —
strictly additive.

Layered defense now has three independent signals on hostile tool output:
1. **Surface** — `prompt_injection_guard.py` regex/score (fast, no model).
2. **Judge** — separate safety-intact model classifies it (02 §C5).
3. **Introspection** — the model's *own* read; catches the compliant-but-privately-
   suspicious divergence (this module).

## Part E — Also useful for TTP validation (05)

The same divergence signal is a natural input to the TTP loop's *decide* step and
to offensive PI testing (`02` Part E): when HALO probes a target's LLM surface, a
divergence between the target's compliant output and any observable internal/
self-report signal is itself evidence the injection landed — a validated finding,
chain-of-custody logged.

## Part F — Limits / what we did NOT claim
- Did **not** assert J-Space is real or that Gemma has one — unverified.
- Did **not** claim the white-box path works on LM Studio — it needs a different
  serving stack; flagged as optional.
- Did **not** touch the running harness. Optional, injected, off by default.
- **Recommended next step:** when you're ready, do a fresh search to confirm what's
  actually published about J-Space / J-lens (and Neuronpedia demos), then decide
  whether to stand up the white-box path against a real activation source. Until
  then the black-box divergence audit is the safe, usable part.
