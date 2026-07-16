# 03 — Titans of Code & Hacking: Model Intelligence for HALO

Re-scoped per operator direction. This is **not** a survey of "every LLM ever."
It covers only the **top echelon** — the models that make HALO fearsome and the
models an adversary would actually field. No toy models. Two lenses:

- **Lens A — Build HALO's brain:** which titans to cast as HALO's *actor*,
  *judge*, and *decision-maker*.
- **Lens B — Adversary intel:** what the best offensive-capable models can do, so
  HALO is designed against a real ceiling, not a soft one.

> Deployment reality: HALO runs **local**. Today's base is an abliterated
> Gemma; the operator also runs two **Qwen** phone quants. So "titan-tier" here
> always has a *runnable-locally* answer (quantized/distilled), not just a
> frontier-API answer. Every recommendation below names the local path.

---

## Part A — The titan tier (the only models in scope)

Ranked by what matters for an offensive-security + elite-coding agent:
reasoning depth, coding/exploit fluency, tool-use fidelity, and whether you can
run it locally.

| Model family | Why it's a titan | Open weights / local? | Best HALO role |
|---|---|---|---|
| **Claude (Opus 4.x / Fable-tier, Anthropic)** | The coding & agentic benchmark — state-of-the-art multi-step reasoning, tool use, long-horizon autonomy, and bug-finding. The bar everything else is measured against. | No (API) | **Decision-brain** (if policy allows a non-local call) + the harness patterns to copy |
| **DeepSeek V3 / R1** | Open **reasoning** titan. R1's chain-of-thought rivals closed frontier on math/code; V3 is a strong MoE coder. Distills run locally. | **Yes** — full + R1-distill (Qwen/Llama) variants | **Local decision-brain** (R1-distill) |
| **Qwen 2.5/3 — Coder & Reasoning (Alibaba)** | Elite open coder line; Qwen-Coder is among the best open code models, and it's what you already run on phone. Big context, strong tool use. | **Yes** — quants down to phone size | **Actor** + **local decider** (you already have quants) |
| **GPT / o-series (OpenAI)** | Frontier reasoning + code; the o-series set the reasoning-model template. | No (API) | Adversary-capability reference; optional decider |
| **Gemini (Google)** | Frontier long-context + code + multimodal. Gemma is its open sibling (HALO's current base). | Gemma: **yes** | Reference; Gemma = current local actor |
| **Llama 3.x + Llama Guard (Meta)** | The open workhorse; **Llama Guard** is a purpose-built safety classifier. | **Yes** | **Judge** (Llama Guard) — the injection/abuse referee (see `02` §C5) |
| **Mistral / Codestral (Mistral AI)** | Efficient open dense+MoE; **Codestral** is a dedicated code model; Apache-licensed. | **Yes** | Alt actor / fast local coder |
| **WhiteRabbitNeo (cybersecurity-specialized)** | Open models explicitly tuned for offensive/defensive security use — recon, exploit reasoning, tooling. Purpose-built for exactly HALO's domain. | **Yes** | Specialist **actor** for security tasks |
| **Gemma (abliterated) — HALO's current base** | Small, fast, refusal-stripped → maximally compliant tool driver. | **Yes** | **Actor** (current) — but never the safety layer (it's abliterated) |

**Explicitly excluded (the "no kiddie crap" line):** 1–3B toy chat models,
generic uncensored roleplay fine-tunes with no coding/security signal, demo
models, and anything without real reasoning or tool-use capability. They add
attack surface and weak decisions, nothing else.

---

## Part B — Lens A: casting HALO's brain

The single most important design choice. Match model to trust + capability. Three
roles, never one model doing all three:

| Role | Job | Titan pick (frontier) | Titan pick (local, runnable) |
|---|---|---|---|
| **Actor** | drives the 29-tool arsenal, composes attack chains — compliant, tool-fluent | — | **abliterated Gemma / Qwen-Coder / WhiteRabbitNeo** |
| **Judge** | classifies hostile input for injection/abuse — must be *safety-intact*, no tools | — | **Llama Guard** (or stock Qwen/Gemma) |
| **Decider** | "is this genuinely exploitable here, with evidence?" — needs deep reasoning | **Claude Opus 4.x** (if policy allows) | **DeepSeek-R1 distill** or **Qwen-reasoning** |

Why the split makes HALO fearsome and safe at once:
- The **actor** is powerful and obedient — great at *doing*, dangerous if it were
  also the safety layer. So it never is.
- The **judge** is a *different* model with intact safety training and no tool
  access — an injection that hijacks the actor doesn't automatically hijack the
  judge (`02` §C5).
- The **decider** is the reasoning titan that turns "we ran tools" into "here's
  what's exploitable, proven" (`01`, `05`). This is the upgrade that moves HALO
  from tool-runner to the thing security people rave about.

**Local-first recommendation:** actor = Qwen-Coder / WhiteRabbitNeo quant;
judge = Llama Guard; decider = DeepSeek-R1-distill. All run on-box, fully
sovereign. Reserve a frontier Claude decider only if you ever relax the
local-only rule for the decision step (the trade-off in `01` §B3).

---

## Part C — Lens B: adversary capability intel (design against the real ceiling)

What the best offensive-capable models let an attacker do — so HALO is built to
beat a titan, not a script kiddie:

- **Autonomous exploit reasoning:** frontier + R1-class models decompose CVEs,
  write PoCs, and adapt to failures — the same loop HALO runs. Assume the
  adversary has it. HALO's edge must be *validated decisions + memory*, not raw
  model IQ.
- **Code understanding at scale:** titan coders read a repo and find the bug
  faster than a human team. HALO must match this on the **debug** side (see the
  debug-mode design) to be credible.
- **Prompt-injection authorship:** strong models write *clean* injections that
  dodge regex filters — which is exactly why HALO needs the judge + introspection
  layers (`02`, `06`), not just pattern matching.
- **Security-specialized fine-tunes (WhiteRabbitNeo-class):** the offensive
  community already runs domain-tuned models. HALO should be *at least* as
  capable, plus have the harness discipline they lack.

**Design implication:** HALO's moat is not the model — a black-hat can download
the same titans. HALO's moat is the **harness**: validated exploitability,
tiered memory, tunable autonomy, chain of custody, injection defense, and debug
soundness. That's the whole thesis of this shelf.

---

## Part D — Harness lessons from the titans (esp. Claude Code)

The titans' *harnesses* are as important as their weights. What HALO borrows:
- **Claude Code:** typed/gated tools, deterministic hooks (harness enforces, not
  the model), progressive-disclosure skills, compaction, sub-agents, permission
  modes. → mirrored in `01` and `agent_loop_ng.py`.
- **Reasoning models (R1/o-series):** explicit think-then-act separation → HALO's
  decider step.
- **Guard models (Llama Guard):** a dedicated classifier as a separate vote →
  `02` §C5.

---

## Part E — Security lens (one screen)
- **Actor:** capable + compliant (abliterated Gemma / Qwen / WhiteRabbitNeo) —
  assume compromisable by hostile input; never the safety layer.
- **Judge:** small, safety-intact, no tools (Llama Guard) — the injection referee.
- **Decider:** reasoning titan (DeepSeek-R1 local; Claude if policy allows) —
  turns tool output into proven exploitability.
- **The harness, not the model, is the security boundary.** A black-hat can field
  the same titans; HALO wins on harness discipline. That is how HALO becomes the
  agent security people ask each other about.
