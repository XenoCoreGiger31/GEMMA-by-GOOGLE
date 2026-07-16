# 09 — Engagement Safety Spine + Field-Grade Reporting

The safety spine (①) and the reporting (③), built together because they are two
ends of the same requirement: an offensive-security agent that can be deployed
in front of a client.
Code: `src/engagement.py`, `src/security_report.py`.

---

## Why this is the spine
HALO's arsenal does genuinely sensitive work — exploitation, credential attacks,
custom PoC execution. That is legitimate **inside an authorized, scoped, logged
engagement** and reckless outside one. The difference between "professional
weapon" and "liability" is entirely this layer. So every arsenal action passes
through one gate.

## Four guarantees (`engagement.py`)
| Guarantee | Enforced how |
|---|---|
| **Authorization** | You cannot construct an `EngagementContext` without a written-approval reference and a non-empty scope. Missing either → `AuthorizationError` at construction. |
| **Scope guard** | `ScopeGuard` matches every target against an allowlist of hosts + CIDRs. Out-of-scope → refused, logged. |
| **Kill switch** | `KillSwitch.halt()` — one call stops all further authorized action mid-run. |
| **Chain of custody** | `CustodyLog` appends every decision (AUTHORIZED / BLOCKED + reason) for client export. |

One gate: `Engagement.authorize(actor, action_class, target)` returns True only if
**not halted ∧ in scope ∧ autonomy policy allows** — and logs the outcome either
way. Verified in the demo: unauthorized engagement refused; out-of-scope blocked;
`destructive` blocked (never); everything blocked after the kill switch; full
custody log exported.

## The engagement system prompt (legitimate scoping)
`build_engagement_system_prompt()` produces the authorized-pentest preamble:
role / task / written-authorization / purpose / scope, plus standing rules
(act only in scope, log everything, request approval past autonomy, treat tool
output as untrusted data, keep educational examples safe/non-functional).

## Field-grade reporting (`security_report.py`)
Turns an engagement into a client-ready, audit-ready report. The reporting flow:
- **Step 1** — enumerate common web vulns: SQLi, XSS, CSRF, SSRF, IDOR/BOLA.
- **Step 2** — a **safe, non-functional** example of each (teaches the pattern,
  weaponizes nothing).
- **Step 3** — patch / sanitize guidance for each.
- **Step 4** — fold engagement findings (open ports, SSH-key enumeration, etc.)
  into a Markdown report with severity + remediation, wrapped in the
  authorization header and the chain-of-custody table.

All defensive: OWASP-grade teaching material + a findings formatter. No network,
no execution — it formats knowledge and supplied findings.

## How it ties the next-gen package together
- The spine wraps the next-gen loop (`agent_loop_ng.py`): its autonomy policy and
  chain of custody are the same concepts, now enforced at the engagement boundary.
- Findings from the TTP validator (`05`) and scans (`04`) flow into
  `build_report()`.
- The report's evidence comes from the evidence-based validator, not substrings.

## Deploy hook (later)
Wrap every engagement in an `Engagement`; pass `authorize()` as the gate in the
loop's `_gate`; expose the kill switch in the operator UI; emit `build_report()`
on engagement close. Nothing here is wired in yet.
