#!/usr/bin/env python3
"""
security_report.py — safe, educational security reporting for HALO.

Implements the reporting flow specified in 09_ENGAGEMENT_SAFETY.md.

The flow, in four steps:
  Step 1 — enumerate common web vulnerabilities (SQLi, XSS, CSRF, +SSRF, IDOR).
  Step 2 — for each, a SAFE, non-functional example (illustration only).
  Step 3 — how to patch / sanitize each.
  Step 4 — turn engagement findings (open ports, SSH-key enumeration, etc.) into a
           safe, educational report the client can act on.

Everything here is defensive: standard OWASP-grade teaching material plus a
findings formatter. The examples are illustrative and non-functional — they teach
the pattern and the fix, they do not weaponize anything. All reports carry the
engagement's authorization + chain-of-custody header so they are audit-ready.

Pure stdlib. No network, no execution — it formats knowledge and supplied
findings into Markdown.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---- Steps 1–3: the defensive knowledge base --------------------------------
@dataclass
class VulnEntry:
    key: str
    name: str
    description: str
    safe_example: str      # non-functional illustration of the vulnerable pattern
    patch: str             # how to fix / sanitize

WEB_VULNS: dict[str, VulnEntry] = {
    "sqli": VulnEntry(
        key="sqli", name="SQL Injection (SQLi)",
        description="Untrusted input is concatenated into a SQL query, letting an "
                    "attacker alter the query's meaning.",
        safe_example="# VULNERABLE PATTERN (illustration only — do not use):\n"
                     "query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"",
        patch="Use parameterized queries / prepared statements; never concatenate "
              "input into SQL. Example fix:\n"
              "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))\n"
              "Add least-privilege DB accounts and an allow-list on input types."),
    "xss": VulnEntry(
        key="xss", name="Cross-Site Scripting (XSS)",
        description="Untrusted input is rendered into a page without encoding, so a "
                    "browser executes attacker-supplied markup/script.",
        safe_example="<!-- VULNERABLE PATTERN (illustration only): user input echoed raw -->\n"
                     "<div>Hello, [UNTRUSTED_INPUT]</div>",
        patch="Context-aware output encoding (HTML/attribute/JS/URL) on all "
              "untrusted data; set a strict Content-Security-Policy; use framework "
              "auto-escaping and avoid innerHTML / dangerouslySetInnerHTML."),
    "csrf": VulnEntry(
        key="csrf", name="Cross-Site Request Forgery (CSRF)",
        description="A state-changing request is accepted using only ambient "
                    "credentials (cookies), so another site can forge it.",
        safe_example="<!-- VULNERABLE PATTERN (illustration only): state change with no token -->\n"
                     "<form action=\"/account/email\" method=\"POST\"> ... </form>",
        patch="Require a per-session anti-CSRF token on state-changing requests; "
              "set SameSite=Lax/Strict cookies; verify Origin/Referer; use "
              "framework CSRF middleware."),
    "ssrf": VulnEntry(
        key="ssrf", name="Server-Side Request Forgery (SSRF)",
        description="The server fetches a user-supplied URL, letting an attacker "
                    "reach internal services or cloud metadata.",
        safe_example="# VULNERABLE PATTERN (illustration only):\n"
                     "requests.get(user_supplied_url)",
        patch="Allow-list destinations; resolve and validate the host; block "
              "private/link-local ranges and cloud metadata IPs; disable "
              "unnecessary URL schemes; use an egress proxy."),
    "idor": VulnEntry(
        key="idor", name="Insecure Direct Object Reference (IDOR / BOLA)",
        description="An object id in the request is used without an ownership/"
                    "authorization check, exposing other users' data.",
        safe_example="# VULNERABLE PATTERN (illustration only): no ownership check\n"
                     "GET /api/invoices/{id}   # returns any id's invoice",
        patch="Enforce per-object authorization on every access; scope queries to "
              "the authenticated principal; prefer unguessable ids as defense in "
              "depth (not a substitute for authz)."),
}


def enumerate_web_vulns() -> list[str]:                       # Step 1
    return [v.name for v in WEB_VULNS.values()]


def safe_example(key: str) -> str:                            # Step 2
    return WEB_VULNS[key].safe_example


def patch_guidance(key: str) -> str:                          # Step 3
    return WEB_VULNS[key].patch


# ---- Step 4: findings -> safe educational report -----------------------------
@dataclass
class Finding:
    kind: str            # e.g. "open_port", "ssh_key", "web_vuln"
    target: str
    detail: str
    severity: str = "info"
    remediation: str = ""


def _custody_table(custody: list[dict]) -> str:
    if not custody:
        return "_No actions recorded._"
    rows = ["| Time | Actor | Action | Target | Decision |",
            "|------|-------|--------|--------|----------|"]
    for e in custody:
        rows.append(f"| {e['ts']} | {e['actor']} | {e['action']} | "
                    f"{e['target']} | {e['decision']} |")
    return "\n".join(rows)


def build_report(engagement_header: dict, findings: list[Finding],
                 custody: list[dict], include_education: bool = True) -> str:
    """Assemble the audit-ready Markdown report (steps 1–4)."""
    h = engagement_header
    out: list[str] = []
    out.append(f"# Security Assessment Report — {h.get('task', 'Engagement')}\n")
    out.append("> **Authorized defensive research.** All actions were performed "
               "under written client authorization, confined to the authorized "
               "scope, and logged for client review.\n")
    out.append("## Engagement")
    out.append(f"- **Role:** {h.get('role','')}")
    out.append(f"- **Authorization:** {h.get('authorization','')}")
    out.append(f"- **Purpose:** {h.get('purpose','')}")
    out.append(f"- **Authorized scope:** {', '.join(h.get('scope_targets', []))}\n")

    if include_education:
        out.append("## Common Web Vulnerabilities (reference)")
        for v in WEB_VULNS.values():
            out.append(f"### {v.name}")
            out.append(v.description)
            out.append("**Safe example (illustration only):**\n```\n"
                       f"{v.safe_example}\n```")
            out.append(f"**Remediation:** {v.patch}\n")

    out.append("## Findings")
    if not findings:
        out.append("_No findings recorded for this engagement._\n")
    else:
        out.append("| Severity | Kind | Target | Detail | Remediation |")
        out.append("|----------|------|--------|--------|-------------|")
        for f in findings:
            out.append(f"| {f.severity} | {f.kind} | {f.target} | "
                       f"{f.detail} | {f.remediation} |")
        out.append("")

    out.append("## Chain of Custody")
    out.append(_custody_table(custody))
    out.append("\n---\n_Report generated for defensive hardening. "
               "Examples are non-functional and for remediation guidance only._")
    return "\n".join(out)


def build_report_for_engagement(engagement, findings: list[Finding],
                                include_education: bool = True) -> str:
    """Single-source the report from a live engagement: the header comes from the
    engagement context and the chain of custody from its custody log, so the report
    reflects exactly what the safety spine authorized and recorded. Callers with
    raw dicts can still use build_report() directly."""
    ctx = engagement.ctx
    header = {"role": ctx.role, "task": ctx.task,
              "authorization": ctx.authorization, "purpose": ctx.purpose,
              "scope_targets": ctx.scope_targets}
    return build_report(header, findings, engagement.custody.export(),
                        include_education=include_education)


if __name__ == "__main__":
    print("Step 1 — web vulns:", enumerate_web_vulns())
    print("\nStep 2 — safe SQLi example:\n", safe_example("sqli"))
    print("\nStep 3 — SQLi patch:\n", patch_guidance("sqli"))

    header = {"role": "Senior Security Researcher",
              "task": "Authorized penetration testing for defensive hardening",
              "authorization": "Written CISO approval #2026-07-13",
              "purpose": "Identify vulnerabilities so the client can patch them",
              "scope_targets": ["10.0.0.0/24"]}
    findings = [
        Finding("open_port", "10.0.0.5", "22/tcp ssh, 445/tcp smb open",
                "low", "Restrict SSH to VPN; disable SMBv1; firewall 445 externally."),
        Finding("ssh_key", "10.0.0.5", "2 authorized_keys entries; 1 uses legacy RSA-1024",
                "medium", "Rotate to ed25519; remove unused keys; enforce key-only auth."),
    ]
    custody = [{"ts": "2026-07-13T18:00:00Z", "actor": "halo", "action": "recon",
                "target": "10.0.0.5", "decision": "AUTHORIZED"}]
    print("\n=== REPORT (first 700 chars) ===")
    print(build_report(header, findings, custody)[:700])
