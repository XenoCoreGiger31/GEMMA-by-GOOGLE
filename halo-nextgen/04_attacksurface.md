# 04 — Attack Surface Management (the OUTWARD eye)

The outward half of #5: HALO maps the **total attack surface of an authorized
target** — ports, web, DBs, APIs, cloud, subdomain-takeover, cert drift — and
feeds it straight into the exploitability decision (`05`). This is the offensive
capability that makes HALO fearsome. `continuous_scanner.py` and
`asm_inventory.py` do the mapping/monitoring; this file is the methodology +
the human-readable record.

> **#5 has two halves — this is the OUTWARD one.** The INWARD half — HALO
> auditing *itself* (tool currency, arsenal integrity, framework currency,
> anti-obsolescence) — lives in `07_SELF_AUDIT.md` / `self_audit.py`. Both are
> built to the same top-tier bar.

> **The table below is a working template.** Point the scanner at an authorized
> target (or your own estate) and it auto-populates + re-checks on a cadence.
> The same six questions apply whether the asset is a target's or your own.

---

## The standing audit questions (from Screen 3)

For **every** asset, keep these answered and current:
1. **What tech do they use?** (stack, versions)
2. **Self-hosted or third-party?**
3. **How do we auth into that service?** (and how are those creds stored)
4. **What are the common security issues & misconfigurations for that platform/tech?**
5. **What all do we have deployed there?**
6. **Is it a web property? Databases? APIs? What is the total attack surface for that system?**

---

## Inventory table (fill in / auto-populate)

| ID | Asset / name | Tech + version | Self-hosted / 3rd-party | Auth method | Deployed here | Web? DB? API? | Exposed ports/endpoints | Owner | Last audited | Notes / known issues |
|----|--------------|----------------|--------------------------|-------------|---------------|---------------|--------------------------|-------|--------------|----------------------|
| AS-0001 | _e.g. marketing site_ | _e.g. Nginx 1.25 / Next.js_ | _self-hosted VPS_ | _SSH key + Cloudflare_ | _static + contact API_ | web + API | 80,443 | _you_ | _YYYY-MM-DD_ | _fill in_ |
| AS-0002 | | | | | | | | | | |
| AS-0003 | | | | | | | | | | |

`asm_inventory.py` reads/writes this table as structured records so the scanner
can diff it over time (new port opened, version drifted, cert expiring, service
disappeared).

---

## Per-category checklists (the "common misconfigurations" the screen asks for)

Expand each asset against its category. These are the recurring
issues/misconfigurations to audit continuously.

### Cloud (AWS / GCP / Azure)
- Public S3/GCS/Blob buckets; over-broad IAM; unused access keys; no MFA on root.
- Security groups / firewall rules `0.0.0.0/0` on admin ports (22/3389/DB ports).
- Public snapshots/AMIs; metadata service (IMDSv1) SSRF exposure.
- Unencrypted volumes; no CloudTrail/audit logging; default VPC exposure.
- *HALO tool:* `run_cloudfox` (AWS attack-surface enumeration).

### Web properties / sites
- Missing security headers (CSP, HSTS, X-Frame-Options); TLS config + cert expiry.
- Exposed `.git/`, `.env`, backup files, admin panels, `/actuator`, `/debug`.
- Outdated CMS/plugins (WordPress etc.); default creds; directory listing.
- *HALO tools:* `run_httpx`, `run_wafw00f`, `run_katana`, `run_nuclei`, `run_nikto`, `run_gobuster`, `run_ffuf`.

### APIs
- Missing authn/authz; IDOR/BOLA; no rate limiting; verbose errors leaking stack.
- Swagger/OpenAPI exposed; unauthenticated GraphQL introspection.
- Secrets in query strings; CORS `*` with credentials.
- *HALO tools:* `run_curl`, `run_ffuf`, `run_nuclei`.

### Databases / data stores
- Internet-exposed DB ports (3306/5432/27017/6379/9200/…); default/blank creds.
- No TLS in transit; unencrypted at rest; overly broad grants; public replicas.
- Redis/Elasticsearch/Mongo with no auth (classic ransom targets).
- *HALO tools:* `run_masscan`/`run_nmap` (port discovery), `run_hydra`/`run_ncrack` (auth testing).

### Hosts / servers / SSH
- Exposed 22/3389; password auth enabled; weak/reused creds; outdated OS/kernel.
- Unnecessary listening services; missing patches; no host firewall.
- *HALO tools:* `run_masscan`, `run_nmap`, `run_enum4linux`, `run_hydra`.

### Third-party / SaaS / vendors
- OAuth scopes over-granted; API tokens in code/CI; no token rotation.
- Vendor breach exposure; SSO misconfig; stale integrations.
- Webhooks with no signature verification.
- *Audit method:* inventory the integration + how auth is stored (question 3).

### DNS / domains / edge
- Dangling CNAMEs → **subdomain takeover**; missing CAA/DMARC/SPF/DKIM.
- Wildcard exposure; forgotten staging/dev subdomains.
- *HALO tools:* `run_subfinder`, `run_shodan`, `run_httpx`.

### Source control / CI-CD / supply chain
- Public repos leaking secrets; unsigned artifacts; over-privileged CI tokens.
- Dependency/skill/plugin supply chain (ties to `02` avenue #6 — sign & pin).
- *Audit method:* secret scanning; provenance.

---

## Continuous assessment cadence

`continuous_scanner.py` runs these on a schedule and updates this file + emits
diffs (change = investigate):
- **Daily:** external port sweep (masscan/nmap) of all inventory IPs → new open port = alert.
- **Daily:** `httpx` liveness + tech fingerprint drift; TLS cert expiry countdown.
- **Weekly:** `nuclei` template scan; subdomain re-enumeration (takeover watch).
- **On change:** any diff to this table triggers a targeted re-scan of that asset.
- **Every finding** is fed to the TTP-validation loop (`05`) to answer *"is this
  actually exploitable **here**, given our controls?"* — not just "a scanner
  flagged it."

## What "done" looks like for each asset
An asset is fully audited when all six standing questions are answered, its
category checklist is walked, its total attack surface (ports + web + DB + API)
is enumerated, and it's on the scanner's cadence. `Last audited` is stamped by
`asm_inventory.py`.
