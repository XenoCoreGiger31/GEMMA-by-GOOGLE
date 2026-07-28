# Attack Surface Inventory

Working record of the authorized attack surface. `asm_inventory.py` reads and
writes the table below as structured records; `continuous_scanner.py` sweeps the
listed assets on a cadence and diffs the results (a new open port, a version
drift, a vanished service, or a cert nearing expiry is a change to investigate).

Methodology, per-category checklists, and cadence are documented in
`halo-nextgen/04_attacksurface.md`. Authorization is enforced separately by the
engagement safety spine (`engagement.py`): the scanner refuses any host outside
the authorized engagement scope, regardless of what is listed here.

## The standing audit questions

For every asset, keep these answered and current:
1. What tech do they use? (stack, versions)
2. Self-hosted or third-party?
3. How do we auth into that service? (and how are those creds stored)
4. What are the common security issues & misconfigurations for that platform/tech?
5. What all do we have deployed there?
6. Is it a web property? Databases? APIs? What is the total attack surface?

## Inventory table

The three `AS-000x` rows are seed placeholders and are skipped by the parser.
Replace them with real assets, or add new rows below.

| ID | Asset / name | Tech + version | Self-hosted / 3rd-party | Auth method | Deployed here | Web? DB? API? | Exposed ports/endpoints | Owner | Last audited | Notes / known issues |
|----|--------------|----------------|--------------------------|-------------|---------------|---------------|--------------------------|-------|--------------|----------------------|
| AS-0001 | _e.g. marketing site_ | _e.g. Nginx 1.25 / Next.js_ | _self-hosted VPS_ | _SSH key + Cloudflare_ | _static + contact API_ | web + API | 80,443 | _you_ | _YYYY-MM-DD_ | _fill in_ |
| AS-0002 | | | | | | | | | | |
| AS-0003 | | | | | | | | | | |

---
*Not affiliated with Google LLC. For authorized security testing on systems you
own or have written permission to test.*
