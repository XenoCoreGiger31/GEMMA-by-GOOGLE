# Phase 07 — Self-Audit + Live Frontier-Currency (graduation + wiring)

**Status:** approved design, pre-implementation
**Design doc:** `halo-nextgen/07_SELF_AUDIT.md`
**Module graduating:** `halo-nextgen/src/self_audit.py`
**New module:** `frontier_feed.py` (the live outward eye)

## Goal

Graduate the self-audit module to the repo root and make **both of its eyes real**:

- **Inward** — is HALO's own arsenal / modules / architecture healthy and current?
  (tool currency, arsenal integrity, module health)
- **Outward** — regardless of HALO, what has the world shipped publicly that HALO
  should adopt to stay modern? (live frontier-currency across 5 sources)

The inward eye is wired to HALO's real 29-tool registry and its real modules. The
outward eye becomes a live, network-backed feed with an injectable HTTP transport
(so it still tests fully offline) and a curated fallback for air-gapped boxes.

The deliberate safety line is preserved and enforced in code: tool updates are an
action under the autonomy policy; **architecture / frontier items are proposal-only
and never auto-applied.**

Nothing in the agent tool loop (`halo_tools.py`, `agent_loop.py`) or `engagement.py`
changes this phase.

## Why the outward eye can work on a local MCP server

"Local MCP server" means HALO runs on the operator's box, not that it is offline.
The repo already depends on `requests>=2.28` and makes outbound HTTP calls
(`agent_loop.py`, `mcp_client.py`, `halo_adapters.py`). The frontier feed is the
same kind of call, pointed at public release endpoints. The Python module makes
the calls itself — it does not depend on the LLM having internet. When the box is
air-gapped, live sources degrade gracefully and the curated source still returns a
meaningful backlog.

## Part A — inward eye (`self_audit.py`, graduated to root)

Graduates as-is except:

1. **Deprecation fix.** Both `datetime.utcnow()` calls (report `ran_at`, `due()`)
   → the repo UTC convention `datetime.now(timezone.utc).replace(tzinfo=None)`,
   via a local `_utc_now()` helper. Suite stays clean under
   `-W error::DeprecationWarning`.

2. **`HALO_TOOL_BINARIES` map + `INTERNAL_TOOLS` set.** Classifies all 29 tools in
   `halo_tools.SUPPORTED_TOOLS`: 25 map HALO wrapper → Kali binary
   (`run_nmap`→`nmap`, `run_sqlmap`→`sqlmap`, …); 4 are internal with no package
   (`run_command`, `run_exploit`, `write_file`, `read_file`). A test asserts
   `set(HALO_TOOL_BINARIES) | INTERNAL_TOOLS == set(SUPPORTED_TOOLS)` — a drift
   guard: adding a 30th tool later fails the suite until it is classified.

3. **`SelfAuditor.for_halo(oracle, prober, frontier=None, ...)`** — convenience
   constructor (parallels Phase 04's `for_engagement`). Builds the audited binary
   list from the live registry through the map, and defaults `health` to a real
   `ModuleHealthProbe`. If `frontier` is None it defaults to a curated-only
   `PublicFrontierFeed` (offline-safe).

4. **`ModuleHealthProbe`** — a real `HealthProbe` that imports HALO's core modules
   (engagement, halo_tools, ttp_chain, prompt_injection_guard, continuous_scanner,
   asm_inventory, tiered_memory, introspection_audit) and reports which fail to
   import. Makes "do my own modules still load" functional.

## Part B — outward eye (`frontier_feed.py`, new at root)

A live, best-effort frontier-currency feed. `FrontierAdvance` and the `FrontierFeed`
Protocol stay defined in `self_audit.py` (the auditor's interface); the concrete
live implementation lives here to keep `self_audit.py` focused.

### Source interface
```
class FrontierSource(Protocol):
    def fetch(self, http_get) -> list[FrontierAdvance]: ...
```

### The 5 sources
1. **`GitHubReleasesSource`** — security-tool ecosystem. Given a `{name: "owner/repo"}`
   map (HALO's tools that live on GitHub, plus a watchlist of notable new tools)
   and what HALO has, GETs `releases/latest`, compares `tag_name`, and emits an
   advance for a newer release or a watchlist tool HALO lacks entirely.
2. **`MitreAttackSource`** — reduces to the same mechanism: MITRE ATT&CK ships as
   the `mitre-attack/attack-stix-data` GitHub repo; emit an advance when a newer
   ATT&CK version than HALO's adopted version is published.
3. **`ModelsEndpointSource`** — model frontier. Given provider base URLs
   (OpenAI-compatible `/models`, incl. the local model endpoint and hosted
   providers) and the model ids HALO knows, GETs the model list and emits advances
   for unknown models. Best-effort per provider.
4. **Anthropic / DeepSeek / OpenAI** are covered by `ModelsEndpointSource` provider
   entries (their model-list endpoints); provider-specific quirks degrade to no-op
   on failure.
5. **`CuratedSource`** — a static list HALO ships with (adaptive thinking, R1-distill
   decider, latest ATT&CK, etc.). Always returned; the offline / air-gapped fallback.

### `PublicFrontierFeed(FrontierFeed)`
- `__init__(self, sources, http_get=None, log=print)`.
- `http_get` defaults to a lazy `requests.get` → JSON wrapper (lazy import so the
  module loads and tests run without `requests`).
- `advances()` runs every source, **catching per-source failures** (offline,
  timeout, parse error) so one dead source never crashes an audit; dedupes and
  returns the pooled `FrontierAdvance` list.
- Builder `PublicFrontierFeed.default_for_halo(...)` assembles the standard source
  set (GitHub tool repos + MITRE + model endpoints + curated).

### Honest boundaries (enforced)
- **Detect + surface only.** The feed produces the modernize backlog; adoption is
  operator-approved. `apply_tool_updates()` touches only tools; backlog items have
  no auto-apply path. This is the deliberate safety line and gets its own test.
- **Bounded sources.** It tracks the configured feeds, not "all of the internet."
- **Best-effort + offline-safe.** Any live-source failure degrades to the curated
  list; the audit never crashes because a site was down.

## Data flow

```
                         inward eye                          outward eye
halo_tools.SUPPORTED_TOOLS ──map──▶ [nmap,…] ─┐        GitHub / MITRE / models  ─┐
PackageOracle / Prober (injected) ────────────┤        (live, injectable GET)    │
ModuleHealthProbe (imports modules) ──────────┤        CuratedSource (offline) ──┤
                                               ▼                                  ▼
                                    SelfAuditor.run() ◀── PublicFrontierFeed.advances()
                                               │
                                               ▼
                       SelfAuditReport → CURRENT / UPDATES_AVAILABLE / ATTENTION
                       (broken/missing/unhealthy ⇒ ATTENTION; outdated/backlog ⇒ UPDATES_AVAILABLE)
```

## Non-goals (boundaries held this phase)
- No registration in `halo_tools.py` TOOLS / `ToolExecutor._DISPATCH`.
- No changes to `agent_loop.py` or `engagement.py`.
- No scheduler: the 30-day cadence stays the library method `due()`; wiring it to a
  cron / MCP trigger is a later deploy hook.
- No autonomous architecture change — proposal-only, by design.

## Tests
`test_self_audit.py` (inward) and `test_frontier_feed.py` (outward), stdlib +
`unittest.mock`, all offline (stub `http_get`, stub oracle/prober):
- tool currency flags outdated + missing; arsenal integrity flags broken;
- verdict rolls up ATTENTION / UPDATES_AVAILABLE / CURRENT correctly;
- `apply_tool_updates` respects never / ask-denied / ask-approved / auto **and
  never touches the modernize backlog** (safety-line regression test);
- `due()` cadence: no last-run ⇒ due; recent ⇒ not due; old ⇒ due;
- `for_halo` maps the registry to binaries and skips internal tools;
- registry fully classified (drift guard);
- `ModuleHealthProbe` reports a bad module name as unhealthy, real modules as healthy;
- `GitHubReleasesSource` emits an advance for a newer tag / missing watchlist tool
  (stub `http_get` returns canned release JSON);
- `ModelsEndpointSource` emits advances for unknown model ids;
- `CuratedSource` always returns its list;
- `PublicFrontierFeed.advances()` survives a source that raises (offline) and still
  returns the curated items;
- no `DeprecationWarning` under `-W error`.

## Verification
```
python3 -m venv /tmp/v && /tmp/v/bin/pip install -r requirements.txt \
  && /tmp/v/bin/python -m unittest discover -p 'test_*.py' \
  && /tmp/v/bin/python -W error::DeprecationWarning -m unittest discover -p 'test_*.py'
```
Both runs green; suite count rises above the current 41.

---
*Not affiliated with Google LLC. For authorized security testing on systems you
own or have written permission to test.*
