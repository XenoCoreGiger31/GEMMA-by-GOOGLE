# Phase 04 — Attack Surface Management (graduation + engagement wiring)

**Status:** approved design, pre-implementation
**Design docs:** `halo-nextgen/04_attacksurface.md`
**Modules graduating:** `halo-nextgen/src/continuous_scanner.py`, `halo-nextgen/src/asm_inventory.py`

## Goal

Graduate the two attack-surface modules from `halo-nextgen/src/` to the repo root
and integrate them with the existing engagement safety spine, so the scanner's
authorization is single-sourced from `engagement.py` rather than a private set.

Nothing in the agent tool loop (`halo_tools.py`, `agent_loop.py`) changes this
phase; the engagement spine is consumed, not modified.

## Core design decision

The scanner currently overloads one `authorized_hosts` set to mean two different
things. This phase splits them:

- **What to scan** comes from the **inventory** — `asm_inventory.parse(attacksurface.md)`
  yields the concrete host list.
- **What is authorized to be scanned** comes from the **engagement** —
  `engagement.ScopeGuard.in_scope(host)` is the single authorization authority
  (and is CIDR-aware, unlike the old flat-set membership check).

## Component changes

### `continuous_scanner.py` (graduated to root)
- Constructor accepts `in_scope: Callable[[str], bool]` in place of
  `authorized_hosts: set[str]`. Default `lambda host: False` — deny-all, so an
  unconfigured scanner scans nothing (preserves the current safe default).
- `scan_host()` gates on `self.in_scope(host)`; a refused host raises
  `PermissionError` as today. Now CIDR-aware via the engagement ScopeGuard.
- `sweep(hosts, prior=None)` takes an explicit iterable of hosts to sweep, fed
  from the inventory. Each host is authorized through `in_scope`; out-of-scope
  hosts are skipped with an emitted `out_of_scope` event rather than crashing the
  sweep.
- New convenience constructor `ContinuousScanner.for_engagement(engagement, probe=None, on_event=None)`
  that wires `engagement.scope.in_scope` in one line.
- Replace both deprecated `datetime.utcnow()` calls (cert expiry math and
  `scanned_at`) with timezone-aware `datetime.now(timezone.utc)`, matching the
  repo cleanup at commit a6b572e. Suite must stay clean under
  `-W error::DeprecationWarning`.

### `asm_inventory.py` (graduated to root)
- Moves as-is (already pure stdlib, already parses the Markdown pipe-table).
- Reads/writes a root-level `attacksurface.md`.

### `attacksurface.md` (new, at repo root)
- The working inventory file the modules read/write. Contains the header row,
  the column separator, and the three seed template rows (`AS-0001..0003`) that
  `asm_inventory.parse()` already skips. Sourced from the template in
  `halo-nextgen/04_attacksurface.md`.

### `test_attack_surface.py` (new, at repo root)
Written first (TDD). Covers:
- inventory `parse()` skips the separator, template placeholder, and seed rows;
- inventory `parse()` extracts a real asset row;
- `diff()` detects `ports_opened`, `removed`, and `tech_drift` events;
- scanner refuses an out-of-scope host (`PermissionError`);
- scanner accepts an in-scope host via a stub `PortProbe` (no real network);
- a CIDR scope authorizes a contained IP address;
- `for_engagement()` wires the engagement scope so its `in_scope` governs scans;
- `sweep()` skips out-of-scope hosts with an `out_of_scope` event and scans the rest;
- no `DeprecationWarning` is raised (guarded by `-W error::DeprecationWarning` in CI run).

## Data flow

```
attacksurface.md ──asm_inventory.parse──▶ [Asset,…] ──host list──▶ ContinuousScanner.sweep
                                                                          │
engagement scope ──ScopeGuard.in_scope──────────authorizes each host─────┘
                                                                          ▼
                                     ScanResult + change events
                                     (port_opened → "hand to ttp_chain.validate" marker)
```

## Explicit non-goals (boundaries held this phase)
- No registration in `halo_tools.py` `TOOLS` / `ToolExecutor._DISPATCH` — the
  agent tool loop is untouched.
- No changes to `agent_loop.py`.
- No changes to `engagement.py` — it is imported, not edited.
- The `ttp_chain` handoff remains a string marker inside the change event.
  Actually invoking `ttp_chain.validate` is Phase 05 work.

## Verification
Run in a venv (system python lacks deps):
```
python3 -m venv /tmp/v && /tmp/v/bin/pip install -r requirements.txt \
  && /tmp/v/bin/python -m unittest discover -p 'test_*.py' \
  && /tmp/v/bin/python -W error::DeprecationWarning -m unittest discover -p 'test_*.py'
```
Both runs green. New tests raise the suite count above the current 28.

---
*Not affiliated with Google LLC. For authorized security testing on systems you
own or have written permission to test.*
