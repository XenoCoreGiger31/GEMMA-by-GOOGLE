#!/usr/bin/env python3
"""
asm_inventory.py — structured read/write for attacksurface.md.

Implements the attack-surface inventory model specified in halo-nextgen/04_attacksurface.md.

attacksurface.md is the human-readable source of truth for the deployed-infra
audit (Screen 3). This module lets the continuous scanner treat the inventory
table as structured data: load assets, diff two snapshots (new port opened,
version drifted, service vanished, cert expiring), upsert results, and stamp
`Last audited`. Pure stdlib — it parses the Markdown pipe-table in place so the
file stays hand-editable.

An Asset carries the six standing audit questions from Screen 3 as fields.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, asdict, fields

# Columns in the attacksurface.md inventory table, in order.
COLUMNS = [
    "id", "name", "tech", "hosting", "auth", "deployed",
    "surface", "ports", "owner", "last_audited", "notes",
]


@dataclass
class Asset:
    id: str = ""
    name: str = ""
    tech: str = ""          # Q1: what tech + version
    hosting: str = ""       # Q2: self-hosted / third-party
    auth: str = ""          # Q3: how we auth in
    deployed: str = ""      # Q5: what we have deployed there
    surface: str = ""       # Q6: web? DB? API?
    ports: str = ""         # Q6: exposed ports/endpoints
    owner: str = ""
    last_audited: str = ""
    notes: str = ""         # Q4: known issues / misconfigs

    def key(self) -> str:
        return self.id or self.name

    def ports_set(self) -> set[str]:
        return {p.strip() for p in re.split(r"[,\s]+", self.ports) if p.strip()}


_ROW_RE = re.compile(r"^\|(.+)\|\s*$")


def _split_row(line: str) -> list[str] | None:
    m = _ROW_RE.match(line.strip())
    if not m:
        return None
    return [c.strip() for c in m.group(1).split("|")]


def parse(md_text: str) -> list[Asset]:
    """Extract Asset rows from the inventory table in attacksurface.md."""
    assets: list[Asset] = []
    in_table = False
    for line in md_text.splitlines():
        cells = _split_row(line)
        if not cells:
            in_table = False
            continue
        header = [c.lower() for c in cells]
        if not in_table:
            # Detect the inventory header row by its first two columns.
            if header[:2] == ["id", "asset / name"] or header[0] == "id":
                in_table = True
            continue
        # Skip the markdown separator row (|----|----|).
        if all(set(c) <= set("-: ") for c in cells):
            continue
        # Skip template placeholder rows (italic _..._ or empty).
        joined = "".join(cells).replace("_", "").strip()
        if not joined:
            continue
        row = dict(zip(COLUMNS, (cells + [""] * len(COLUMNS))[: len(COLUMNS)]))
        if row["id"].startswith("_") or row["id"].lower() in {"as-0001", "as-0002", "as-0003"}:
            continue  # seed/template rows
        assets.append(Asset(**row))
    return assets


def diff(old: list[Asset], new: list[Asset]) -> list[dict]:
    """Return change events between two inventory snapshots. Each event is a dict
    with type in {added, removed, ports_opened, ports_closed, tech_drift}."""
    events: list[dict] = []
    old_by = {a.key(): a for a in old}
    new_by = {a.key(): a for a in new}

    for k in new_by.keys() - old_by.keys():
        events.append({"type": "added", "asset": k, "detail": new_by[k].ports})
    for k in old_by.keys() - new_by.keys():
        events.append({"type": "removed", "asset": k})
    for k in old_by.keys() & new_by.keys():
        o, n = old_by[k], new_by[k]
        opened = n.ports_set() - o.ports_set()
        closed = o.ports_set() - n.ports_set()
        if opened:
            events.append({"type": "ports_opened", "asset": k, "detail": sorted(opened)})
        if closed:
            events.append({"type": "ports_closed", "asset": k, "detail": sorted(closed)})
        if o.tech and n.tech and o.tech != n.tech:
            events.append({"type": "tech_drift", "asset": k, "from": o.tech, "to": n.tech})
    return events


def stamp_audited(asset: Asset) -> Asset:
    asset.last_audited = _dt.date.today().isoformat()
    return asset


def to_row(asset: Asset) -> str:
    vals = [getattr(asset, f.name) or "" for f in fields(asset)]
    return "| " + " | ".join(vals) + " |"


def upsert_rows(md_text: str, assets: list[Asset]) -> str:
    """Append new asset rows to the inventory table (idempotent by key).

    Minimal, non-destructive: appends after the last existing table row. A fuller
    implementation would rewrite in place; kept simple so the file stays readable.
    """
    existing = {a.key() for a in parse(md_text)}
    additions = [to_row(a) for a in assets if a.key() not in existing]
    if not additions:
        return md_text
    lines = md_text.splitlines()
    # Find the last inventory table row and insert after it.
    last_idx = None
    for i, line in enumerate(lines):
        if _split_row(line):
            last_idx = i
    if last_idx is None:
        return md_text + "\n" + "\n".join(additions) + "\n"
    lines[last_idx + 1 : last_idx + 1] = additions
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    demo = """
| ID | Asset / name | Tech + version | Self-hosted / 3rd-party | Auth method | Deployed here | Web? DB? API? | Exposed ports/endpoints | Owner | Last audited | Notes / known issues |
|----|--------------|----------------|--------------------------|-------------|---------------|---------------|--------------------------|-------|--------------|----------------------|
| AS-0100 | api-gw | Kong 3.4 | self-hosted | mTLS | prod API | API | 443,8001 | ops | 2026-07-01 | admin 8001 exposed |
"""
    a = parse(demo)
    print("parsed:", [x.name for x in a])
    a2 = [Asset(id="AS-0100", name="api-gw", tech="Kong 3.4", ports="443")]
    print("diff:", diff(a, a2))
