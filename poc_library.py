#!/usr/bin/env python3
"""poc_library.py — curated, deterministic exploits keyed by port/service.

WHY THIS EXISTS
    The live loop's ``run_exploit`` asked the 12B to author a full socket-level
    exploit inline, one-shot, no refine loop (agent_loop.py:139). For canonical
    backdoors that is pure waste: the exploit is public, tiny, and 100%
    deterministic, but a 12B fumbles it and the attack phase fails — so nothing
    ever bit. This library hands the sandbox a *known-good* PoC instead of a
    blank page. The 12B still drives target selection and everything non-curated;
    it just no longer has to reinvent the vsftpd backdoor from memory.

CONTRACT
    ``select_poc(port, service_hint)`` returns ``(key, code)`` or ``None``. The
    ``code`` is the verbatim source of a module under ``pocs/`` — the exact bytes
    the sandbox ``run_exploit`` runner executes and the test suite exercises, so
    "tested" and "shipped" are the same thing. Selection is deterministic: a port
    match plus a service-hint regex. If nothing matches, return None and the loop
    falls back to the model-authored path, unchanged.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

_POC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pocs")
_DELIVERY_MODULE = "_delivery.py"

# A `from pocs._delivery import ...` (or any other `from pocs...`) line, and a
# `from __future__ import ...` line. Both are stripped from the two source bodies
# before bundling; the future statement is re-emitted once, at the very top.
_SIBLING_IMPORT_RE = re.compile(r"^\s*from\s+pocs\b.*$")
_FUTURE_IMPORT_RE = re.compile(r"^\s*from\s+__future__\s+import\s+(?P<names>.+?)\s*$")


def _bundle(poc_source: str, delivery_source: str) -> str:
    """Inline the shared delivery primitive into a PoC so it runs self-contained.

    The sandbox mounts a lone temp `.py` with the repo NOT on the path, so a PoC's
    `from pocs._delivery import ...` explodes with ModuleNotFoundError. This fixes
    that at ship time (not by touching the sandbox): the full `_delivery.py` body is
    inlined ahead of the PoC body, the sibling import is dropped, and exactly one
    `from __future__` statement is hoisted to the very first line (a future statement
    must precede all other code). Ordinary duplicate imports (os, socket, ...) are
    left as-is — harmless in Python; only `from __future__` must be singular + first.
    Pure and stdlib-only.
    """
    future_names: set[str] = set()

    def _strip(source: str) -> str:
        kept: list[str] = []
        for line in source.splitlines():
            if _SIBLING_IMPORT_RE.match(line):
                continue
            m = _FUTURE_IMPORT_RE.match(line)
            if m:
                for name in m.group("names").split(","):
                    name = name.strip()
                    if name:
                        future_names.add(name)
                continue
            kept.append(line)
        return "\n".join(kept)

    delivery_body = _strip(delivery_source)
    poc_body = _strip(poc_source)
    # In practice only `annotations` is ever used; union defensively so nothing a
    # future line imported is silently dropped, and guarantee at least `annotations`.
    future_names.add("annotations")
    future_line = "from __future__ import " + ", ".join(sorted(future_names))
    return f"{future_line}\n\n{delivery_body}\n\n{poc_body}"


@dataclass(frozen=True)
class PoCEntry:
    key: str
    module: str            # filename under pocs/
    ports: frozenset       # ports this PoC applies to (as strings)
    service_re: re.Pattern  # must also match the service hint (case-insensitive)

    def code(self) -> str:
        """Self-contained single-file source for the sandbox: the PoC body with the
        shared pocs/_delivery.py primitive inlined (see _bundle). The repo stays DRY
        — devs still edit _delivery.py once — while the shipped file needs no `pocs`
        package at runtime."""
        with open(os.path.join(_POC_DIR, self.module), encoding="utf-8") as f:
            poc_source = f.read()
        with open(os.path.join(_POC_DIR, _DELIVERY_MODULE), encoding="utf-8") as f:
            delivery_source = f.read()
        return _bundle(poc_source, delivery_source)


# Order matters only if ports overlap; today they don't.
KNOWN_POCS: list[PoCEntry] = [
    PoCEntry(
        key="vsftpd_2_3_4_backdoor",
        module="vsftpd_2_3_4_backdoor.py",
        ports=frozenset({"21"}),
        service_re=re.compile(r"vsftpd|ftp|\b2\.3\.4\b", re.I),
    ),
    PoCEntry(
        key="ingreslock_1524_bindshell",
        module="ingreslock_1524_bindshell.py",
        ports=frozenset({"1524"}),
        # An unknown/empty hint still matches on port (recon gaps mustn't silence a
        # known root bind shell); a positive hint just adds confidence.
        service_re=re.compile(r"ingreslock|bind\s*shell|shell|metasploit", re.I),
    ),
    PoCEntry(
        key="unrealircd_3281_backdoor",
        module="unrealircd_3281_backdoor.py",
        ports=frozenset({"6667"}),
        service_re=re.compile(r"unreal|ircd?|3\.2\.8\.1|chat", re.I),
    ),
]


def select_poc(port, service_hint: str = "") -> tuple[str, str] | None:
    """Return (key, code) for a curated PoC matching this port+service, else None.

    Matching is deterministic and fail-closed: BOTH the port and the service-hint
    regex must match. A port alone is not enough (so a non-FTP service that
    happens to sit on 21 won't get the vsftpd PoC if the hint disagrees), but an
    empty/unknown hint still matches on port so recon gaps don't silence a known
    box. The regex is written to accept the FTP hint HALO emits for port 21.
    """
    port = str(port)
    hint = service_hint or ""
    for entry in KNOWN_POCS:
        if port in entry.ports and (not hint or entry.service_re.search(hint)):
            return entry.key, entry.code()
    return None
