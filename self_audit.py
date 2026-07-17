#!/usr/bin/env python3
"""
self_audit.py — HALO's inward eye: self-audit & anti-obsolescence.

Implements the self-audit schedule specified in 07_SELF_AUDIT.md.

On a schedule (default ~30 days, once the MCP server is running) HALO turns its
eyes on ITSELF and answers: am I going stale, broken, or behind the frontier?
Four checks:

  1. Tool currency   — Kali pushes UPGRADES to existing tools. Are mine behind?
  2. Arsenal integrity — did an upstream upgrade BREAK one of the 29 tools?
  3. Framework currency — what have Anthropic / DeepSeek / OpenAI shipped that
     HALO's architecture hasn't adopted? -> a prioritized "modernize me" backlog.
  4. Self health     — do my own modules still import / pass their self-tests?

SAFETY LINE (deliberate): tool updates are an ACTION, gated by the autonomy
policy (auto/ask/never). Architecture changes are ALWAYS proposal-only — HALO
NEVER autonomously rewrites its own framework. A security agent that silently
re-architects itself is a liability, not a feature.

Everything external (package versions, tool probes, frontier feed) is INJECTED,
so this runs and is testable offline. Pure stdlib.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Protocol


def _utc_now() -> _dt.datetime:
    """Naive-UTC now, matching the repo timestamp convention."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _ver_tuple(v: str | None) -> tuple:
    if not v:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


# HALO exposes 29 wrapper tools (halo_tools.SUPPORTED_TOOLS). The self-audit checks
# currency (dpkg/apt) and smoke-tests the underlying Kali BINARY, so map each
# wrapper to its binary. INTERNAL_TOOLS have no external package (shell exec, file
# I/O, the sandbox exploit runner) and are intentionally excluded. A test asserts
# HALO_TOOL_BINARIES ∪ INTERNAL_TOOLS == SUPPORTED_TOOLS, so a newly added tool
# fails the suite until it is classified here.
HALO_TOOL_BINARIES = {
    "run_masscan": "masscan", "run_nmap": "nmap", "run_netstat": "netstat",
    "run_sqlmap": "sqlmap", "run_nikto": "nikto", "run_wafw00f": "wafw00f",
    "run_shodan": "shodan", "run_phoneinfoga": "phoneinfoga",
    "run_cloudfox": "cloudfox", "run_hydra": "hydra", "run_john": "john",
    "run_ncrack": "ncrack", "run_medusa": "medusa",
    "run_searchsploit": "searchsploit", "run_curl": "curl", "run_wget": "wget",
    "run_gobuster": "gobuster", "run_ffuf": "ffuf", "run_enum4linux": "enum4linux",
    "run_setoolkit": "setoolkit", "run_subfinder": "subfinder",
    "run_nuclei": "nuclei", "run_katana": "katana", "run_httpx": "httpx",
    "run_sherlock": "sherlock",
}
INTERNAL_TOOLS = {"run_command", "run_exploit", "write_file", "read_file"}


# --------------------------------------------------------- 1) tool currency ---
class PackageOracle(Protocol):
    """Supplies installed vs latest-available versions. Real impl shells
    dpkg-query / apt-cache / `<tool> --version`; offline it's stubbed."""
    def installed(self, tool: str) -> str | None: ...
    def latest(self, tool: str) -> str | None: ...


@dataclass
class ToolStatus:
    tool: str
    installed: str | None
    latest: str | None
    outdated: bool
    missing: bool


def check_tool_currency(tools: list[str], oracle: PackageOracle) -> list[ToolStatus]:
    out = []
    for t in tools:
        inst, lat = oracle.installed(t), oracle.latest(t)
        out.append(ToolStatus(
            tool=t, installed=inst, latest=lat,
            missing=inst is None,
            outdated=bool(inst and lat and _ver_tuple(inst) < _ver_tuple(lat)),
        ))
    return out


# ------------------------------------------------------ 2) arsenal integrity ---
class Prober(Protocol):
    """Returns True if a tool still runs (e.g. `<tool> --version` exits clean)."""
    def probe(self, tool: str) -> bool: ...


def check_arsenal_integrity(tools: list[str], prober: Prober) -> list[str]:
    """Return the list of tools that FAILED their smoke test (broken by an
    upgrade, missing, etc.) — catch it before an engagement, not during."""
    return [t for t in tools if not prober.probe(t)]


# ---------------------------------------------------- 3) framework currency ---
@dataclass
class FrontierAdvance:
    source: str        # "Anthropic" | "DeepSeek" | "OpenAI" | "MITRE" | ...
    item: str          # e.g. "adaptive thinking", "tool-search", "R1-distill decider"
    halo_has: bool     # does HALO already use/adopt this?
    priority: str = "medium"


class FrontierFeed(Protocol):
    """Supplies recent notable advances. Real impl fetches changelogs / release
    notes when online; offline it's a static list the operator maintains."""
    def advances(self) -> list[FrontierAdvance]: ...


def framework_backlog(feed: FrontierFeed) -> list[FrontierAdvance]:
    """The modernize-me backlog: advances HALO has NOT yet adopted. Proposal-only
    — surfaced to the operator, never auto-applied."""
    return [a for a in feed.advances() if not a.halo_has]


# ------------------------------------------------------------- 4) self health ---
class HealthProbe(Protocol):
    def check(self) -> dict: ...   # {"module": ok_bool, ...}


class ModuleHealthProbe:
    """Real HealthProbe: confirms HALO's own core modules still import. A module
    that fails to import (a broken graduation, a bad edit) surfaces as unhealthy
    and drives the verdict to ATTENTION before it bites during an engagement."""

    DEFAULT_MODULES = [
        "engagement", "halo_tools", "ttp_chain", "prompt_injection_guard",
        "continuous_scanner", "asm_inventory", "tiered_memory",
        "introspection_audit", "frontier_feed", "debug_mode", "security_report",
        "exploit_authoring",
    ]

    def __init__(self, modules: list[str] | None = None):
        self.modules = modules or list(self.DEFAULT_MODULES)

    def check(self) -> dict:
        import importlib
        result: dict[str, bool] = {}
        for name in self.modules:
            try:
                importlib.import_module(name)
                result[name] = True
            except Exception:
                result[name] = False
        return result


# --------------------------------------------------------------- the report ---
@dataclass
class SelfAuditReport:
    ran_at: str = field(default_factory=lambda: _utc_now().isoformat() + "Z")
    outdated_tools: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)
    broken_tools: list[str] = field(default_factory=list)
    modernize_backlog: list[dict] = field(default_factory=list)
    unhealthy_modules: list[str] = field(default_factory=list)

    def verdict(self) -> str:
        if self.broken_tools or self.missing_tools or self.unhealthy_modules:
            return "ATTENTION"          # something is broken now
        if self.outdated_tools or self.modernize_backlog:
            return "UPDATES_AVAILABLE"  # not broken, but falling behind
        return "CURRENT"

    def as_dict(self) -> dict:
        return {"ran_at": self.ran_at, "verdict": self.verdict(),
                "outdated_tools": self.outdated_tools,
                "missing_tools": self.missing_tools,
                "broken_tools": self.broken_tools,
                "unhealthy_modules": self.unhealthy_modules,
                "modernize_backlog": self.modernize_backlog}


class SelfAuditor:
    def __init__(self, tools: list[str], package_oracle: PackageOracle,
                 prober: Prober, frontier: FrontierFeed,
                 health: HealthProbe | None = None,
                 update_autonomy: str = "ask",   # auto | ask | never (tool updates)
                 approver=None, log=print):
        self.tools = tools
        self.oracle = package_oracle
        self.prober = prober
        self.frontier = frontier
        self.health = health
        self.update_autonomy = update_autonomy
        self.approver = approver or (lambda tool: False)
        self.log = log

    @classmethod
    def for_halo(cls, package_oracle: PackageOracle, prober: Prober,
                 frontier: FrontierFeed | None = None,
                 health: "HealthProbe | None" = None,
                 update_autonomy: str = "ask", approver=None, log=print) -> "SelfAuditor":
        """Wire the audit to HALO's real arsenal and modules: the tool list comes
        from the live halo_tools registry (mapped to Kali binaries, internal tools
        skipped), health defaults to the real ModuleHealthProbe, and frontier
        defaults to an offline-safe curated feed when none is supplied."""
        import halo_tools
        tools = [HALO_TOOL_BINARIES[t] for t in halo_tools.SUPPORTED_TOOLS
                 if t in HALO_TOOL_BINARIES]
        if frontier is None:
            from frontier_feed import PublicFrontierFeed
            frontier = PublicFrontierFeed.curated_only()
        return cls(tools, package_oracle, prober, frontier,
                   health=health or ModuleHealthProbe(),
                   update_autonomy=update_autonomy, approver=approver, log=log)

    @staticmethod
    def due(last_run: str | None, interval_days: int = 30) -> bool:
        if not last_run:
            return True
        try:
            last = _dt.datetime.fromisoformat(last_run.replace("Z", ""))
        except ValueError:
            return True
        return (_utc_now() - last).days >= interval_days

    def run(self) -> SelfAuditReport:
        rep = SelfAuditReport()
        for st in check_tool_currency(self.tools, self.oracle):
            if st.missing:
                rep.missing_tools.append(st.tool)
            elif st.outdated:
                rep.outdated_tools.append(st.tool)
        rep.broken_tools = check_arsenal_integrity(self.tools, self.prober)
        rep.modernize_backlog = [a.__dict__ for a in framework_backlog(self.frontier)]
        if self.health:
            rep.unhealthy_modules = [m for m, ok in self.health.check().items() if not ok]
        self.log(f"[SELF-AUDIT] verdict={rep.verdict()} "
                 f"outdated={rep.outdated_tools} broken={rep.broken_tools} "
                 f"backlog={len(rep.modernize_backlog)}")
        return rep

    def apply_tool_updates(self, report: SelfAuditReport,
                           updater=None) -> list[str]:
        """Auto-update TOOLS only, under the autonomy policy. Architecture items
        are never touched here — they stay in the backlog for the operator."""
        if self.update_autonomy == "never":
            self.log("[SELF-AUDIT] tool auto-update disabled (never)")
            return []
        updater = updater or (lambda tool: True)
        updated = []
        for tool in report.outdated_tools + report.missing_tools:
            if self.update_autonomy == "ask" and not self.approver(tool):
                self.log(f"[SELF-AUDIT] update {tool}: denied")
                continue
            if updater(tool):
                updated.append(tool)
                self.log(f"[SELF-AUDIT] updated {tool}")
        return updated


if __name__ == "__main__":
    tools = ["nmap", "sqlmap", "nuclei", "hydra"]

    class StubOracle:  # nuclei is behind; hydra missing
        _inst = {"nmap": "7.94", "sqlmap": "1.8.2", "nuclei": "3.1.0", "hydra": None}
        _lat = {"nmap": "7.94", "sqlmap": "1.8.2", "nuclei": "3.3.0", "hydra": "9.5"}
        def installed(self, t): return self._inst.get(t)
        def latest(self, t): return self._lat.get(t)

    class StubProber:  # sqlmap broke after an upgrade
        def probe(self, t): return t != "sqlmap"

    class StubFrontier:
        def advances(self):
            return [
                FrontierAdvance("Anthropic", "adaptive thinking / effort", halo_has=False, priority="high"),
                FrontierAdvance("DeepSeek", "R1-distill local decider", halo_has=False, priority="high"),
                FrontierAdvance("OpenAI", "structured tool-call schemas", halo_has=True),
                FrontierAdvance("MITRE", "latest ATT&CK techniques", halo_has=False, priority="medium"),
            ]

    auditor = SelfAuditor(tools, StubOracle(), StubProber(), StubFrontier(),
                          update_autonomy="ask", approver=lambda t: True)
    if SelfAuditor.due(last_run=None):
        report = auditor.run()
        import json
        print(json.dumps(report.as_dict(), indent=2))
        print("applied tool updates:", auditor.apply_tool_updates(report))
