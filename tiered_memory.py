#!/usr/bin/env python3
"""
tiered_memory.py — Phase 2: the read/write memory loop for HALO.

Implements the read/write memory loop specified in 01_HARNESS_OPTIMIZATION.md §C2.

This is the "better memory" upgrade over agent_cache.NegativeCache. Two objects:

  CaseFile      — per-engagement, READ at the top of every model call and WRITTEN
                  after every validated step. Stops the harness from re-deriving
                  the target's state on each turn (the re-derivation tax, 01 A2.4).
                  This is the session-log half of "Phase 1+2".

  TieredMemory  — cross-session, THREE tiers instead of negative-only:
                    * negative      — tool calls that failed  -> skip / de-prioritize
                    * positive      — tool calls that produced VALIDATED findings
                                      -> prefer / try first   (NEW: agent_cache
                                      deletes successes; we PROMOTE them)
                    * environmental — which control broke which technique on which
                                      target-class -> the exploitability evidence the
                                      TTP loop (ttp_chain.py) consumes.

Same fingerprint mechanism as agent_cache._fingerprint so it stays compatible.
Pure stdlib; persists to JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import datetime as _dt
from dataclasses import dataclass, field, asdict


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def fingerprint(step: dict) -> str:
    """Stable hash of a tool call (compatible with agent_cache._fingerprint)."""
    relevant = {k: v for k, v in step.items() if k != "_meta"}
    canonical = json.dumps(relevant, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ------------------------------------------------------------------ CaseFile ---
@dataclass
class CaseFile:
    """Per-engagement working state. Read before each model call, written after
    each validated step. Persisted so an engagement survives a restart."""
    session_id: str
    target: str = ""
    created_at: str = field(default_factory=_now)
    open_ports: list[int] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)         # "port" -> service
    findings: list[dict] = field(default_factory=list)            # evidence-backed
    techniques_tried: list[str] = field(default_factory=list)
    controls_observed: dict[str, list[str]] = field(default_factory=dict)  # asset->controls
    notes: list[str] = field(default_factory=list)

    # ---- read/write ----
    def add_ports(self, ports: list[int]) -> None:
        for p in ports:
            if p not in self.open_ports:
                self.open_ports.append(int(p))

    def add_service(self, port: int, service: str) -> None:
        self.services[str(port)] = service

    def add_finding(self, port: int, tool: str, evidence: str,
                    exploitable_here: bool | None = None) -> None:
        self.findings.append({
            "port": port, "tool": tool, "evidence": evidence[:2000],
            "exploitable_here": exploitable_here, "ts": _now(),
        })

    def mark_technique(self, technique: str) -> None:
        if technique not in self.techniques_tried:
            self.techniques_tried.append(technique)

    def observe_control(self, asset: str, control: str) -> None:
        self.controls_observed.setdefault(asset, [])
        if control not in self.controls_observed[asset]:
            self.controls_observed[asset].append(control)

    def summary_for_prompt(self) -> str:
        """Compact state the model reads at the top of every call — the thing that
        removes the re-derivation tax. Kept terse to protect context budget."""
        return json.dumps({
            "target": self.target,
            "open_ports": sorted(self.open_ports),
            "services": self.services,
            "findings": [{"port": f["port"], "tool": f["tool"],
                          "exploitable_here": f["exploitable_here"]}
                         for f in self.findings],
            "techniques_tried": self.techniques_tried,
            "controls_observed": self.controls_observed,
        }, sort_keys=True)

    # ---- persistence ----
    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "CaseFile":
        with open(path) as f:
            return cls(**json.load(f))


# --------------------------------------------------------------- TieredMemory ---
class TieredMemory:
    """Bi-directional, cross-session memory. Superset of agent_cache.NegativeCache."""

    def __init__(self, path: str | None = None):
        self.path = path
        self._neg: dict[str, dict] = {}
        self._pos: dict[str, dict] = {}
        self._env: dict[str, dict[str, str]] = {}   # target_class -> {technique: result}
        if path and os.path.exists(path):
            self._load()

    # ---- decision helpers the loop calls ----
    def should_attempt(self, step: dict) -> bool:
        """False iff this call is permanently blocked (negative tier)."""
        e = self._neg.get(fingerprint(step))
        return not (e and e.get("blocked"))

    def preference(self, step: dict) -> float:
        """>0 if this call has produced validated findings before (positive tier).
        The loop uses this to try proven-good approaches first."""
        e = self._pos.get(fingerprint(step))
        return float(e["successes"]) if e else 0.0

    def control_outcome(self, target_class: str, technique: str) -> str | None:
        """What a control did to this technique here before — feeds ttp_chain."""
        return self._env.get(target_class, {}).get(technique)

    # ---- writers ----
    def record_failure(self, step: dict, reason: str = "") -> None:
        fp = fingerprint(step)
        e = self._neg.setdefault(fp, {"tool": step.get("tool"), "attempts": 0,
                                       "blocked": False, "reason": reason,
                                       "first_seen": _now()})
        e["attempts"] += 1
        e["reason"] = reason or e["reason"]
        e["last_seen"] = _now()
        if e["attempts"] >= 2:
            e["blocked"] = True
        self._save()

    def record_success(self, step: dict, evidence: str = "") -> None:
        """PROMOTE to positive tier (agent_cache deletes; we keep and prefer)."""
        fp = fingerprint(step)
        e = self._pos.setdefault(fp, {"tool": step.get("tool"), "successes": 0,
                                      "first_seen": _now(), "evidence": ""})
        e["successes"] += 1
        e["evidence"] = evidence[:500] or e["evidence"]
        e["last_seen"] = _now()
        # A now-proven approach is no longer a dead end.
        self._neg.pop(fp, None)
        self._save()

    def observe_control_outcome(self, target_class: str, technique: str,
                                result: str) -> None:
        self._env.setdefault(target_class, {})[technique] = result
        self._save()

    # ---- stats / persistence ----
    def stats(self) -> dict:
        return {"negative": len(self._neg), "positive": len(self._pos),
                "environmental": sum(len(v) for v in self._env.values())}

    def _save(self) -> None:
        if not self.path:
            return
        with open(self.path, "w") as f:
            json.dump({"negative": self._neg, "positive": self._pos,
                       "environmental": self._env}, f, indent=2)

    def _load(self) -> None:
        with open(self.path) as f:
            d = json.load(f)
        self._neg = d.get("negative", {})
        self._pos = d.get("positive", {})
        self._env = d.get("environmental", {})


if __name__ == "__main__":
    cf = CaseFile(session_id="demo", target="10.0.0.5")
    cf.add_ports([22, 80, 445])
    cf.add_service(445, "smb")
    cf.add_finding(445, "run_enum4linux", "null session allowed; users enumerated",
                   exploitable_here=True)
    print("case file summary:", cf.summary_for_prompt())

    mem = TieredMemory()
    step = {"tool": "run_hydra", "target": "10.0.0.5", "service": "ssh"}
    mem.record_failure(step, "empty output"); mem.record_failure(step, "empty output")
    print("should_attempt after 2 fails:", mem.should_attempt(step))
    good = {"tool": "run_enum4linux", "target": "10.0.0.5"}
    mem.record_success(good, "null session -> user list")
    print("preference for proven-good:", mem.preference(good))
    mem.observe_control_outcome("windows-host", "T1003", "blocked")
    print("control outcome:", mem.control_outcome("windows-host", "T1003"))
    print("stats:", mem.stats())
