#!/usr/bin/env python3
"""
ttp_chain.py — TTP-chain validation engine for HALO. (SHELF / DORMANT)

Not imported by the running harness. Staged per halo-nextgen/05_TTP_CHAIN_VALIDATION.md.

The rocket principle: you can't always fire the live exploit (production /
air-gapped / one-of-a-kind assets, or brand-new CVEs nobody has weaponized). So
you prove each COMPONENT technique on the ground against the controls actually
deployed. Decompose an exposure into its chain of techniques; validate each
required link against the environment's controls. If the environment breaks any
required link, the exposure is NOT exploitable here — and you know that, with
evidence, without launching.

The loop:  VALIDATE -> DECIDE -> FIX -> RE-VALIDATE
  * validate: test each technique in the chain against deployed controls
  * decide:   exploitable-here iff every REQUIRED technique passes
  * fix:      emit a structured finding (evidence + chain of custody attached)
              for a ticketing adapter (Jira/ServiceNow — not built here)
  * re-validate: re-run after remediation / control drift (BAS)

This is an ORCHESTRATION layer over existing HALO capability — "orchestrate,
don't sprawl." It reuses the arsenal to exercise techniques; it does not add
scanners. Tunable autonomy + chain of custody per Gartner's caution.

Pure stdlib. The control-validation is pluggable: `ControlOracle` decides whether
a given control breaks a given technique, sourced from attacksurface.md, observed
probes, and HALO's environmental memory tier (see 01 §C2).
"""

from __future__ import annotations

import datetime as _dt
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Protocol


class Autonomy(str, Enum):
    AUTO = "auto"     # passive technique checks
    ASK = "ask"       # exercises an exploit primitive — human approval
    NEVER = "never"   # not permitted


class Result(str, Enum):
    PASS = "pass"           # technique would succeed (link intact for the attacker)
    BLOCKED = "blocked"     # a deployed control breaks this link
    UNKNOWN = "unknown"     # couldn't validate (insufficient evidence)


@dataclass
class Technique:
    id: str                 # e.g. "T1110" (ATT&CK-style)
    name: str
    tactic: str             # e.g. "credential-access"
    exercised_by: str       # which HALO tool/action exercises it (reuse arsenal)
    broken_by: list[str]    # controls that would block it (LSASS protection, EDR, ...)
    autonomy: Autonomy = Autonomy.AUTO
    required: bool = True    # a broken REQUIRED link => not exploitable here


@dataclass
class ChainStep:
    technique: Technique
    result: Result = Result.UNKNOWN
    evidence: str = ""


@dataclass
class CustodyEntry:
    actor: str
    action: str
    detail: str
    ts: str = field(default_factory=lambda: _dt.datetime.utcnow().isoformat() + "Z")


@dataclass
class Finding:
    exposure: str                 # CVE id or exposure description
    asset: str
    exploitable_here: bool
    steps: list[ChainStep]
    custody: list[CustodyEntry]
    id: str = field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8]}")
    decided_at: str = field(default_factory=lambda: _dt.datetime.utcnow().isoformat() + "Z")

    def blocking_control(self) -> str | None:
        """Which required, blocked link makes this non-exploitable (if any)."""
        for s in self.steps:
            if s.technique.required and s.result == Result.BLOCKED:
                return ", ".join(s.technique.broken_by) or s.technique.name
        return None

    def as_ticket(self) -> dict:
        """Structured finding for a Jira/ServiceNow adapter (adapter not built —
        needs your instance + creds; see 05 §C4)."""
        return {
            "finding_id": self.id,
            "summary": (
                f"{self.exposure} on {self.asset}: "
                + ("EXPLOITABLE here" if self.exploitable_here
                   else f"NOT exploitable here (blocked by {self.blocking_control()})")
            ),
            "exposure": self.exposure,
            "asset": self.asset,
            "exploitable_here": self.exploitable_here,
            "chain": [
                {"technique": s.technique.id, "name": s.technique.name,
                 "result": s.result.value, "required": s.technique.required,
                 "evidence": s.evidence}
                for s in self.steps
            ],
            "chain_of_custody": [c.__dict__ for c in self.custody],
            "decided_at": self.decided_at,
        }


class ControlOracle(Protocol):
    """Decides whether a technique would succeed against an asset's controls.

    The real deployment backs this with: attacksurface.md (what's deployed),
    observed probe results (run the technique safely, watch the control), and
    HALO's environmental memory tier (what stopped this technique here before).
    """
    def validate(self, asset: str, technique: Technique) -> tuple[Result, str]: ...


class StaticControlOracle:
    """Reference oracle: an asset -> set-of-active-controls map. A technique is
    BLOCKED iff any of its `broken_by` controls is active on the asset."""

    def __init__(self, controls_by_asset: dict[str, set[str]]):
        self.controls = controls_by_asset

    def validate(self, asset: str, technique: Technique) -> tuple[Result, str]:
        active = self.controls.get(asset)
        if active is None:
            return Result.UNKNOWN, f"no control inventory for {asset}"
        blockers = active & set(technique.broken_by)
        if blockers:
            return Result.BLOCKED, f"blocked by active control(s): {sorted(blockers)}"
        return Result.PASS, f"no active control in {technique.broken_by} on {asset}"


# ------------------------------------------------------------------------------
# Starter technique catalog (DATA, grows over time — Bitter-Lesson friendly).
# A CVE decomposes into an ordered chain drawn from this catalog.
# ------------------------------------------------------------------------------
CATALOG: dict[str, Technique] = {
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "initial-access",
                       exercised_by="run_nuclei/run_sqlmap", broken_by=["WAF", "patched"]),
    "T1059": Technique("T1059", "Command/Scripting Execution", "execution",
                       exercised_by="run_exploit", broken_by=["app_allow_listing", "EDR"],
                       autonomy=Autonomy.ASK),
    "T1110": Technique("T1110", "Brute Force", "credential-access",
                       exercised_by="run_hydra", broken_by=["mfa", "lockout_policy"],
                       autonomy=Autonomy.ASK),
    "T1003": Technique("T1003", "OS Credential Dumping", "credential-access",
                       exercised_by="run_command", broken_by=["lsass_protection", "EDR"],
                       autonomy=Autonomy.ASK),
    "T1021": Technique("T1021", "Remote Services / Lateral Movement", "lateral-movement",
                       exercised_by="run_ncrack", broken_by=["network_segmentation", "firewall"],
                       autonomy=Autonomy.ASK),
    "PI-01": Technique("PI-01", "Prompt Injection Probe", "initial-access",
                       exercised_by="run_prompt_injection_probe",
                       broken_by=["input_trust_framing", "injection_judge"],
                       autonomy=Autonomy.ASK),
}


def decompose(cve: str, technique_ids: list[str],
              optional: set[str] | None = None) -> list[Technique]:
    """Map an exposure to its ordered required-technique chain from the catalog.

    A production version would derive this from the advisory + searchsploit/nuclei
    context; here the chain is supplied explicitly. `optional` marks non-required
    links (failing them means 'harder here', not 'safe')."""
    optional = optional or set()
    chain: list[Technique] = []
    for tid in technique_ids:
        base = CATALOG[tid]
        chain.append(Technique(**{**base.__dict__, "required": tid not in optional}))
    return chain


class TTPValidator:
    def __init__(self, oracle: ControlOracle,
                 autonomy_policy: dict[Autonomy, bool] | None = None,
                 approver: Callable[[Technique], bool] | None = None):
        self.oracle = oracle
        # Which autonomy classes may run without asking. ASK requires `approver`.
        self.policy = autonomy_policy or {Autonomy.AUTO: True, Autonomy.ASK: False,
                                          Autonomy.NEVER: False}
        self.approver = approver or (lambda t: False)

    def _permitted(self, t: Technique) -> bool:
        if t.autonomy == Autonomy.NEVER:
            return False
        if self.policy.get(t.autonomy, False):
            return True
        if t.autonomy == Autonomy.ASK:
            return self.approver(t)
        return False

    def validate(self, cve: str, asset: str, chain: list[Technique]) -> Finding:
        """VALIDATE + DECIDE. Returns a Finding with evidence + chain of custody."""
        custody = [CustodyEntry("ttp_chain", "validate_start", f"{cve} on {asset}")]
        steps: list[ChainStep] = []
        for t in chain:
            if not self._permitted(t):
                steps.append(ChainStep(t, Result.UNKNOWN,
                                       f"autonomy={t.autonomy.value}: not authorized to exercise"))
                custody.append(CustodyEntry("ttp_chain", "skip", f"{t.id} gated ({t.autonomy.value})"))
                continue
            result, evidence = self.oracle.validate(asset, t)
            steps.append(ChainStep(t, result, evidence))
            custody.append(CustodyEntry("ttp_chain", f"validate:{t.id}",
                                        f"{result.value} — {evidence}"))

        # DECIDE: exploitable-here iff every REQUIRED link PASSes.
        required = [s for s in steps if s.technique.required]
        exploitable = bool(required) and all(s.result == Result.PASS for s in required)
        custody.append(CustodyEntry("ttp_chain", "decide",
                                    f"exploitable_here={exploitable}"))
        return Finding(exposure=cve, asset=asset, exploitable_here=exploitable,
                       steps=steps, custody=custody)


if __name__ == "__main__":
    # Demo: a CVE whose exploit chain needs public-facing exploitation -> code
    # execution -> credential dumping. The asset has LSASS protection active,
    # which breaks a REQUIRED link => not exploitable here, proven on the ground.
    oracle = StaticControlOracle({
        "db-01": {"lsass_protection", "EDR"},   # controls active on this asset
        "web-07": set(),                        # no relevant controls
    })
    validator = TTPValidator(
        oracle,
        autonomy_policy={Autonomy.AUTO: True, Autonomy.ASK: True},  # demo: auto-approve ASK
    )
    chain = decompose("CVE-2026-DEMO", ["T1190", "T1059", "T1003"])
    for asset in ("db-01", "web-07"):
        f = validator.validate("CVE-2026-DEMO", asset, chain)
        print(json.dumps(f.as_ticket(), indent=2))
