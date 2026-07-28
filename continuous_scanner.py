#!/usr/bin/env python3
"""
continuous_scanner.py — attack-surface monitor for HALO.

Implements the attack-surface monitoring loop specified in halo-nextgen/04_attacksurface.md
and 05_TTP_CHAIN_VALIDATION.md (the BAS / re-validate cadence).

What it does:
  * sweeps the ports of every asset it is handed (the inventory from
    asm_inventory.py is the source of what to scan),
  * diffs against the last snapshot (a NEW open port / vanished service / cert
    nearing expiry is a change to investigate),
  * emits change events, and hands each finding to the TTP-validation loop
    (ttp_chain.py) to answer "is this exploitable HERE, given our controls?"
    rather than just "a scanner flagged it."

Design constraints, consistent across the next-gen components:
  * stdlib-only for the built-in probe (a TCP-connect sweep) so it runs anywhere;
  * a pluggable `PortProbe` interface so the real deployment swaps in HALO's
    masscan/nmap tools (via the tool server) without changing the loop;
  * AUTHORIZATION-GATED: authorization is single-sourced from the engagement
    safety spine. `for_engagement()` wires `engagement.ScopeGuard.in_scope`, so a
    host is scannable only if it is inside the authorized engagement scope
    (hosts and CIDRs alike). The default predicate denies everything.

It scans; it does not exploit. Exploitation decisions live in ttp_chain.py behind
the autonomy policy.
"""

from __future__ import annotations

import json
import socket
import ssl
import datetime as _dt
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

# Common ports worth a default sweep. Extend per environment.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

CERT_EXPIRY_WARN_DAYS = 21


def _utc_now() -> _dt.datetime:
    """Naive-UTC now, matching the repo timestamp convention."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


class PortProbe(Protocol):
    """Swap-in point: the real deployment uses HALO's masscan/nmap via the tool
    server. The built-in TCPConnectProbe is the stdlib fallback."""
    def open_ports(self, host: str, ports: Iterable[int]) -> set[int]: ...


class TCPConnectProbe:
    """Plain TCP-connect sweep. No raw sockets, no root needed."""

    def __init__(self, timeout: float = 1.0, workers: int = 64):
        self.timeout = timeout
        self.workers = workers

    def _one(self, host: str, port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return port
        except (OSError, socket.timeout):
            return None

    def open_ports(self, host: str, ports: Iterable[int]) -> set[int]:
        ports = list(ports)
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            results = ex.map(lambda p: self._one(host, p), ports)
        return {p for p in results if p is not None}


@dataclass
class ScanResult:
    host: str
    open_ports: list[int] = field(default_factory=list)
    tls_expiry_days: dict[int, int] = field(default_factory=dict)  # port -> days to expiry
    scanned_at: str = ""

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "open_ports": sorted(self.open_ports),
            "tls_expiry_days": self.tls_expiry_days,
            "scanned_at": self.scanned_at,
        }


def _tls_days_to_expiry(host: str, port: int, timeout: float = 3.0) -> int | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        if not cert or "notAfter" not in cert:
            return None
        expires = _dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (expires - _utc_now()).days
    except Exception:
        return None


class ContinuousScanner:
    def __init__(self, in_scope: Callable[[str], bool] | None = None,
                 probe: PortProbe | None = None,
                 on_event: Callable[[dict], None] | None = None):
        self.probe = probe or TCPConnectProbe()
        # AUTHORIZATION GATE: single-sourced from the engagement scope. The default
        # predicate denies everything, so an unconfigured scanner scans nothing.
        self.in_scope = in_scope or (lambda host: False)
        self.on_event = on_event or (lambda e: print(json.dumps(e)))

    @classmethod
    def for_engagement(cls, engagement, probe: PortProbe | None = None,
                       on_event: Callable[[dict], None] | None = None) -> "ContinuousScanner":
        """Wire authorization to the engagement safety spine's ScopeGuard, so a
        host is scannable only if it is inside the authorized engagement scope."""
        return cls(in_scope=engagement.scope.in_scope, probe=probe, on_event=on_event)

    def scan_host(self, host: str, ports: Iterable[int] | None = None) -> ScanResult:
        if not self.in_scope(host):
            raise PermissionError(
                f"{host} is not in the authorized engagement scope — refusing to scan. "
                "Add it to the engagement scope (and attacksurface.md) first."
            )
        ports = list(ports or DEFAULT_PORTS)
        found = self.probe.open_ports(host, ports)
        res = ScanResult(host=host, open_ports=sorted(found),
                         scanned_at=_utc_now().isoformat() + "Z")
        for p in (443, 8443, 993, 995):
            if p in found:
                days = _tls_days_to_expiry(host, p)
                if days is not None:
                    res.tls_expiry_days[p] = days
                    if days <= CERT_EXPIRY_WARN_DAYS:
                        self.on_event({"type": "cert_expiring", "host": host,
                                       "port": p, "days": days})
        return res

    def diff_snapshot(self, host: str, prev: ScanResult | None,
                      curr: ScanResult) -> list[dict]:
        """Emit change events between two scans of the same host."""
        events: list[dict] = []
        prev_ports = set(prev.open_ports) if prev else set()
        curr_ports = set(curr.open_ports)
        for p in sorted(curr_ports - prev_ports):
            events.append({"type": "port_opened", "host": host, "port": p,
                           "action": "hand to ttp_chain.validate"})
        for p in sorted(prev_ports - curr_ports):
            events.append({"type": "port_closed", "host": host, "port": p})
        for e in events:
            self.on_event(e)
        return events

    def sweep(self, hosts: Iterable[str],
              prior: dict[str, ScanResult] | None = None) -> dict[str, ScanResult]:
        """One cadence tick over the given hosts (typically the asm_inventory
        asset list). Each host is authorized through `in_scope`; out-of-scope
        hosts are skipped with an event rather than aborting the sweep. Returns
        fresh snapshots for the hosts that were scanned."""
        prior = prior or {}
        fresh: dict[str, ScanResult] = {}
        for host in hosts:
            if not self.in_scope(host):
                self.on_event({"type": "out_of_scope", "host": host,
                               "action": "skipped — not in authorized engagement"})
                continue
            curr = self.scan_host(host)
            self.diff_snapshot(host, prior.get(host), curr)
            fresh[host] = curr
        return fresh


if __name__ == "__main__":
    # Localhost demo (explicitly authorized). Safe: only touches 127.0.0.1.
    scanner = ContinuousScanner(in_scope=lambda h: h == "127.0.0.1")
    snap = scanner.sweep(["127.0.0.1"])
    for host, res in snap.items():
        print("snapshot:", res.as_dict())
