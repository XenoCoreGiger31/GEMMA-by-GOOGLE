#!/usr/bin/env python3
"""
continuous_scanner.py — attack-surface monitor for HALO. (SHELF / DORMANT)

Not imported by the running harness. Staged per shelf/halo-nextgen/04_attacksurface.md
and 05_TTP_CHAIN_VALIDATION.md (the BAS / re-validate cadence).

What it does when deployed:
  * sweeps the ports of every asset in attacksurface.md,
  * diffs against the last snapshot (a NEW open port / vanished service / cert
    nearing expiry is a change to investigate),
  * emits change events, and hands each finding to the TTP-validation loop
    (ttp_chain.py) to answer "is this exploitable HERE, given our controls?"
    rather than just "a scanner flagged it."

Design constraints, matching the rest of the shelf:
  * stdlib-only for the built-in probe (a TCP-connect sweep) so it runs anywhere;
  * a pluggable `PortProbe` interface so the real deployment swaps in HALO's
    masscan/nmap tools (via the tool server) without changing the loop;
  * AUTHORIZATION-GATED: it refuses to scan anything not in the inventory, and
    respects the autonomy policy (recon = auto; anything active is out of scope
    for this module — that belongs to the agent loop under gating).

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
        return (expires - _dt.datetime.utcnow()).days
    except Exception:
        return None


class ContinuousScanner:
    def __init__(self, probe: PortProbe | None = None,
                 authorized_hosts: set[str] | None = None,
                 on_event: Callable[[dict], None] | None = None):
        self.probe = probe or TCPConnectProbe()
        # AUTHORIZATION GATE: only hosts explicitly in scope are scannable.
        self.authorized_hosts = authorized_hosts or set()
        self.on_event = on_event or (lambda e: print(json.dumps(e)))

    def _authorized(self, host: str) -> bool:
        return host in self.authorized_hosts

    def scan_host(self, host: str, ports: Iterable[int] | None = None) -> ScanResult:
        if not self._authorized(host):
            raise PermissionError(
                f"{host} is not in the authorized inventory — refusing to scan. "
                "Add it to attacksurface.md and the authorized set first."
            )
        ports = list(ports or DEFAULT_PORTS)
        found = self.probe.open_ports(host, ports)
        res = ScanResult(host=host, open_ports=sorted(found),
                         scanned_at=_dt.datetime.utcnow().isoformat() + "Z")
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

    def sweep(self, prior: dict[str, ScanResult] | None = None) -> dict[str, ScanResult]:
        """One cadence tick over all authorized hosts. Returns fresh snapshots."""
        prior = prior or {}
        fresh: dict[str, ScanResult] = {}
        for host in sorted(self.authorized_hosts):
            curr = self.scan_host(host)
            self.diff_snapshot(host, prior.get(host), curr)
            fresh[host] = curr
        return fresh


if __name__ == "__main__":
    # Localhost demo (authorized). Safe: only touches 127.0.0.1.
    scanner = ContinuousScanner(authorized_hosts={"127.0.0.1"})
    snap = scanner.sweep()
    for host, res in snap.items():
        print("snapshot:", res.as_dict())
