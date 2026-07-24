"""Generalized breach-delivery primitive for HALO curated PoCs.

Target-agnostic shell delivery + challenge-response (nonce) proof, shared by every
PoC under pocs/. Stdlib-socket only — runs unchanged in python:3.12-slim.

Trust model: the MODEL is untrusted, the PoC CODE is trusted (we wrote+tested it), the
TARGET is untrusted. A per-attempt nonce (minted by the orchestrator, injected as
HALO_NONCE) is echoed back by the target; only a matching echo proves *our* command ran
on *this* target — a tarpit streaming `uid=0(root)` cannot forge it.
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass

_EVIDENCE_PREFIX = "HALO-EVIDENCE"


def make_nonce() -> str:
    """A fresh unpredictable hex token. os.urandom so a target can't guess it."""
    return os.urandom(12).hex()


@dataclass(frozen=True)
class Breach:
    confirmed: bool
    level: str                 # "shell" | "blind-rce" | "none"
    nonce: str
    proof: str
    uid: str | None = None
    host: str | None = None
    exit_code: str | None = None

    def __bool__(self) -> bool:
        return self.confirmed

    def __str__(self) -> str:
        parts = [_EVIDENCE_PREFIX, f"nonce={self.nonce}", f"level={self.level}"]
        if self.uid is not None:
            parts.append(f"uid={self.uid}")
        if self.host is not None:
            parts.append(f"host={self.host}")
        if self.exit_code is not None:
            parts.append(f"exit={self.exit_code}")
        head = " ".join(parts)
        return f"{head}\n{self.proof}" if self.proof else head


def local_ip_for(target: str, _sock_factory=socket.socket) -> str:
    """deddy's source IP toward `target` — the LHOST for a reverse shell.

    Works because the ATTACK sandbox is --network=host, so getsockname() sees deddy's
    real interface (no packet is sent for a UDP connect())."""
    s = _sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


_UID_RE = re.compile(r"uid=(\d+)\(")


def _drain(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    except OSError:
        pass
    return b"".join(chunks)


def confirm_shell(sock: socket.socket, *, service: str = "", nonce: str = "",
                  timeout: float = 8.0) -> Breach:
    """Probe an already-open shell socket with a challenge-response marker.

    Confirmed only when the target echoes `<nonce>-MARK` — proves *our* command ran,
    so a banner/tarpit that streams `uid=0` without the nonce is NOT a breach."""
    nonce = nonce or make_nonce()
    mark = f"{nonce}-MARK"
    try:
        sock.sendall(f"echo {mark}; id; uname -n\n".encode())
        out = _drain(sock, timeout)
    except OSError:
        out = b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    text = out.decode("utf-8", "replace")
    if mark not in text:
        return Breach(confirmed=False, level="none", nonce=nonce, proof=text)
    m = _UID_RE.search(text)
    uid = m.group(1) if m else None
    host = None
    for line in text.splitlines():
        line = line.strip()
        if line and line != mark and not line.startswith("uid=") and " " not in line:
            host = line
            break
    return Breach(confirmed=True, level="shell", nonce=nonce, proof=text.strip(),
                  uid=uid, host=host, exit_code="0")
