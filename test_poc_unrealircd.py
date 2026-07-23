#!/usr/bin/env python3
"""test_poc_unrealircd.py — proves the curated UnrealIRCd 3.2.8.1 PoC BITES.

UnrealIRCd 3.2.8.1 (CVE-2010-2075) shipped with a backdoor: any line beginning
``AB;`` is executed as a shell command by the daemon (running as its service user
— root on Metasploitable 2). Unlike vsftpd/ingreslock the backdoor gives blind RCE
with NO built-in output channel, so the PoC's command spawns a bind shell on a
chosen port, then we connect to it and run ``id``. This suite pins that the PoC:

  1. is *selected* automatically for port 6667 / ircd,
  2. self-checks clean offline (hardens under --network=none, no target),
  3. triggers ``AB;`` RCE, pops a shell via the bind port, prints uid=…,
  4. that stdout trips the REAL breach evidence regex (no fake success), and
  5. does NOT claim success against a patched daemon (ignores AB;) or closed port.

No podman, no network egress, no real target: the mock IS the backdoored daemon.
"""

import re
import socket
import threading

import pytest

import poc_library
from pocs import unrealircd_3281_backdoor as unreal
from agent_loop import breach_confirmed, _SHELL_EVIDENCE


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ── a stand-in UnrealIRCd 3.2.8.1: `AB;<cmd>` → RCE → bind shell on a port ────────
class FakeUnrealIRCd:
    """Mimics the observable backdoor: greet like ircd, and on a line starting
    ``AB;`` (when ``vulnerable``) execute the command by spawning a bind shell on
    ``bind_port`` that answers ``id`` as root. A patched daemon ignores ``AB;``."""

    def __init__(self, bind_port, vulnerable=True, root=True):
        self.bind_port = bind_port
        self.vulnerable = vulnerable
        self.root = root
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def start(self):
        threading.Thread(target=self._serve_irc, daemon=True).start()
        return self

    def _serve_irc(self):
        self.sock.settimeout(5)
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            conn.sendall(b":irc.local NOTICE AUTH :*** Looking up your hostname...\r\n")
            try:
                data = conn.recv(512)
            except OSError:
                return
            if self.vulnerable and data.startswith(b"AB;"):
                # The "command" ran — stand up the bind shell it would have spawned.
                threading.Thread(target=self._serve_bindshell, daemon=True).start()

    def _serve_bindshell(self):
        bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            bs.bind(("127.0.0.1", self.bind_port))
        except OSError:
            return
        bs.listen(1)
        bs.settimeout(5)
        try:
            conn, _ = bs.accept()
        except OSError:
            bs.close()
            return
        with conn:
            conn.settimeout(5)
            try:
                cmd = conn.recv(256)
            except OSError:
                return
            if b"id" in cmd:
                who = (b"uid=0(root) gid=0(root) groups=0(root)\n" if self.root
                       else b"uid=1000(user) gid=1000(user)\n")
                conn.sendall(who)
                conn.sendall(b"Linux metasploitable 2.6.24-16-server\n")
        bs.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def daemon():
    bp = _free_port()
    srv = FakeUnrealIRCd(bp).start()
    srv._bp = bp
    yield srv
    srv.close()


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
    _, code = poc_library.select_poc("6667", "unrealircd")
    with open(unreal.__file__) as f:
        assert code == f.read()


# ── the bite ──────────────────────────────────────────────────────────────────
def test_unrealircd_pops_shell(daemon):
    out = unreal.exploit("127.0.0.1", irc_port=daemon.port,
                         bind_port=daemon._bp, timeout=5)
    assert re.search(r"uid=\d+\(", out)


def test_popped_output_trips_real_breach_evidence(daemon):
    out = unreal.exploit("127.0.0.1", irc_port=daemon.port,
                         bind_port=daemon._bp, timeout=5)
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True) is True


# ── no false positives ──────────────────────────────────────────────────────
def test_no_shell_when_irc_port_closed():
    dead = _free_port()   # nothing listening there
    with pytest.raises(Exception):
        unreal.exploit("127.0.0.1", irc_port=dead, bind_port=_free_port(), timeout=2)


def test_no_success_against_patched_daemon():
    bp = _free_port()
    srv = FakeUnrealIRCd(bp, vulnerable=False).start()
    try:
        with pytest.raises(Exception):
            unreal.exploit("127.0.0.1", irc_port=srv.port, bind_port=bp, timeout=3)
    finally:
        srv.close()


def test_selfcheck_is_clean_offline():
    # test phase runs --network=none with no TARGET; the PoC must still exit 0
    # with real stdout so the hardening loop passes it to the fire gate.
    rc, out = unreal.run_from_env({})   # no TARGET
    assert rc == 0
    assert out.strip() != ""
    assert "TARGET_IP" not in out
