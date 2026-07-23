#!/usr/bin/env python3
"""test_poc_library.py — proves the curated PoC library actually BITES.

The live agent used to hand the 12B a blank page and ask it to author a full
socket-level exploit inline in JSON, one-shot, no refine loop. It never landed.
This suite pins the opposite: a curated, deterministic PoC for the single most
reliable exploit in a Metasploitable box — the vsftpd 2.3.4 backdoor — that

  1. is *selected* automatically for port 21 / vsftpd,
  2. self-checks clean offline (so it hardens without a network),
  3. pops a real root shell against a stand-in backdoor and prints uid=0(root),
  4. that stdout trips the REAL breach evidence regex (no fake success), and
  5. does NOT claim success when the box isn't actually backdoored.

No podman, no network egress, no real target: the mock IS a vsftpd 2.3.4
backdoor (accepts the `:)` smiley, opens a root bind shell on another port).
"""

import socket
import threading

import pytest

import poc_library
from pocs import vsftpd_2_3_4_backdoor as vsftpd
from agent_loop import breach_confirmed, _SHELL_EVIDENCE


# ── a stand-in vsftpd 2.3.4: smiley trigger → root bind shell ─────────────────
class FakeVsftpdBackdoor:
    """Mimics the real bug: a USER ending in ':)' spins up a no-auth root shell
    on `backdoor_port`; that shell answers `id` with uid=0(root)."""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.ftp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ftp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ftp.bind(("127.0.0.1", 0))
        self.ftp.listen(1)
        self.ftp_port = self.ftp.getsockname()[1]
        # reserve the backdoor port up front so the exploit has a fixed target
        self.bd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bd.bind(("127.0.0.1", 0))
        self.backdoor_port = self.bd.getsockname()[1]
        self._backdoor_armed = False
        self._threads = []
        self._stop = False

    def start(self):
        t = threading.Thread(target=self._serve_ftp, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def _serve_ftp(self):
        try:
            self.ftp.settimeout(5)
            conn, _ = self.ftp.accept()
        except OSError:
            return
        with conn:
            conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")
            conn.settimeout(5)
            try:
                user = conn.recv(256)
            except OSError:
                return
            conn.sendall(b"331 Please specify the password.\r\n")
            # THE BUG: a username ending in ':)' arms the backdoor.
            if self.vulnerable and user.rstrip().endswith(b":)"):
                self._backdoor_armed = True
                bt = threading.Thread(target=self._serve_backdoor, daemon=True)
                bt.start()
                self._threads.append(bt)
            try:
                conn.recv(256)  # PASS — the real backdoor never completes login
            except OSError:
                pass

    def _serve_backdoor(self):
        self.bd.listen(1)
        self.bd.settimeout(5)
        try:
            shell, _ = self.bd.accept()
        except OSError:
            return
        with shell:
            shell.settimeout(5)
            try:
                cmd = shell.recv(256)
            except OSError:
                return
            if b"id" in cmd:
                shell.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
                shell.sendall(b"Linux metasploitable 2.6.24-16-server\n")

    def close(self):
        self._stop = True
        for s in (self.ftp, self.bd):
            try:
                s.close()
            except OSError:
                pass


@pytest.fixture
def backdoor():
    srv = FakeVsftpdBackdoor().start()
    yield srv
    srv.close()


# ── selection ─────────────────────────────────────────────────────────────────
def test_selects_vsftpd_poc_for_port_21():
    sel = poc_library.select_poc("21", "FTP (often vsftpd 2.3.4 — known backdoor)")
    assert sel is not None
    key, code = sel
    assert key == "vsftpd_2_3_4_backdoor"
    assert "USER" in code and ":)" in code       # the actual trigger is in the shipped code
    assert "TARGET_IP" not in code               # must not trip the placeholder guard


def test_no_curated_poc_for_plain_ssh():
    assert poc_library.select_poc("22", "SSH") is None


def test_shipped_code_matches_the_tested_module():
    # The string the sandbox runs must be the SAME source this suite exercises.
    _, code = poc_library.select_poc("21", "vsftpd")
    with open(vsftpd.__file__) as f:
        assert code == f.read()


# ── the bite ──────────────────────────────────────────────────────────────────
def test_vsftpd_backdoor_pops_root_shell(backdoor):
    out = vsftpd.exploit("127.0.0.1", ftp_port=backdoor.ftp_port,
                         backdoor_port=backdoor.backdoor_port, timeout=5)
    assert "uid=0(root)" in out


def test_popped_output_trips_real_breach_evidence(backdoor):
    out = vsftpd.exploit("127.0.0.1", ftp_port=backdoor.ftp_port,
                         backdoor_port=backdoor.backdoor_port, timeout=5)
    # honest: the SAME regex that guards the whole pipeline must fire on this
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True) is True


# ── no false positives ──────────────────────────────────────────────────────
def test_no_shell_when_not_vulnerable():
    srv = FakeVsftpdBackdoor(vulnerable=False).start()
    try:
        with pytest.raises(Exception):
            vsftpd.exploit("127.0.0.1", ftp_port=srv.ftp_port,
                           backdoor_port=srv.backdoor_port, timeout=3)
    finally:
        srv.close()


def test_selfcheck_is_clean_offline():
    # test phase runs --network=none with no TARGET; the PoC must still exit 0
    # with real stdout so the hardening loop passes it to the fire gate.
    rc, out = vsftpd.run_from_env({})   # no TARGET
    assert rc == 0
    assert out.strip() != ""
    assert "TARGET_IP" not in out
