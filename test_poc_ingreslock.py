#!/usr/bin/env python3
"""test_poc_ingreslock.py — proves the curated ingreslock/1524 PoC BITES.

Metasploitable 2 leaves an unauthenticated root shell bound to TCP 1524 (the
"ingreslock" backdoor). There is no trigger and no auth: connect and you are
already root. This suite pins that the curated PoC:

  1. is *selected* automatically for port 1524 / ingreslock,
  2. self-checks clean offline (hardens under --network=none, no target),
  3. pops a real root shell against a stand-in and prints uid=0(root),
  4. that stdout trips the REAL breach evidence regex (no fake success), and
  5. does NOT claim success when nothing is listening / it isn't root.

No podman, no network egress, no real target: the mock IS the 1524 backdoor.
"""

import socket
import threading

import pytest

import poc_library
from pocs import ingreslock_1524_bindshell as ing
from agent_loop import breach_confirmed, _SHELL_EVIDENCE


# ── a stand-in ingreslock backdoor: connect → unauthenticated root shell ──────
class FakeIngreslockShell:
    """Mimics the real bug: an open root shell on the port. On `id` it answers
    uid=0(root); if `root=False` it behaves like a non-root/absent shell."""

    def __init__(self, root=True):
        self.root = root
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def start(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self):
        self.sock.settimeout(5)
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            try:
                cmd = conn.recv(256)
            except OSError:
                return
            if b"id" in cmd:
                if self.root:
                    conn.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
                    conn.sendall(b"Linux metasploitable 2.6.24-16-server\n")
                else:
                    conn.sendall(b"uid=1000(user) gid=1000(user)\n")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def shell():
    srv = FakeIngreslockShell().start()
    yield srv
    srv.close()


# ── selection ─────────────────────────────────────────────────────────────────
def test_selects_ingreslock_poc_for_port_1524():
    sel = poc_library.select_poc("1524", "ingreslock — often a root bind shell")
    assert sel is not None
    key, code = sel
    assert key == "ingreslock_1524_bindshell"
    assert "1524" in code
    assert "TARGET_IP" not in code               # must not trip the placeholder guard


def test_no_curated_poc_for_plain_ssh():
    assert poc_library.select_poc("22", "SSH") is None


def test_shipped_code_matches_the_tested_module():
    _, code = poc_library.select_poc("1524", "ingreslock")
    with open(ing.__file__) as f:
        assert code == f.read()


# ── the bite ──────────────────────────────────────────────────────────────────
def test_ingreslock_pops_root_shell(shell):
    out = ing.exploit("127.0.0.1", port=shell.port, timeout=5)
    assert "uid=0(root)" in out


def test_popped_output_trips_real_breach_evidence(shell):
    out = ing.exploit("127.0.0.1", port=shell.port, timeout=5)
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True) is True


# ── no false positives ──────────────────────────────────────────────────────
def test_no_shell_when_port_closed():
    # Bind a port, then close it so nothing is listening → must raise, not fake.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    with pytest.raises(Exception):
        ing.exploit("127.0.0.1", port=dead_port, timeout=2)


def test_no_success_when_not_root():
    srv = FakeIngreslockShell(root=False).start()
    try:
        with pytest.raises(Exception):
            ing.exploit("127.0.0.1", port=srv.port, timeout=3)
    finally:
        srv.close()


def test_selfcheck_is_clean_offline():
    # test phase runs --network=none with no TARGET; the PoC must still exit 0
    # with real stdout so the hardening loop passes it to the fire gate.
    rc, out = ing.run_from_env({})   # no TARGET
    assert rc == 0
    assert out.strip() != ""
    assert "TARGET_IP" not in out
