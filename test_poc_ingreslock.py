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

import re
import socket
import threading

import pytest

import poc_library
from pocs import ingreslock_1524_bindshell as ing
from agent_loop import breach_confirmed, _SHELL_EVIDENCE


# ── a stand-in ingreslock backdoor: connect → unauthenticated root shell ──────
class FakeIngreslockShell:
    """Mimics the real bug: an open root shell on the port. It behaves like a
    real /bin/sh — it RUNS the challenge-response probe `echo <nonce>-MARK; id;
    uname -n`, so it echoes the nonce (proving our command ran) and answers `id`
    with uid=0(root).

    ``echo_mark=False`` models a tarpit that streams uid=0 WITHOUT running our
    command (never echoing the nonce) — the primitive must NOT confirm that."""

    def __init__(self, root=True, echo_mark=True):
        self.root = root
        self.echo_mark = echo_mark
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
            text = cmd.decode("utf-8", "replace")
            m = re.search(r"echo (\S+)", text)
            if m and self.echo_mark:                 # a real shell runs `echo <mark>`
                conn.sendall(m.group(1).encode() + b"\n")
            if "id" in text:
                if self.root:
                    conn.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
                else:
                    conn.sendall(b"uid=1000(user) gid=1000(user)\n")
            conn.sendall(b"metasploitable\n")        # uname -n

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
    # Task 11: the shipped bundle inlines pocs/_delivery.py so the single file runs
    # self-contained in the sandbox, so it is no longer byte-for-byte the module
    # file. The behavioural invariant still holds: the bundle carries this PoC's own
    # body AND the shared delivery primitive, with the sibling import removed.
    _, code = poc_library.select_poc("1524", "ingreslock")
    with open(ing.__file__) as f:
        module_src = f.read()
    assert "no bind shell on" in code             # this PoC's own error path
    assert "def run_from_env(env)" in code         # the module's entry point
    assert "HALO-EVIDENCE" in code                 # inlined _delivery body
    assert "def confirm_shell" in code             # the primitive it depends on
    assert "from pocs._delivery" not in code       # sibling import stripped
    assert "from pocs._delivery" in module_src     # (still present in the source)
    assert "TARGET_IP" not in code


# ── the bite ──────────────────────────────────────────────────────────────────
def test_ingreslock_pops_root_shell(shell):
    br = ing.exploit("127.0.0.1", port=shell.port, nonce="beef", timeout=5)
    assert br                                    # confirmed breach
    assert br.nonce == "beef"
    assert "uid=0(root)" in str(br)              # the shell's id output is the proof


def test_popped_output_trips_real_breach_evidence(shell):
    br = ing.exploit("127.0.0.1", port=shell.port, nonce="beef", timeout=5)
    out = str(br)
    assert "HALO-EVIDENCE" in out and "nonce=beef" in out
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True) is True
    assert breach_confirmed("run_exploit", out, ok=True, nonce="beef") is True


# ── no false positives ──────────────────────────────────────────────────────
def test_no_shell_when_port_closed():
    # Bind a port, then close it so nothing is listening → must raise, not fake.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    with pytest.raises(Exception):
        ing.exploit("127.0.0.1", port=dead_port, timeout=2)


def test_tarpit_streaming_uid_without_nonce_is_not_confirmed():
    # A box that streams uid=0 but NEVER echoes our nonce (a tarpit that didn't
    # run our command) must NOT be confirmed — that is the whole point of the
    # challenge-response primitive. exploit returns a falsy, unconfirmed Breach.
    srv = FakeIngreslockShell(root=True, echo_mark=False).start()
    try:
        br = ing.exploit("127.0.0.1", port=srv.port, nonce="beef", timeout=3)
        assert not br                            # non-breach: nonce never echoed
        assert br.confirmed is False
        assert br.level == "none"
    finally:
        srv.close()


def test_selfcheck_is_clean_offline():
    # test phase runs --network=none with no TARGET; the PoC must still exit 0
    # with real stdout so the hardening loop passes it to the fire gate.
    rc, out = ing.run_from_env({})   # no TARGET
    assert rc == 0
    assert out.strip() != ""
    assert "TARGET_IP" not in out


# ── delegates verification to the shared confirm_shell primitive ─────────────
def test_ingreslock_uses_confirm_shell_and_emits_evidence(monkeypatch):
    # The PoC must DELEGATE its result-verification to the shared confirm_shell
    # primitive and surface the standard nonce-bearing HALO-EVIDENCE line, not
    # hand-roll its own read+regex.
    from pocs import _delivery
    monkeypatch.setattr(
        ing, "confirm_shell",
        lambda sock, **kw: _delivery.Breach(True, "shell", kw.get("nonce", "n"),
                                            "uid=0(root)", uid="0", host="victim",
                                            exit_code="0"),
        raising=False)

    class FakeSock:
        def close(self):
            pass

    monkeypatch.setattr(ing.socket, "create_connection", lambda *a, **k: FakeSock())
    rc, out = ing.run_from_env({"TARGET": "10.0.0.1", "HALO_NONCE": "zz9"})
    assert rc == 0 and "HALO-EVIDENCE" in out and "nonce=zz9" in out
