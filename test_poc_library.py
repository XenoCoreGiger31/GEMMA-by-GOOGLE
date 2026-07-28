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

import os
import re
import socket
import subprocess
import sys
import tempfile
import threading

import pytest

import poc_library
from pocs import vsftpd_2_3_4_backdoor as vsftpd
from agent_loop import breach_confirmed, _SHELL_EVIDENCE

# Every curated PoC the library ships. Each 2-tuple is (port, service_hint) that
# select_poc() matches, so we exercise the real selection path for all three.
_CURATED = [
    ("21", "vsftpd 2.3.4"),
    ("1524", "ingreslock bind shell"),
    ("6667", "unrealircd 3.2.8.1"),
]


def _shipped(port, hint):
    sel = poc_library.select_poc(port, hint)
    assert sel is not None, f"no curated PoC selected for {port}/{hint}"
    return sel[1]


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
            # Behave like a real /bin/sh running the challenge-response probe
            # `echo <nonce>-MARK; id; uname -n`: echo the nonce (proves our
            # command ran), then answer id, then the hostname.
            text = cmd.decode("utf-8", "replace")
            m = re.search(r"echo (\S+)", text)
            if m:
                shell.sendall(m.group(1).encode() + b"\n")
            if "id" in text:
                shell.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
            shell.sendall(b"metasploitable\n")

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
    # The shipped bundle is no longer a byte-for-byte copy of the module file: it
    # inlines pocs/_delivery.py so the single file runs self-contained in the
    # sandbox (Task 11). The invariant that still must hold is behavioural — the
    # shipped code contains BOTH the exact PoC body this suite exercises AND the
    # shared delivery primitive it depends on, minus the sibling import.
    _, code = poc_library.select_poc("21", "vsftpd")
    with open(vsftpd.__file__) as f:
        module_src = f.read()
    # the PoC's own trigger + behaviour bytes are present verbatim
    assert "USER hax0r:)" in code                 # the vsftpd smiley trigger
    assert "def run_from_env(env)" in code        # the module's entry point
    # the _delivery body is inlined (its evidence prefix + confirm_shell are here)
    assert "HALO-EVIDENCE" in code
    assert "def confirm_shell" in code
    # ...but the sibling import that broke standalone execution is gone
    assert "from pocs._delivery" not in code
    assert "from pocs._delivery" in module_src    # (still present in the source file)
    assert "TARGET_IP" not in code                # keep the placeholder-guard invariant


# ── Task 11: self-contained bundling of _delivery into the shipped PoC ────────
def test_bundled_code_has_no_sibling_import():
    for port, hint in _CURATED:
        code = _shipped(port, hint)
        assert "from pocs._delivery" not in code
        assert "from pocs " not in code
        assert "import pocs" not in code


def test_bundled_code_has_single_leading_future_import():
    for port, hint in _CURATED:
        code = _shipped(port, hint)
        assert code.splitlines()[0] == "from __future__ import annotations"
        assert code.count("from __future__ import") == 1


def test_bundled_code_defines_primitive_symbols():
    unreal = _shipped("6667", "unrealircd 3.2.8.1")
    assert "def establish_rce" in unreal
    assert "class Breach" in unreal
    assert "def make_nonce" in unreal
    for port, hint in (("21", "vsftpd"), ("1524", "ingreslock")):
        assert "def confirm_shell" in _shipped(port, hint)


def test_bundled_code_compiles():
    for port, hint in _CURATED:
        code = _shipped(port, hint)
        compile(code, "<bundle>", "exec")


def test_bundled_code_has_no_placeholder_token():
    for port, hint in _CURATED:
        assert "TARGET_IP" not in _shipped(port, hint)


def test_bundled_poc_runs_standalone_selfcheck():
    # THE regression reproduction. Before Task 11 the shipped code began with
    # `from pocs._delivery import ...`; written to a lone temp file and run where
    # `pocs` is not importable (repo NOT on the path, cwd = tempdir), it died with
    # ModuleNotFoundError. The bundle must now run self-contained: exit 0 and print
    # SELF-CHECK OK with no TARGET, exactly the network-less TEST phase.
    # Reproduce the no-`pocs` environment: strip PYTHONPATH (so the repo root can't
    # leak in) and any TARGET/HALO_* so we stay in the self-check branch. For
    # `python <file>` sys.path[0] is the script's own dir (the tempdir), never cwd,
    # so the repo package is genuinely unreachable.
    env = {
        k: v for k, v in os.environ.items()
        if k != "PYTHONPATH" and k != "TARGET" and not k.startswith("HALO_")
    }
    for port, hint in _CURATED:
        code = _shipped(port, hint)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "shipped_poc.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            proc = subprocess.run(
                [sys.executable, path],
                env=env, cwd=td,
                capture_output=True, text=True, timeout=30,
            )
        assert proc.returncode == 0, (
            f"{hint}: rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}")
        assert "SELF-CHECK OK" in proc.stdout, (
            f"{hint}: stdout={proc.stdout!r} stderr={proc.stderr!r}")


# ── the bite ──────────────────────────────────────────────────────────────────
def test_vsftpd_backdoor_pops_root_shell(backdoor):
    br = vsftpd.exploit("127.0.0.1", ftp_port=backdoor.ftp_port,
                        backdoor_port=backdoor.backdoor_port, nonce="beef", timeout=5)
    assert br                                    # confirmed breach
    assert br.nonce == "beef"
    assert "uid=0(root)" in str(br)              # the shell's id output is the proof


def test_popped_output_trips_real_breach_evidence(backdoor):
    br = vsftpd.exploit("127.0.0.1", ftp_port=backdoor.ftp_port,
                        backdoor_port=backdoor.backdoor_port, nonce="beef", timeout=5)
    out = str(br)
    # honest: the SAME regex that guards the whole pipeline must fire on this
    assert "HALO-EVIDENCE" in out and "nonce=beef" in out
    assert _SHELL_EVIDENCE.search(out)
    assert breach_confirmed("run_exploit", out, ok=True) is True
    assert breach_confirmed("run_exploit", out, ok=True, nonce="beef") is True


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


# ── delegates verification to the shared confirm_shell primitive ─────────────
def test_vsftpd_uses_confirm_shell_and_emits_evidence(monkeypatch):
    # The PoC must DELEGATE result-verification to the shared confirm_shell
    # primitive and surface the standard nonce-bearing HALO-EVIDENCE line. vsftpd
    # makes TWO create_connection calls (FTP trigger + backdoor retry) — the stub
    # must satisfy both, and time.sleep is stubbed so the retry loop is instant.
    from pocs import _delivery

    class FakeSock:
        def sendall(self, *a):
            pass

        def recv(self, *a):
            return b""

        def settimeout(self, *a):
            pass

        def close(self):
            pass

    monkeypatch.setattr(vsftpd.socket, "create_connection", lambda *a, **k: FakeSock())
    monkeypatch.setattr(vsftpd.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(
        vsftpd, "confirm_shell",
        lambda sock, **kw: _delivery.Breach(True, "shell", kw.get("nonce", "n"),
                                            "uid=0(root)", uid="0", host="victim",
                                            exit_code="0"),
        raising=False)
    rc, out = vsftpd.run_from_env({"TARGET": "10.0.0.1", "HALO_NONCE": "zz9"})
    assert rc == 0 and "HALO-EVIDENCE" in out and "nonce=zz9" in out
