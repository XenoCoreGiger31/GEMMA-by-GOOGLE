#!/usr/bin/env python3
"""test_metasploit_tool.py — Brick 2 firing: the gated run_metasploit tool.

Pins that run_metasploit builds a correct, PRIVATE (quiet, DB-less, no daemon),
INJECTION-SAFE, time-bounded msfconsole invocation, and that it is registered +
gated as an exploitation-tier action. Offline: _execute_command is monkeypatched,
no msf binary runs.
"""

import halo_tools
from engagement import classify
from agent_loop import breach_confirmed


def _capture(monkeypatch):
    cap = {}

    def fake_exec(self, command, *a, **k):
        cap["command"] = command
        cap["timeout"] = k.get("timeout", a[1] if len(a) > 1 else None)
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    return cap


def test_builds_use_set_rhosts_run():
    ex = halo_tools.ToolExecutor()
    cap = {}
    # inline monkeypatch without fixture
    orig = halo_tools.ToolExecutor._execute_command
    halo_tools.ToolExecutor._execute_command = lambda self, command, *a, **k: cap.setdefault("command", command)
    try:
        ex._run_metasploit({"module": "exploit/unix/ftp/vsftpd_234_backdoor",
                            "target": "203.0.113.3"})
    finally:
        halo_tools.ToolExecutor._execute_command = orig
    c = cap["command"]
    assert "use exploit/unix/ftp/vsftpd_234_backdoor" in c
    assert "set RHOSTS 203.0.113.3" in c
    assert "run" in c and "exit" in c


def test_private_quiet_dbless_no_daemon(monkeypatch):
    cap = _capture(monkeypatch)
    halo_tools.ToolExecutor()._run_metasploit(
        {"module": "exploit/x", "target": "10.0.0.1"})
    c = cap["command"]
    assert c.startswith("msfconsole")
    assert " -q " in f" {c} " and " -n " in f" {c} "   # quiet + no-database
    assert "msfrpcd" not in c                            # never the listening daemon


def test_optional_rport_payload_lhost_lport_options(monkeypatch):
    cap = _capture(monkeypatch)
    halo_tools.ToolExecutor()._run_metasploit({
        "module": "exploit/multi/handler", "target": "10.0.0.1",
        "rport": "6667", "payload": "cmd/unix/reverse",
        "lhost": "10.0.0.2", "lport": "4444", "options": "SSL=false FOO=bar",
    })
    c = cap["command"]
    assert "set RPORT 6667" in c
    assert "set PAYLOAD cmd/unix/reverse" in c
    assert "set LHOST 10.0.0.2" in c and "set LPORT 4444" in c
    assert "set SSL false" in c and "set FOO bar" in c


def test_bounded_timeout_env_overridable(monkeypatch):
    cap = _capture(monkeypatch)
    halo_tools.ToolExecutor()._run_metasploit({"module": "exploit/x", "target": "10.0.0.1"})
    assert cap["timeout"] is not None
    assert cap["timeout"] < halo_tools.TOOL_TIMEOUT

    monkeypatch.setenv("HALO_MSF_TIMEOUT", "42")
    cap2 = _capture(monkeypatch)
    halo_tools.ToolExecutor()._run_metasploit({"module": "exploit/x", "target": "10.0.0.1"})
    assert cap2["timeout"] == 42


def test_missing_module_or_target_is_invalid_params(monkeypatch):
    _capture(monkeypatch)
    ex = halo_tools.ToolExecutor()
    assert ex._run_metasploit({"target": "10.0.0.1"})["error_type"] == "invalid_params"
    assert ex._run_metasploit({"module": "exploit/x"})["error_type"] == "invalid_params"


def test_sanitizes_injection_in_module_and_target(monkeypatch):
    cap = _capture(monkeypatch)
    halo_tools.ToolExecutor()._run_metasploit({
        "module": "exploit/x", "target": '10.0.0.1"; rm -rf / ;#',
    })
    c = cap["command"]
    # Isolate just the RHOSTS value (up to the next resource-string separator) and
    # assert the injection could not smuggle in break-out chars or extra tokens.
    rhosts_val = c.split("set RHOSTS ", 1)[1].split(";", 1)[0].strip()
    for bad in ['"', ";", "#", " "]:
        assert bad not in rhosts_val, f"{bad!r} leaked into the RHOSTS value"


def test_registered_and_gated_as_exploitation():
    # registry <-> dispatch drift guard already ran at import; confirm presence + tier.
    assert "run_metasploit" in halo_tools.SUPPORTED_TOOLS
    assert "run_metasploit" in halo_tools.ToolExecutor._DISPATCH
    assert classify("run_metasploit") == "exploitation"   # ask-tier gate


# ── a popped msf session must count as a real breach ─────────────────────────
def test_meterpreter_session_is_a_breach():
    out = "[*] Meterpreter session 1 opened (10.0.0.2:4444 -> 10.0.0.1:1234)"
    assert breach_confirmed("run_metasploit", out, ok=True) is True


def test_command_shell_session_is_a_breach():
    out = "[*] Command shell session 2 opened (10.0.0.2 -> 10.0.0.1)"
    assert breach_confirmed("run_metasploit", out, ok=True) is True


def test_no_session_created_is_not_a_breach():
    out = "[-] Exploit completed, but no session was created."
    assert breach_confirmed("run_metasploit", out, ok=True) is False
