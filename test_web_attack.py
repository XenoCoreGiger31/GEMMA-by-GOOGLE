"""Tests for the active web-attack + flag-hunt phase (2026-08-11).

Flag extraction is pinned tightly (real CTF shapes match; ordinary braces don't),
and the orchestration is driven with a stubbed execute_step so we prove the phase
fires the right tools, captures a flag from any tool's output, and short-circuits
the moment it wins.
"""
import asyncio

import agent_loop
from exploitation_core import AgentMemory


# ── flag extraction ─────────────────────────────────────────────────────────

def test_extract_flags_matches_common_shapes():
    assert agent_loop.extract_flags("here is flag{he110_w0rld}") == ["flag{he110_w0rld}"]
    assert agent_loop.extract_flags("CTFIO{beginner_win}") == ["CTFIO{beginner_win}"]
    assert agent_loop.extract_flags("prefix ctf{abc} suffix") == ["ctf{abc}"]


def test_extract_flags_matches_ctfio_delimiter_style():
    # ctfio.com's own format, seen live on vanadium.ctfio.com
    out = "some page text [^FLAG^2B22E2CB70E218510802B0359488F6A2^FLAG^] more text"
    assert agent_loop.extract_flags(out) == ["[^FLAG^2B22E2CB70E218510802B0359488F6A2^FLAG^]"]


def test_extract_flags_ignores_non_flag_braces():
    assert agent_loop.extract_flags('.cls{color:red} function(){return 1}') == []
    assert agent_loop.extract_flags('{"json": "value"}') == []


def test_extract_flags_dedups():
    assert agent_loop.extract_flags("flag{x} ... flag{x}") == ["flag{x}"]


def test_memory_add_flag_dedups_and_summarizes():
    m = AgentMemory()
    m.add_flag("flag{x}", "run_curl")
    m.add_flag("flag{x}", "run_nuclei")   # dup ignored
    m.add_flag("ctfio{y}", "run_feroxbuster")
    assert [f["flag"] for f in m.flags] == ["flag{x}", "ctfio{y}"]
    assert m.summary()["flags"] == ["flag{x}", "ctfio{y}"]


# ── phase gating ────────────────────────────────────────────────────────────

def test_web_attack_noop_without_web_port(monkeypatch):
    calls = []

    async def fake_execute_step(session, step):
        calls.append(step["tool"])
        return "", True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)
    mem = AgentMemory()
    mem.add_ports(["22", "3306"])          # no 80/443
    asyncio.run(agent_loop.run_web_attack(None, "host.example", mem))
    assert calls == []                      # nothing fired


# ── orchestration + flag capture ────────────────────────────────────────────

def test_web_attack_captures_flag_and_short_circuits(monkeypatch):
    calls = []

    async def fake_execute_step(session, step):
        calls.append(step["tool"])
        # feroxbuster finds nothing; the flag sits at /robots.txt (first curl).
        if step["tool"] == "run_curl":
            return "User-agent: *\nDisallow: /admin\nflag{r0b0ts_txt}", True
        return "", True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)
    mem = AgentMemory()
    mem.add_ports(["443"])
    asyncio.run(agent_loop.run_web_attack(None, "https://vanadium.ctfio.com", mem))

    assert [f["flag"] for f in mem.flags] == ["flag{r0b0ts_txt}"]
    # feroxbuster ran, then curl — and we stopped before nuclei/dalfox.
    assert calls[0] == "run_feroxbuster"
    assert "run_curl" in calls
    assert "run_nuclei" not in calls and "run_dalfox" not in calls


def test_web_attack_runs_vuln_tools_when_no_flag(monkeypatch):
    calls = []

    async def fake_execute_step(session, step):
        calls.append(step["tool"])
        return "nothing here", True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)
    mem = AgentMemory()
    mem.add_ports(["80"])
    asyncio.run(agent_loop.run_web_attack(None, "http://plain.example", mem))

    # no flag anywhere → escalates to nuclei + dalfox
    assert "run_nuclei" in calls and "run_dalfox" in calls
    assert mem.flags == []


def test_web_attack_scopes_bare_host_not_url(monkeypatch):
    seen = []

    async def fake_execute_step(session, step):
        seen.append(step)
        return "", True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)
    mem = AgentMemory()
    mem.add_ports(["443"])
    asyncio.run(agent_loop.run_web_attack(None, "https://vanadium.ctfio.com/x", mem))

    # every step is scoped to the bare host; the URL rides in a tool-specific param
    for step in seen:
        assert step["target"] == "vanadium.ctfio.com"
    ferox = next(s for s in seen if s["tool"] == "run_feroxbuster")
    assert ferox["url"] == "https://vanadium.ctfio.com"
