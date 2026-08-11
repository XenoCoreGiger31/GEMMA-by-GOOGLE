"""Tests for the domain web-recon phase (2026-08-11).

Covers the pure extractors + the domain gate, the memory fields that hold the
results, and run_web_recon's orchestration (with execute_step stubbed so no tool
actually shells out). The point of the phase is that these tools fire
deterministically on a domain engage — the model never picked them — so the
orchestration test asserts exactly that.
"""
import asyncio

import agent_loop
from exploitation_core import AgentMemory


# ── domain gate ─────────────────────────────────────────────────────────────

def test_is_domain_target_true_for_dns_names():
    assert agent_loop.is_domain_target("katz.ctfio.com")
    assert agent_loop.is_domain_target("https://katz.ctfio.com/path")
    assert agent_loop.is_domain_target("sub.katz.ctfio.com:443")


def test_is_domain_target_false_for_ips_and_empty():
    assert not agent_loop.is_domain_target("192.168.64.3")
    assert not agent_loop.is_domain_target("192.168.64.3:80")
    assert not agent_loop.is_domain_target("10.0.0.0")
    assert not agent_loop.is_domain_target("")


# ── extractors ──────────────────────────────────────────────────────────────

def test_extract_subdomains_finds_and_dedups_excluding_apex():
    out = "www.katz.ctfio.com\napi.katz.ctfio.com\nwww.katz.ctfio.com\nkatz.ctfio.com\n"
    subs = agent_loop.extract_subdomains(out, "katz.ctfio.com")
    assert subs == ["www.katz.ctfio.com", "api.katz.ctfio.com"]  # apex excluded, deduped


def test_extract_subdomains_ignores_unrelated_hosts():
    out = "www.katz.ctfio.com evil.example.com mail.google.com"
    subs = agent_loop.extract_subdomains(out, "katz.ctfio.com")
    assert subs == ["www.katz.ctfio.com"]


def test_extract_urls_trims_punctuation_and_dedups():
    out = 'found https://katz.ctfio.com/login. and http://katz.ctfio.com/a) plus https://katz.ctfio.com/login.'
    urls = agent_loop.extract_urls(out)
    assert urls == ["https://katz.ctfio.com/login", "http://katz.ctfio.com/a"]


# ── memory fields ───────────────────────────────────────────────────────────

def test_memory_add_subdomains_and_urls_dedup_and_summarize():
    m = AgentMemory()
    m.add_subdomains(["a.x.com", "b.x.com", "a.x.com"])
    m.add_urls(["http://x.com/1", "http://x.com/1", "http://x.com/2"])
    assert m.subdomains == ["a.x.com", "b.x.com"]
    assert m.urls == ["http://x.com/1", "http://x.com/2"]
    s = m.summary()
    assert s["subdomains"] == ["a.x.com", "b.x.com"]
    assert s["urls"] == ["http://x.com/1", "http://x.com/2"]


# ── orchestration ───────────────────────────────────────────────────────────

def test_run_web_recon_fires_all_passive_tools_and_seeds_memory(monkeypatch):
    called = []

    canned = {
        "run_subfinder": "www.katz.ctfio.com\napi.katz.ctfio.com",
        "run_gau": "https://katz.ctfio.com/login\nhttps://api.katz.ctfio.com/v1",
    }

    async def fake_execute_step(session, step):
        called.append(step["tool"])
        # scope check must have been fed the apex, not a URL/port
        assert step["target"] == "katz.ctfio.com"
        return canned.get(step["tool"], ""), True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)

    mem = AgentMemory()
    asyncio.run(agent_loop.run_web_recon(None, "https://katz.ctfio.com/x", mem))

    # every passive recon tool fired, in order — deterministic, not model-chosen
    assert called == agent_loop.WEB_RECON_TOOLS
    assert "www.katz.ctfio.com" in mem.subdomains
    assert "api.katz.ctfio.com" in mem.subdomains
    assert "https://katz.ctfio.com/login" in mem.urls


def test_run_web_recon_survives_tool_failure(monkeypatch):
    async def fake_execute_step(session, step):
        if step["tool"] == "run_amass":
            return "", False            # missing/failed tool → empty output
        return "x.katz.ctfio.com", True

    monkeypatch.setattr(agent_loop, "execute_step", fake_execute_step)
    mem = AgentMemory()
    asyncio.run(agent_loop.run_web_recon(None, "katz.ctfio.com", mem))
    assert "x.katz.ctfio.com" in mem.subdomains    # other tools still contributed
