"""Tests for the theHarvester OSINT tool — passive email/subdomain/host harvesting.

New arsenal tool. Same shape as the other recon tools: a `_run_theharvester` handler
that builds a bounded, sanitized command and runs it through _execute_command, plus a
schema-registry entry and a dispatch mapping so the MCP server advertises and routes it.
"""
import halo_tools


def _capture(monkeypatch):
    cap = {}

    def fake_exec(self, command, *a, **k):
        cap["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    return cap


def test_theharvester_builds_command_with_domain_and_default_sources(monkeypatch):
    cap = _capture(monkeypatch)
    ex = halo_tools.ToolExecutor()
    res = ex._run_theharvester({"domain": "example.com"})
    assert res["status"] == "success"
    assert "theHarvester" in cap["command"]
    assert "-d example.com" in cap["command"]
    assert "-b " in cap["command"]          # a default passive source set is supplied


def test_theharvester_missing_domain_is_clean_json_error():
    ex = halo_tools.ToolExecutor()
    res = ex._run_theharvester({})
    assert res["status"] == "error"
    assert res["error_type"] == "invalid_params"


def test_theharvester_honors_custom_sources(monkeypatch):
    cap = _capture(monkeypatch)
    ex = halo_tools.ToolExecutor()
    ex._run_theharvester({"domain": "example.com", "sources": "crtsh,bing"})
    assert "-b crtsh,bing" in cap["command"]


def test_theharvester_clamps_non_numeric_limit(monkeypatch):
    cap = _capture(monkeypatch)
    ex = halo_tools.ToolExecutor()
    ex._run_theharvester({"domain": "example.com", "limit": "abc"})
    assert "-l 100" in cap["command"]       # falls back to the default, never crashes


def test_theharvester_registered_in_manifest_and_dispatch():
    names = [t["name"] for t in halo_tools.TOOLS]
    assert "run_theharvester" in names
    assert "run_theharvester" in halo_tools.ToolExecutor._DISPATCH
