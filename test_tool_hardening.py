"""Tests for the tool-wrapper hardening that stopped the last engagement from
no-op'ing 20 of 23 ports: wordlist fallback, integer coercion, and the
network-less scope-gate carve-out."""

import os

import halo_tools
from halo_tools import BUNDLED_WEB_WORDLIST, BUNDLED_WORDLIST, _clamp_int, resolve_wordlist


def test_bundled_wordlists_ship_with_repo():
    # The whole point is that these always exist, so a bad seclists path can
    # never again kill every hydra call with "File for passwords not found".
    assert os.path.isfile(BUNDLED_WORDLIST)
    assert os.path.isfile(BUNDLED_WEB_WORDLIST)


def test_resolve_wordlist_prefers_existing_request(tmp_path):
    wanted = tmp_path / "mylist.txt"
    wanted.write_text("hunter2\n")
    path, note = resolve_wordlist(str(wanted), BUNDLED_WORDLIST, BUNDLED_WORDLIST)
    assert path == str(wanted)
    assert note == ""


def test_resolve_wordlist_falls_back_when_request_missing(tmp_path):
    # Use paths guaranteed not to exist (under tmp_path) so the result doesn't
    # depend on whether seclists happens to be installed on this host.
    missing = str(tmp_path / "requested-does-not-exist.txt")
    also_missing = str(tmp_path / "default-does-not-exist.txt")
    path, note = resolve_wordlist(missing, also_missing, BUNDLED_WORDLIST)
    assert path == BUNDLED_WORDLIST
    assert "missing" in note


def test_resolve_wordlist_none_request_uses_default_chain():
    path, note = resolve_wordlist(None, "/nope.txt", BUNDLED_WORDLIST)
    assert path == BUNDLED_WORDLIST
    assert note == ""  # no requested path -> silent fallback, nothing to warn about


def test_clamp_int_coerces_and_clamps():
    assert _clamp_int("3", lo=1, hi=5, default=1) == 3
    assert _clamp_int("9", lo=1, hi=5, default=1) == 5      # above range
    assert _clamp_int("0", lo=1, hi=5, default=1) == 1      # below range
    assert _clamp_int("A", lo=1, hi=5, default=1) == 1      # the crash we hit
    assert _clamp_int(None, lo=1, hi=3, default=2) == 2
    assert _clamp_int("  2 ", lo=1, hi=3, default=1) == 2   # whitespace tolerated


def test_hydra_missing_wordlist_still_runs(monkeypatch):
    """A hydra call with a bogus wordlist path must still fire (against a real,
    present list) and annotate the substitution — never abort as invalid_params."""
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    # Force the seclists default to be absent too, so the fallback is
    # deterministically the bundled list regardless of what's installed here.
    monkeypatch.setattr(halo_tools, "DEFAULT_WORDLIST", "/nonexistent/default.txt")
    ex = halo_tools.ToolExecutor()
    res = ex._run_hydra({
        "target": "203.0.113.3", "service": "ftp", "username": "root",
        "wordlist": "/does/not/exist.txt",
    })
    assert res["status"] == "success"
    # The bogus requested path must never reach the command line...
    assert "/does/not/exist.txt" not in captured["command"]
    # ...and it must fall through to the bundled list that ships with the repo.
    assert BUNDLED_WORDLIST in captured["command"]
    assert "missing" in res.get("note", "")


def test_gobuster_adds_scheme(monkeypatch):
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    ex = halo_tools.ToolExecutor()
    ex._run_gobuster({"target": "203.0.113.3:8180"})
    assert "http://203.0.113.3:8180" in captured["command"]


def test_sqlmap_rejects_letter_level(monkeypatch):
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    ex = halo_tools.ToolExecutor()
    ex._run_sqlmap({"target": "http://203.0.113.3/x?id=1", "level": "A", "risk": "Z"})
    assert "--level=1" in captured["command"]
    assert "--risk=1" in captured["command"]


def test_searchsploit_accepts_query_alias(monkeypatch):
    """The model reliably calls searchsploit with `query`, not `keyword`. That must
    reach the search (it was the 20x '0s non-JSON MCP response' bug — every model call
    got rejected before running). `query` (and `search`) alias to `keyword`."""
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    ex = halo_tools.ToolExecutor()
    res = ex._run_searchsploit({"query": "openssh 4.7p1"})
    assert res["status"] == "success"
    assert "openssh 4.7p1" in captured["command"]

    ex._run_searchsploit({"search": "apache 2.2.8"})
    assert "apache 2.2.8" in captured["command"]


def test_searchsploit_keyword_still_works(monkeypatch):
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    ex = halo_tools.ToolExecutor()
    ex._run_searchsploit({"keyword": "vsftpd 2.3.4"})
    assert "vsftpd 2.3.4" in captured["command"]


def test_searchsploit_schema_does_not_hard_require_keyword():
    """The MCP layer validates args against inputSchema and hard-rejects (non-JSON)
    a call missing a *required* field — that's what killed every `query` call before
    it ran. `keyword` must NOT be required, and `query` must be an accepted property,
    so a `query` call passes validation and the tool resolves the alias itself."""
    schema = next(t["inputSchema"] for t in halo_tools.TOOLS
                  if t["name"] == "run_searchsploit")
    assert "keyword" not in schema.get("required", [])
    assert "query" in schema["properties"]


def test_searchsploit_no_terms_returns_clean_json_error():
    ex = halo_tools.ToolExecutor()
    res = ex._run_searchsploit({})
    assert res["status"] == "error"
    assert res["error_type"] == "invalid_params"


def _capture_timeout(monkeypatch):
    """Patch _execute_command to record the timeout it was called with."""
    captured = {}

    def fake_exec(self, command, *a, **k):
        captured["command"] = command
        # timeout may arrive positionally or by keyword; _run_* uses keyword.
        captured["timeout"] = k.get("timeout", a[1] if len(a) > 1 else None)
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    return captured


def test_nuclei_does_not_ride_the_300s_wall(monkeypatch):
    """Last engagement nuclei burned the full 300s default twice with zero output.
    It must pass an explicit, tight timeout so a slow host can't stall the loop."""
    captured = _capture_timeout(monkeypatch)
    ex = halo_tools.ToolExecutor()
    ex._run_nuclei({"target": "203.0.113.3:1099"})
    assert captured["timeout"] is not None, "nuclei inherited the 300s catch-all"
    assert captured["timeout"] < halo_tools.TOOL_TIMEOUT
    assert captured["timeout"] <= 120


def test_hydra_does_not_ride_the_300s_wall(monkeypatch):
    """Telnet hydra stalled the whole 300s default on a hung login negotiation.
    With small wordlists it must be bounded well under the catch-all."""
    captured = _capture_timeout(monkeypatch)
    monkeypatch.setattr(halo_tools, "DEFAULT_WORDLIST", "/nonexistent/default.txt")
    ex = halo_tools.ToolExecutor()
    ex._run_hydra({"target": "203.0.113.3", "service": "telnet", "username": "root"})
    assert captured["timeout"] is not None, "hydra inherited the 300s catch-all"
    assert captured["timeout"] < halo_tools.TOOL_TIMEOUT
    assert captured["timeout"] <= 150
