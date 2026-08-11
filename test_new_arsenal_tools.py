"""Tests for the 2026-08-11 arsenal expansion — dalfox, feroxbuster, gowitness,
dnsx, gau, waybackurls, amass, ghosttrack, spiderfoot, recon-ng and phonextract.

Every one follows the established recon/scan tool shape: a `_run_*` handler that
builds a bounded command and runs it through `_execute_command`, plus a schema
entry and a dispatch mapping so the MCP server advertises and routes it. These
tests pin the command construction, the clean-error contract on missing params,
and manifest/dispatch registration — the network behaviour is proven live on
deddy, not here.
"""
import halo_tools


def _capture(monkeypatch):
    cap = {}

    def fake_exec(self, command, *a, **k):
        cap["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    return cap


def _ex():
    return halo_tools.ToolExecutor()


# ── command construction ────────────────────────────────────────────────────

def test_dalfox_builds_url_scan(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_dalfox({"url": "http://t/?q=1"})
    assert cap["command"].startswith("dalfox url http://t/?q=1")


def test_feroxbuster_builds_with_default_wordlist(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_feroxbuster({"url": "http://t"})
    assert "feroxbuster -u http://t" in cap["command"]
    assert "-w " in cap["command"]


def test_gowitness_single_target(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_gowitness({"target": "http://t"})   # `target` alias honored
    assert cap["command"] == "gowitness single http://t"


def test_dnsx_resolves_domain(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_dnsx({"domain": "example.com"})
    # stdin-fed resolution (dnsx `-d` is bruteforce mode and needs `-w`)
    assert "example.com" in cap["command"] and "dnsx" in cap["command"]
    assert "-d example.com" not in cap["command"]


def test_gau_fetches_domain_urls(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_gau({"domain": "example.com"})
    assert cap["command"] == "gau example.com"


def test_waybackurls_fetches_domain_urls(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_waybackurls({"domain": "example.com"})
    assert cap["command"] == "waybackurls example.com"


def test_amass_defaults_to_passive(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_amass({"domain": "example.com"})
    assert "amass enum -passive -nolocaldb -d example.com" in cap["command"]


def test_amass_active_mode_drops_passive_flag(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_amass({"domain": "example.com", "passive": False})
    assert "-passive" not in cap["command"]
    assert "amass enum -nolocaldb -d example.com" in cap["command"]


def test_ghosttrack_target(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_ghosttrack({"target": "someuser"})
    assert cap["command"] == "ghosttrack someuser"


def test_spiderfoot_scan(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_spiderfoot({"target": "example.com"})
    assert "spiderfoot -s example.com" in cap["command"]


def test_spiderfoot_honors_types(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_spiderfoot({"target": "example.com", "types": "DNS,IP"})
    assert "-t DNS,IP" in cap["command"]


def test_recon_ng_resource_file(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_recon_ng({"resource": "/tmp/r.rc"})
    assert cap["command"] == "recon-ng -r /tmp/r.rc"


def test_recon_ng_falls_back_to_workspace(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_recon_ng({"target": "acme"})
    assert cap["command"] == "recon-ng -w acme"


def test_phonextract_number(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_phonextract({"phone": "+15555550123"})
    assert cap["command"] == "phonextract +15555550123"


# ── clean-error contract on missing required params ─────────────────────────

def test_missing_params_return_invalid_params():
    ex = _ex()
    cases = [
        ex._run_dalfox({}), ex._run_feroxbuster({}), ex._run_gowitness({}),
        ex._run_dnsx({}), ex._run_gau({}), ex._run_waybackurls({}),
        ex._run_amass({}), ex._run_ghosttrack({}), ex._run_spiderfoot({}),
        ex._run_recon_ng({}), ex._run_phonextract({}),
    ]
    for res in cases:
        assert res["status"] == "error"
        assert res["error_type"] == "invalid_params"


# ── manifest / dispatch registration ────────────────────────────────────────

def test_all_new_tools_registered():
    names = [t["name"] for t in halo_tools.TOOLS]
    new = [
        "run_dalfox", "run_feroxbuster", "run_gowitness", "run_dnsx", "run_gau",
        "run_waybackurls", "run_amass", "run_ghosttrack", "run_spiderfoot",
        "run_recon_ng", "run_phonextract",
    ]
    for n in new:
        assert n in names, f"{n} missing from TOOLS manifest"
        assert n in halo_tools.ToolExecutor._DISPATCH, f"{n} missing from _DISPATCH"


def test_manifest_and_dispatch_stay_in_sync():
    # Mirrors the module-level assertion: every advertised tool is routable.
    assert set(halo_tools.SUPPORTED_TOOLS) == set(halo_tools.ToolExecutor._DISPATCH)
