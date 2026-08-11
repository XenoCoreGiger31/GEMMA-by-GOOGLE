"""Tests for the 2026-08-11 invocation fixes surfaced by the beryl.ctfio.com run.

Each pins the corrected command string so the exact bug we saw in the field
(wrong dnsx mode, removed theHarvester engine, amass sudo escalation, masscan
choking on a hostname) can't silently come back.
"""
import halo_tools


def _capture(monkeypatch):
    cap = {}

    def fake_exec(self, command, *a, **k):
        cap["command"] = command
        return {"status": "success", "stdout": "", "stderr": ""}

    monkeypatch.setattr(halo_tools.ToolExecutor, "_execute_command", fake_exec)
    monkeypatch.setattr(halo_tools.ToolExecutor, "_run_and_escalate", fake_exec)
    return cap


def _ex():
    return halo_tools.ToolExecutor()


def test_dnsx_resolves_from_stdin_not_dashd(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_dnsx({"domain": "beryl.ctfio.com"})
    # stdin-fed resolution, never the bruteforce `-d` mode that demands `-w`
    assert "| " in cap["command"] and "dnsx" in cap["command"]
    assert "-d beryl.ctfio.com" not in cap["command"]
    assert "beryl.ctfio.com" in cap["command"]


def test_theharvester_default_sources_drop_bing(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_theharvester({"domain": "beryl.ctfio.com"})
    assert "bing" not in cap["command"]
    assert "-b " in cap["command"]


def test_amass_uses_nolocaldb_to_avoid_sudo(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_amass({"domain": "beryl.ctfio.com"})
    assert "-nolocaldb" in cap["command"]
    assert "amass enum -passive" in cap["command"]


def test_masscan_resolves_hostname_to_ip(monkeypatch):
    cap = _capture(monkeypatch)
    monkeypatch.setattr(halo_tools.socket, "gethostbyname", lambda h: "188.166.137.91")
    _ex()._run_masscan({"target": "beryl.ctfio.com"})
    assert "188.166.137.91" in cap["command"]
    assert "beryl.ctfio.com" not in cap["command"]   # hostname never reaches masscan


def test_masscan_ip_target_passes_through(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_masscan({"target": "192.168.64.3"})
    assert "192.168.64.3" in cap["command"]


def test_masscan_unresolvable_hostname_is_clean_error(monkeypatch):
    def boom(h):
        raise OSError("name resolution failed")
    monkeypatch.setattr(halo_tools.socket, "gethostbyname", boom)
    res = _ex()._run_masscan({"target": "nope.invalid"})
    assert res["status"] == "error"
    assert res["error_type"] == "invalid_params"


def test_httpx_default_flags_drop_slow_tech_detect(monkeypatch):
    cap = _capture(monkeypatch)
    _ex()._run_httpx({"target": "beryl.ctfio.com:80"})
    assert "-tech-detect" not in cap["command"]
    assert "-status-code" in cap["command"] and "-title" in cap["command"]


def test_runner_detaches_stdin():
    # The DEVNULL fix is what stops httpx/dnsx/nuclei blocking on the inherited
    # MCP JSON-RPC pipe. Assert a real command returns promptly with stdin closed.
    ex = _ex()
    res = ex._execute_command("cat")   # cat with no args reads stdin → must EOF, not hang
    assert res["status"] == "success"
    assert res["stdout"] == ""
