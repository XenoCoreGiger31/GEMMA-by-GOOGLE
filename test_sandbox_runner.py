"""Tests for sandbox/run_sandbox.py — the two-phase PoC container runner.

Live bug (session_20260723_112744, port 1099): a model-authored script blocked on a
socket with no timeout; run_sandbox's podman subprocess hit its 120s wall and raised
TimeoutExpired, which propagated BEFORE the '=== EXIT ===' contract was printed. The
caller (_run_exploit) then saw no marker and reported the opaque "No EXIT marker from
sandbox" after eating 120s.

The runner must instead ALWAYS emit a parseable contract: a hung PoC is killed and
reported as a clean exit 124 with partial output preserved. The podman call is injected
so these run with no podman/container/network.
"""
import subprocess

import sandbox.run_sandbox as rs


def test_hung_poc_returns_clean_exit_124_with_partial_output():
    def fake_runner(cmd, **kw):
        raise subprocess.TimeoutExpired(
            cmd=cmd, timeout=kw.get("timeout"), output="partial stdout", stderr="")

    out, err, rc = rs.run("x.py", "attack", target="10.0.0.1", timeout=5,
                          _runner=fake_runner)
    assert rc == 124
    assert "partial stdout" in out
    assert "killed" in err.lower()


def test_timeout_still_produces_parseable_contract():
    # The whole point: even on timeout the emitted contract has an EXIT marker, so
    # _run_exploit parses a real failure instead of "No EXIT marker from sandbox".
    def fake_runner(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kw.get("timeout"))

    out, err, rc = rs.run("x.py", "attack", target="10.0.0.1", timeout=5,
                          _runner=fake_runner)
    contract = rs.format_contract(out, err, rc)
    assert "=== EXIT 124 ===" in contract


def test_normal_completion_passes_through_stdout_and_code():
    class _R:
        stdout = "uid=0(root) gid=0(root)"
        stderr = ""
        returncode = 0

    out, err, rc = rs.run("x.py", "test", _runner=lambda cmd, **kw: _R())
    assert out == "uid=0(root) gid=0(root)"
    assert rc == 0


def test_contract_matches_run_exploit_parser():
    c = rs.format_contract("uid=0(root)", "", 0)
    assert "=== STDOUT ===" in c and "=== STDERR ===" in c and "=== EXIT 0 ===" in c
    # Mimic _run_exploit's stdout extraction between the markers.
    inner = c.split("=== STDOUT ===", 1)[1].split("=== STDERR ===", 1)[0].strip()
    assert inner == "uid=0(root)"


def test_test_phase_isolates_network_attack_phase_reaches_target():
    assert "--network=none" in rs.build_cmd("x.py", "test")
    # ATTACK phase shares host netns by default so it routes to the LAN target.
    assert "--network=host" in rs.build_cmd("x.py", "attack")
    # Untrusted-PoC isolation invariants stay put.
    assert "--cap-drop=ALL" in rs.build_cmd("x.py", "attack")
    assert "--read-only" in rs.build_cmd("x.py", "attack")
