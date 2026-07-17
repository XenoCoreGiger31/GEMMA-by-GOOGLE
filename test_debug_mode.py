"""
Unit tests for the graduated debug-mode module (Phase 08).

Covers the separate/bridged/sandboxed debugger: the toggle gate, the fix loop,
the engagement bridge (repair_poc), the mandatory-sandbox refusal, and the real
DockerSandbox adapter that wraps the repo's podman runner. The sandbox runner is
injected as a stub, so every test runs offline with no podman and no network — and
the phase assertion proves the debugger runs network-isolated by design.
"""

import os
import unittest
from types import SimpleNamespace

import debug_mode
from debug_mode import DebugMode, DockerSandbox
from self_audit import ModuleHealthProbe


class StubSandbox:
    """Fails while the bug marker is present, passes once it's gone."""

    def __init__(self, bug="divide(10, 0)"):
        self.bug = bug

    def run(self, code):
        if self.bug in code:
            return {"ok": False, "stdout": "", "stderr": "ZeroDivisionError: division by zero"}
        return {"ok": True, "stdout": "result=5", "stderr": ""}


class StubModel:
    def __init__(self, fix=("divide(10, 0)", "divide(10, 2)")):
        self.old, self.new = fix

    def propose_fix(self, code, stderr):
        return code.replace(self.old, self.new)


BUG_CODE = "print(divide(10, 0))"


class ToggleTests(unittest.TestCase):
    def test_debug_refused_while_off(self):
        dbg = DebugMode(StubSandbox(), StubModel())
        res = dbg.debug(BUG_CODE)
        self.assertFalse(res.fixed)
        self.assertIn("off", res.reason)

    def test_debug_runs_and_fixes_once_enabled(self):
        dbg = DebugMode(StubSandbox(), StubModel(), log=lambda *_: None)
        dbg.enable()
        res = dbg.debug(BUG_CODE)
        self.assertTrue(res.fixed)
        self.assertEqual(res.reason, "fixed")
        self.assertGreaterEqual(len(res.steps), 2)


class BridgeTests(unittest.TestCase):
    def test_repair_poc_works_without_toggle_when_approved(self):
        dbg = DebugMode(StubSandbox(), StubModel(), approver=lambda why: True,
                        log=lambda *_: None)
        self.assertFalse(dbg.enabled)
        res = dbg.repair_poc(BUG_CODE)
        self.assertTrue(res.fixed)

    def test_repair_poc_refused_when_approval_denied(self):
        dbg = DebugMode(StubSandbox(), StubModel(), approver=lambda why: False,
                        log=lambda *_: None)
        res = dbg.repair_poc(BUG_CODE)
        self.assertFalse(res.fixed)
        self.assertIn("approval denied", res.reason)


class SandboxMandatoryTests(unittest.TestCase):
    def test_debug_refused_without_sandbox(self):
        dbg = DebugMode(None, StubModel(), log=lambda *_: None)
        dbg.enable()
        res = dbg.debug(BUG_CODE)
        self.assertFalse(res.fixed)
        self.assertEqual(res.reason, "no sandbox")


class GiveUpTests(unittest.TestCase):
    def test_gives_up_after_max_iters_when_unfixable(self):
        dbg = DebugMode(StubSandbox(), StubModel(fix=("nope", "nope")),
                        max_iters=3, log=lambda *_: None)
        dbg.enable()
        res = dbg.debug(BUG_CODE)
        self.assertFalse(res.fixed)
        self.assertIn("gave up", res.reason)
        self.assertEqual(len(res.steps), 3)


class DockerSandboxTests(unittest.TestCase):
    def _runner(self, returncode=0, stdout="", stderr=""):
        calls = []

        def runner(path, phase, target=None):
            calls.append({"path": path, "phase": phase, "exists": os.path.exists(path)})
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

        return runner, calls

    def test_maps_zero_returncode_to_ok(self):
        runner, _ = self._runner(returncode=0, stdout="done")
        out = DockerSandbox(runner=runner).run("print('hi')")
        self.assertTrue(out["ok"])
        self.assertEqual(out["stdout"], "done")

    def test_maps_nonzero_returncode_to_failure(self):
        runner, _ = self._runner(returncode=1, stderr="boom")
        out = DockerSandbox(runner=runner).run("print('hi')")
        self.assertFalse(out["ok"])
        self.assertEqual(out["stderr"], "boom")

    def test_runs_in_isolated_test_phase_by_default(self):
        runner, calls = self._runner()
        DockerSandbox(runner=runner).run("print('hi')")
        self.assertEqual(calls[0]["phase"], "test")  # --network=none, isolated

    def test_writes_temp_script_and_cleans_it_up(self):
        runner, calls = self._runner()
        DockerSandbox(runner=runner).run("print('hi')")
        self.assertTrue(calls[0]["exists"])           # file was present during the run
        self.assertFalse(os.path.exists(calls[0]["path"]))  # removed afterward


class SandboxedConstructorTests(unittest.TestCase):
    def test_sandboxed_wires_docker_sandbox_and_runs_end_to_end(self):
        def runner(path, phase, target=None):
            code = open(path).read()
            ok = "divide(10, 0)" not in code
            return SimpleNamespace(returncode=0 if ok else 1, stdout="",
                                   stderr="" if ok else "ZeroDivisionError")
        dbg = DebugMode.sandboxed(StubModel(), runner=runner, log=lambda *_: None)
        dbg.enable()
        res = dbg.debug(BUG_CODE)
        self.assertTrue(res.fixed)


class HealthCoverageTests(unittest.TestCase):
    def test_graduated_module_is_covered_by_self_audit_health(self):
        self.assertIn("debug_mode", ModuleHealthProbe.DEFAULT_MODULES)


if __name__ == "__main__":
    unittest.main()
