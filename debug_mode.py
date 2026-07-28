#!/usr/bin/env python3
"""
debug_mode.py — HALO's isolated, sandboxed debugger.

Implements the isolated debugger specified in 08_DEBUG_MODE.md.

Design: SEPARATE, BRIDGED, SANDBOXED.
  * SEPARATE  — a standalone mode behind an explicit toggle (off by default). A
                debugger must freely write and run code; the security loop must
                gate everything. Mixing the two plumbings is dangerous, so they
                are kept apart. Debug Mode has its OWN state, not the attack loop's.
  * BRIDGED   — the security loop can still CALL the debugger for its own failures
                (repair a failed exploit PoC, diagnose a broken tool run — the
                repo's existing debugger_agent.py role) WITHOUT flipping the whole
                system into debug mode.
  * SANDBOXED — writing-and-running code is the same risk class as run_exploit, so
                every execution goes through a sandbox (the repo's sandbox/ Docker
                runner in deployment). No sandbox -> it refuses to run.

The debug loop: run -> read error -> propose fix -> apply -> re-run, up to N.
Model, sandbox, and approver are INJECTED, so it runs and is testable offline.
Pure stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol


class Sandbox(Protocol):
    """Executes code in isolation and returns the outcome. Real impl routes to
    sandbox/run_sandbox.py (Docker, no network in the test phase)."""
    def run(self, code: str) -> dict: ...   # {"ok": bool, "stdout": str, "stderr": str}


class FixModel(Protocol):
    """Proposes a corrected version of `code` given the error text. Isolated:
    it never has tool access and treats the code as data."""
    def propose_fix(self, code: str, stderr: str) -> str: ...


class DockerSandbox:
    """Real Sandbox: runs `code` isolated in the repo's podman sandbox
    (sandbox/run_sandbox.py). Uses the `test` phase (--network=none), so debugger
    executions are network-isolated by design — the debugger fixes and verifies
    code, it cannot reach a target. Running a repaired script live against a target
    (the `attack` phase, network on) is a separate, approval-gated capability and
    deliberately not wired here.

    The runner is injectable, so this adapter tests fully offline without podman.
    """

    def __init__(self, runner: Callable[..., object] | None = None,
                 phase: str = "test"):
        self._runner = runner
        self.phase = phase

    def _script_runner(self) -> Callable[..., object]:
        if self._runner is not None:
            return self._runner
        from sandbox.run_sandbox import run  # lazy: only the real path needs podman
        return run

    def run(self, code: str) -> dict:
        import os
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            proc = self._script_runner()(path, self.phase)
        finally:
            os.unlink(path)
        return {
            "ok": getattr(proc, "returncode", 1) == 0,
            "stdout": getattr(proc, "stdout", "") or "",
            "stderr": getattr(proc, "stderr", "") or "",
        }


@dataclass
class DebugStep:
    attempt: int
    ok: bool
    stderr: str = ""
    changed: bool = False


@dataclass
class DebugResult:
    fixed: bool
    final_code: str
    steps: list[DebugStep] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict:
        return {"fixed": self.fixed, "attempts": len(self.steps),
                "reason": self.reason,
                "trace": [s.__dict__ for s in self.steps]}


class DebugMode:
    def __init__(self, sandbox: Sandbox | None, model: FixModel,
                 max_iters: int = 4, approver: Callable[[str], bool] | None = None,
                 log: Callable[[str], None] = print):
        self.sandbox = sandbox
        self.model = model
        self.max_iters = max_iters
        self.approver = approver or (lambda why: True)
        self.log = log
        self.enabled = False          # toggle — OFF by default

    @classmethod
    def sandboxed(cls, model: FixModel, phase: str = "test",
                  runner: Callable[..., object] | None = None, max_iters: int = 4,
                  approver: Callable[[str], bool] | None = None,
                  log: Callable[[str], None] = print) -> "DebugMode":
        """Wire the debugger to the repo's real podman sandbox, network-isolated in
        the `test` phase. The runner is injectable for offline tests."""
        return cls(DockerSandbox(runner=runner, phase=phase), model,
                   max_iters=max_iters, approver=approver, log=log)

    # ---- the clickable toggle ----
    def enable(self) -> None:
        self.enabled = True
        self.log("[DEBUG] mode ENABLED (isolated from the security framework)")

    def disable(self) -> None:
        self.enabled = False
        self.log("[DEBUG] mode DISABLED")

    def _require_sandbox(self) -> bool:
        if self.sandbox is None:
            self.log("[DEBUG] refused: no sandbox available (code exec is gated "
                     "behind the sandbox by design)")
            return False
        return True

    # ---- primary: full debug loop (requires the toggle on) ----
    def debug(self, code: str) -> DebugResult:
        if not self.enabled:
            return DebugResult(False, code, reason="debug mode is off — enable() first")
        if not self._require_sandbox():
            return DebugResult(False, code, reason="no sandbox")
        return self._loop(code, gate_reason="debug-mode fix")

    # ---- bridge: callable BY the security loop without full debug mode ----
    def repair_poc(self, code: str) -> DebugResult:
        """Fix a failed exploit PoC / broken tool script for the engagement.
        Still sandboxed and still gated — just doesn't require the global toggle.
        Mirrors debugger_agent.py's 'diagnose a failed run' role, upgraded."""
        if not self._require_sandbox():
            return DebugResult(False, code, reason="no sandbox")
        if not self.approver("security loop requests PoC repair in sandbox"):
            return DebugResult(False, code, reason="approval denied")
        return self._loop(code, gate_reason="engagement PoC repair")

    # ---- shared fix loop ----
    def _loop(self, code: str, gate_reason: str) -> DebugResult:
        result = DebugResult(False, code)
        for i in range(1, self.max_iters + 1):
            outcome = self.sandbox.run(code)
            ok = bool(outcome.get("ok"))
            stderr = outcome.get("stderr", "")
            step = DebugStep(attempt=i, ok=ok, stderr=stderr[:300])
            if ok:
                step.changed = i > 1
                result.steps.append(step)
                result.fixed = True
                result.final_code = code
                result.reason = "passed" if i == 1 else "fixed"
                self.log(f"[DEBUG] attempt {i}: PASS ({result.reason})")
                return result
            # failed -> propose a fix and re-run
            self.log(f"[DEBUG] attempt {i}: FAIL -> {stderr[:80]}")
            if not self.approver(gate_reason):
                step.stderr += " | fix not authorized"
                result.steps.append(step)
                result.reason = "approval denied"
                return result
            new_code = self.model.propose_fix(code, stderr)
            step.changed = new_code != code
            result.steps.append(step)
            code = new_code
        result.final_code = code
        result.reason = f"gave up after {self.max_iters} attempts"
        self.log(f"[DEBUG] {result.reason}")
        return result


if __name__ == "__main__":
    # Offline demo: a sandbox that "runs" python-ish code by checking for a known
    # bug marker, and a model that fixes it. Proves the loop without Docker.
    class StubSandbox:
        def run(self, code):
            if "divide(10, 0)" in code:            # the bug
                return {"ok": False, "stdout": "", "stderr": "ZeroDivisionError: division by zero"}
            return {"ok": True, "stdout": "result=5", "stderr": ""}

    class StubModel:
        def propose_fix(self, code, stderr):
            return code.replace("divide(10, 0)", "divide(10, 2)")

    dbg = DebugMode(StubSandbox(), StubModel(), approver=lambda why: True)

    # (1) primary path needs the toggle
    print("off ->", dbg.debug("print(divide(10, 0))").as_dict())
    dbg.enable()
    import json
    print("on  ->", json.dumps(dbg.debug("print(divide(10, 0))").as_dict(), indent=2))

    # (2) bridge path: security loop repairs a PoC without enabling debug mode
    dbg.disable()
    print("bridge ->", dbg.repair_poc("print(divide(10, 0))").as_dict())

    # (3) sandbox is mandatory
    nosbx = DebugMode(None, StubModel()); nosbx.enable()
    print("no-sandbox ->", nosbx.debug("whatever").as_dict())
