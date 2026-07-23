"""
Unit tests for agent_loop.py's engagement-authorization gate in execute_step().

Standard library only (unittest + unittest.mock). Sets HALO_LOG_DIR to a temp
directory before importing agent_loop so the module's log-setup side effects
don't touch a real filesystem path.

execute_step() is async and runs tools over an MCP ClientSession, so these tests
drive it with asyncio.run() and mock the transport seam (agent_loop._call_tool)
rather than an HTTP client. The gate assertions are unchanged: denied calls must
never reach the tool, authorized ones must dispatch exactly once, and run_exploit
must still pass through the two-gate human-approval flow.
"""

import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

_TMP_LOG_DIR = tempfile.mkdtemp()
os.environ["HALO_LOG_DIR"] = _TMP_LOG_DIR

import agent_loop  # noqa: E402  (must follow the HALO_LOG_DIR override above)
from engagement import Engagement, EngagementContext

# The session object is only ever handed to the mocked _call_tool, so a sentinel
# is enough — no real MCP subprocess is spawned in these tests.
_SESSION = object()


def _make_engagement(scope_targets, autonomy=None, approver=None):
    ctx = EngagementContext(
        role="test", task="test", authorization="test-approval-001",
        purpose="test", scope_targets=scope_targets, operator="test",
    )
    return Engagement(ctx, autonomy=autonomy, approver=approver)


def _run_step(step):
    """Drive the async execute_step to completion against the sentinel session."""
    return asyncio.run(agent_loop.execute_step(_SESSION, step))


class ExecuteStepGatingTests(unittest.TestCase):
    def setUp(self):
        agent_loop.ENGAGEMENT = None

    def test_no_engagement_configured_denies(self):
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            output, ok = _run_step({"tool": "run_nmap", "target": "10.0.0.5"})
        self.assertEqual(output, "")
        self.assertFalse(ok)
        mock_call.assert_not_awaited()

    def test_out_of_scope_target_denies_without_calling_tool(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            output, ok = _run_step({"tool": "run_nmap", "target": "8.8.8.8"})
        self.assertFalse(ok)
        mock_call.assert_not_awaited()

    def test_in_scope_recon_tool_is_dispatched(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"stdout": "22/tcp open ssh", "status": "success"}
            output, ok = _run_step({"tool": "run_nmap", "target": "10.0.0.5"})
        self.assertTrue(ok)
        mock_call.assert_awaited_once()

    def test_destructive_tool_never_dispatched_even_in_scope(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            output, ok = _run_step(
                {"tool": "run_command", "target": "10.0.0.5", "command": "id"})
        self.assertFalse(ok)
        mock_call.assert_not_awaited()

    def test_credential_attack_requires_approval(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: True)
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"stdout": "", "status": "success"}
            output, ok = _run_step({"tool": "run_hydra", "target": "10.0.0.5"})
        self.assertTrue(ok)
        mock_call.assert_awaited_once()

    def test_credential_attack_denied_without_approval(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: False)
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call:
            output, ok = _run_step({"tool": "run_hydra", "target": "10.0.0.5"})
        self.assertFalse(ok)
        mock_call.assert_not_awaited()

    def test_run_exploit_still_goes_through_two_gate_flow_after_authorize(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: True)
        with patch("agent_loop._call_tool", new_callable=AsyncMock) as mock_call, \
             patch("builtins.input", return_value="n"):
            output, ok = _run_step(
                {"tool": "run_exploit", "code": "print(1)", "target": "10.0.0.5"})
        self.assertFalse(ok)
        mock_call.assert_not_awaited()  # sandbox entry declined -> no MCP call at all


if __name__ == "__main__":
    unittest.main()
