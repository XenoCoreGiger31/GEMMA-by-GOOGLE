"""
Unit tests for agent_loop.py's engagement-authorization gate in execute_step().

Standard library only (unittest + unittest.mock). Sets HALO_LOG_DIR to a temp
directory before importing agent_loop so the module's log-setup side effects
don't touch a real filesystem path.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_LOG_DIR = tempfile.mkdtemp()
os.environ["HALO_LOG_DIR"] = _TMP_LOG_DIR

import agent_loop  # noqa: E402  (must follow the HALO_LOG_DIR override above)
from engagement import Engagement, EngagementContext


def _make_engagement(scope_targets, autonomy=None, approver=None):
    ctx = EngagementContext(
        role="test", task="test", authorization="test-approval-001",
        purpose="test", scope_targets=scope_targets, operator="test",
    )
    return Engagement(ctx, autonomy=autonomy, approver=approver)


class ExecuteStepGatingTests(unittest.TestCase):
    def setUp(self):
        agent_loop.ENGAGEMENT = None

    def test_no_engagement_configured_denies(self):
        with patch("agent_loop.requests.post") as mock_post:
            output, ok = agent_loop.execute_step(
                {"tool": "run_nmap", "target": "10.0.0.5"})
        self.assertEqual(output, "")
        self.assertFalse(ok)
        mock_post.assert_not_called()

    def test_out_of_scope_target_denies_without_calling_tool(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop.requests.post") as mock_post:
            output, ok = agent_loop.execute_step(
                {"tool": "run_nmap", "target": "8.8.8.8"})
        self.assertFalse(ok)
        mock_post.assert_not_called()

    def test_in_scope_recon_tool_is_dispatched(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop.requests.post") as mock_post:
            mock_post.return_value.json.return_value = {
                "stdout": "22/tcp open ssh", "status": "success"}
            output, ok = agent_loop.execute_step(
                {"tool": "run_nmap", "target": "10.0.0.5"})
        self.assertTrue(ok)
        mock_post.assert_called_once()

    def test_destructive_tool_never_dispatched_even_in_scope(self):
        agent_loop.ENGAGEMENT = _make_engagement(scope_targets=["10.0.0.0/24"])
        with patch("agent_loop.requests.post") as mock_post:
            output, ok = agent_loop.execute_step(
                {"tool": "run_command", "target": "10.0.0.5", "command": "id"})
        self.assertFalse(ok)
        mock_post.assert_not_called()

    def test_credential_attack_requires_approval(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: True)
        with patch("agent_loop.requests.post") as mock_post:
            mock_post.return_value.json.return_value = {
                "stdout": "", "status": "success"}
            output, ok = agent_loop.execute_step(
                {"tool": "run_hydra", "target": "10.0.0.5"})
        self.assertTrue(ok)
        mock_post.assert_called_once()

    def test_credential_attack_denied_without_approval(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: False)
        with patch("agent_loop.requests.post") as mock_post:
            output, ok = agent_loop.execute_step(
                {"tool": "run_hydra", "target": "10.0.0.5"})
        self.assertFalse(ok)
        mock_post.assert_not_called()

    def test_run_exploit_still_goes_through_two_gate_flow_after_authorize(self):
        agent_loop.ENGAGEMENT = _make_engagement(
            scope_targets=["10.0.0.0/24"], approver=lambda cls, tgt: True)
        with patch("agent_loop.requests.post") as mock_post, \
             patch("builtins.input", return_value="n"):
            output, ok = agent_loop.execute_step(
                {"tool": "run_exploit", "code": "print(1)", "target": "10.0.0.5"})
        self.assertFalse(ok)
        mock_post.assert_not_called()  # sandbox entry declined -> no MCP call at all


if __name__ == "__main__":
    unittest.main()
