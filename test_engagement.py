"""
Unit tests for engagement.py's config loader and tool classification.

Standard library only (unittest + tempfile) plus PyYAML, which is already a
HALO runtime dependency (requirements.txt).
"""

import os
import tempfile
import unittest

from engagement import (AuthorizationError, EngagementContext,
                        classify, load_engagement_context)


class LoadEngagementContextTests(unittest.TestCase):
    def test_missing_file_raises_authorization_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = os.path.join(tmpdir, "does_not_exist.yaml")
            with self.assertRaises(AuthorizationError):
                load_engagement_context(missing_path)

    def test_valid_file_loads_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "engagement.yaml")
            with open(path, "w") as f:
                f.write(
                    "role: Senior Security Researcher\n"
                    "task: Authorized penetration testing\n"
                    'authorization: "Written CISO approval #2026-07-13"\n'
                    "purpose: Identify vulnerabilities to patch\n"
                    "scope_targets:\n"
                    "  - 10.0.0.0/24\n"
                    "  - app.client.example\n"
                    "operator: chris\n"
                )
            ctx = load_engagement_context(path)
            self.assertIsInstance(ctx, EngagementContext)
            self.assertEqual(ctx.authorization, "Written CISO approval #2026-07-13")
            self.assertEqual(ctx.scope_targets, ["10.0.0.0/24", "app.client.example"])
            self.assertEqual(ctx.operator, "chris")

    def test_file_missing_authorization_field_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "engagement.yaml")
            with open(path, "w") as f:
                f.write(
                    "role: x\ntask: y\nauthorization: ''\npurpose: z\n"
                    "scope_targets:\n  - 10.0.0.0/24\n"
                )
            with self.assertRaises(AuthorizationError):
                load_engagement_context(path)


class ClassifyTests(unittest.TestCase):
    def test_recon_tools(self):
        self.assertEqual(classify("run_nmap"), "recon")
        self.assertEqual(classify("run_httpx"), "recon")

    def test_credential_attack_tools(self):
        self.assertEqual(classify("run_hydra"), "credential_attack")

    def test_destructive_tools(self):
        self.assertEqual(classify("run_command"), "destructive")

    def test_unknown_tool_defaults_to_exploitation(self):
        self.assertEqual(classify("some_future_tool"), "exploitation")


if __name__ == "__main__":
    unittest.main()
