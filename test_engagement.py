"""
Unit tests for engagement.py's config loader and tool classification.

Standard library only (unittest + tempfile) plus PyYAML, which is already a
HALO runtime dependency (requirements.txt).
"""

import os
import tempfile
import unittest

from engagement import (AuthorizationError, Engagement, EngagementContext,
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
                    "operator: analyst\n"
                )
            ctx = load_engagement_context(path)
            self.assertIsInstance(ctx, EngagementContext)
            self.assertEqual(ctx.authorization, "Written CISO approval #2026-07-13")
            self.assertEqual(ctx.scope_targets, ["10.0.0.0/24", "app.client.example"])
            self.assertEqual(ctx.operator, "analyst")

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


class OperatorTrustTests(unittest.TestCase):
    def _ctx(self, **kw):
        base = dict(role="r", task="t", authorization="self-auth lab",
                    purpose="p", scope_targets=[])
        base.update(kw)
        return EngagementContext(**base)

    def test_empty_scope_allowed_only_with_trust(self):
        # Without trust, empty scope is refused (the standing invariant)...
        with self.assertRaises(AuthorizationError):
            self._ctx(scope_targets=[], trust_operator=False)
        # ...with trust, an empty pre-configured scope is permitted.
        ctx = self._ctx(scope_targets=[], trust_operator=True)
        self.assertEqual(ctx.scope_targets, [])

    def test_admit_makes_typed_target_the_scope(self):
        eng = Engagement(self._ctx(trust_operator=True))
        self.assertFalse(eng.scope.in_scope("katz.ctfio.com"))
        eng.admit_operator_target("katz.ctfio.com")
        self.assertTrue(eng.authorize("halo", "recon", "katz.ctfio.com"))
        self.assertEqual(eng.ctx.scope_targets, ["katz.ctfio.com"])

    def test_admit_replaces_prior_target_no_drift(self):
        # Switching targets replaces scope; the old host is no longer in scope,
        # and a host the model merely "discovers" is never admitted.
        eng = Engagement(self._ctx(scope_targets=["old.example"], trust_operator=True))
        eng.admit_operator_target("new.example")
        self.assertTrue(eng.scope.in_scope("new.example"))
        self.assertFalse(eng.scope.in_scope("old.example"))
        self.assertFalse(eng.scope.in_scope("192.168.1.50"))  # undiscovered pivot

    def test_admit_is_noop_without_trust(self):
        eng = Engagement(self._ctx(scope_targets=["only.example"], trust_operator=False))
        eng.admit_operator_target("attacker-controlled.example")
        self.assertFalse(eng.scope.in_scope("attacker-controlled.example"))
        self.assertEqual(eng.ctx.scope_targets, ["only.example"])

    def test_trust_operator_loads_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "engagement.yaml")
            with open(path, "w") as f:
                f.write(
                    "role: x\ntask: y\nauthorization: self-auth\npurpose: z\n"
                    "trust_operator: true\n"
                )
            ctx = load_engagement_context(path)
            self.assertTrue(ctx.trust_operator)
            self.assertEqual(ctx.scope_targets, [])


class ClassifyTests(unittest.TestCase):
    def test_recon_tools(self):
        self.assertEqual(classify("run_nmap"), "recon")
        self.assertEqual(classify("run_httpx"), "recon")

    def test_http_fetch_tools_are_recon_not_gated(self):
        # curl/wget are benign GETs — they must run under 'auto', not trip the
        # per-call approval gate during a web sweep.
        self.assertEqual(classify("run_curl"), "recon")
        self.assertEqual(classify("run_wget"), "recon")

    def test_credential_attack_tools(self):
        self.assertEqual(classify("run_hydra"), "credential_attack")

    def test_destructive_tools(self):
        self.assertEqual(classify("run_command"), "destructive")

    def test_unknown_tool_defaults_to_exploitation(self):
        self.assertEqual(classify("some_future_tool"), "exploitation")


if __name__ == "__main__":
    unittest.main()
