"""
Unit tests for the graduated security-report module (final phase).

Covers the defensive web-vuln knowledge base (steps 1-3), the findings -> report
builder (step 4), and the convenience that single-sources the report header and
chain of custody from a real Engagement. Standard library only; the report is
pure string assembly, so nothing here touches the network or executes anything.
"""

import unittest

import security_report
from security_report import Finding, build_report, build_report_for_engagement
from engagement import Engagement, EngagementContext
from self_audit import ModuleHealthProbe


def _engagement():
    ctx = EngagementContext(
        role="Senior Security Researcher",
        task="Authorized penetration testing",
        authorization="Written CISO approval #2026-07-13",
        purpose="Identify vulnerabilities so the client can patch them",
        scope_targets=["10.0.0.0/24"],
        operator="chris",
    )
    return Engagement(ctx)


HEADER = {"role": "Researcher", "task": "Assessment",
          "authorization": "Written approval #7", "purpose": "Harden",
          "scope_targets": ["10.0.0.0/24"]}


class KnowledgeBaseTests(unittest.TestCase):
    def test_enumerate_lists_all_web_vulns(self):
        names = security_report.enumerate_web_vulns()
        self.assertEqual(len(names), len(security_report.WEB_VULNS))
        self.assertTrue(any("SQL Injection" in n for n in names))

    def test_safe_example_is_marked_illustration_only(self):
        self.assertIn("illustration only", security_report.safe_example("sqli"))

    def test_patch_guidance_gives_a_fix(self):
        self.assertIn("parameterized", security_report.patch_guidance("sqli").lower())


class BuildReportTests(unittest.TestCase):
    def test_report_includes_header_findings_and_custody(self):
        findings = [Finding("open_port", "10.0.0.5", "22/tcp ssh open", "low",
                            "Restrict SSH to VPN.")]
        custody = [{"ts": "2026-07-13T18:00:00Z", "actor": "halo", "action": "recon",
                    "target": "10.0.0.5", "decision": "AUTHORIZED"}]
        report = build_report(HEADER, findings, custody)
        self.assertIn("Written approval #7", report)
        self.assertIn("22/tcp ssh open", report)
        self.assertIn("Chain of Custody", report)
        self.assertIn("halo", report)

    def test_education_section_toggles_off(self):
        with_edu = build_report(HEADER, [], [], include_education=True)
        without_edu = build_report(HEADER, [], [], include_education=False)
        self.assertIn("Common Web Vulnerabilities", with_edu)
        self.assertNotIn("Common Web Vulnerabilities", without_edu)

    def test_empty_findings_and_custody_render_gracefully(self):
        report = build_report(HEADER, [], [])
        self.assertIn("No findings recorded", report)
        self.assertIn("No actions recorded", report)


class EngagementWiringTests(unittest.TestCase):
    def test_report_single_sources_header_and_custody_from_engagement(self):
        eng = _engagement()
        eng.custody.record("halo", "recon", "10.0.0.5", "AUTHORIZED")
        findings = [Finding("ssh_key", "10.0.0.5", "legacy RSA-1024 key", "medium",
                            "Rotate to ed25519.")]
        report = build_report_for_engagement(eng, findings)
        self.assertIn("Written CISO approval #2026-07-13", report)  # from ctx
        self.assertIn("legacy RSA-1024 key", report)                # the finding
        self.assertIn("AUTHORIZED", report)                         # from custody log

    def test_report_reflects_authorized_actions_recorded_via_the_gate(self):
        eng = _engagement()
        eng.authorize("halo", "recon", "10.0.0.5")  # in scope + auto -> AUTHORIZED
        report = build_report_for_engagement(eng, [])
        self.assertIn("recon", report)
        self.assertIn("10.0.0.5", report)


class HealthCoverageTests(unittest.TestCase):
    def test_graduated_module_is_covered_by_self_audit_health(self):
        self.assertIn("security_report", ModuleHealthProbe.DEFAULT_MODULES)


if __name__ == "__main__":
    unittest.main()
