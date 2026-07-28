"""
Unit tests for the graduated self-audit module (Phase 07, inward eye).

Covers tool currency, arsenal integrity, framework backlog, verdict roll-up, the
autonomy-gated tool-update path (including the safety line that architecture
items are never auto-applied), the cadence check, the wiring to HALO's real
29-tool registry, and the real ModuleHealthProbe. Standard library only; all
external inputs are stubbed, so nothing touches the network or the OS package DB.
"""

import unittest
import warnings

import halo_tools
import self_audit
from self_audit import (FrontierAdvance, ModuleHealthProbe, SelfAuditor,
                        SelfAuditReport)


class StubOracle:
    def __init__(self, inst, lat):
        self._inst, self._lat = inst, lat

    def installed(self, t):
        return self._inst.get(t)

    def latest(self, t):
        return self._lat.get(t)


class StubProber:
    def __init__(self, broken=()):
        self.broken = set(broken)

    def probe(self, t):
        return t not in self.broken


class StubFrontier:
    def __init__(self, advances):
        self._advances = advances

    def advances(self):
        return list(self._advances)


class ToolCurrencyTests(unittest.TestCase):
    def test_run_flags_outdated_and_missing(self):
        oracle = StubOracle(inst={"nmap": "7.94", "nuclei": "3.1.0", "hydra": None},
                            lat={"nmap": "7.94", "nuclei": "3.3.0", "hydra": "9.5"})
        auditor = SelfAuditor(["nmap", "nuclei", "hydra"], oracle,
                              StubProber(), StubFrontier([]), log=lambda *_: None)
        rep = auditor.run()
        self.assertEqual(rep.outdated_tools, ["nuclei"])
        self.assertEqual(rep.missing_tools, ["hydra"])


class ArsenalIntegrityTests(unittest.TestCase):
    def test_run_flags_broken_tool(self):
        oracle = StubOracle(inst={"sqlmap": "1.8"}, lat={"sqlmap": "1.8"})
        auditor = SelfAuditor(["sqlmap"], oracle, StubProber(broken=["sqlmap"]),
                              StubFrontier([]), log=lambda *_: None)
        rep = auditor.run()
        self.assertEqual(rep.broken_tools, ["sqlmap"])


class BacklogTests(unittest.TestCase):
    def test_backlog_excludes_already_adopted(self):
        frontier = StubFrontier([
            FrontierAdvance("Anthropic", "adaptive thinking", halo_has=False, priority="high"),
            FrontierAdvance("OpenAI", "structured tool calls", halo_has=True),
        ])
        auditor = SelfAuditor([], StubOracle({}, {}), StubProber(), frontier,
                              log=lambda *_: None)
        rep = auditor.run()
        items = [a["item"] for a in rep.modernize_backlog]
        self.assertEqual(items, ["adaptive thinking"])


class VerdictTests(unittest.TestCase):
    def test_attention_when_broken(self):
        rep = SelfAuditReport(broken_tools=["sqlmap"])
        self.assertEqual(rep.verdict(), "ATTENTION")

    def test_updates_available_when_only_outdated(self):
        rep = SelfAuditReport(outdated_tools=["nuclei"])
        self.assertEqual(rep.verdict(), "UPDATES_AVAILABLE")

    def test_current_when_clean(self):
        self.assertEqual(SelfAuditReport().verdict(), "CURRENT")


class ApplyUpdatesTests(unittest.TestCase):
    def _report(self):
        return SelfAuditReport(outdated_tools=["nuclei"], missing_tools=["hydra"],
                               modernize_backlog=[{"source": "Anthropic",
                                                   "item": "adaptive thinking"}])

    def test_never_applies_nothing(self):
        auditor = SelfAuditor([], StubOracle({}, {}), StubProber(), StubFrontier([]),
                              update_autonomy="never", log=lambda *_: None)
        self.assertEqual(auditor.apply_tool_updates(self._report()), [])

    def test_ask_denied_applies_nothing(self):
        auditor = SelfAuditor([], StubOracle({}, {}), StubProber(), StubFrontier([]),
                              update_autonomy="ask", approver=lambda t: False,
                              log=lambda *_: None)
        self.assertEqual(auditor.apply_tool_updates(self._report()), [])

    def test_ask_approved_applies_tools(self):
        auditor = SelfAuditor([], StubOracle({}, {}), StubProber(), StubFrontier([]),
                              update_autonomy="ask", approver=lambda t: True,
                              log=lambda *_: None)
        got = auditor.apply_tool_updates(self._report(), updater=lambda t: True)
        self.assertEqual(sorted(got), ["hydra", "nuclei"])

    def test_update_never_touches_architecture_backlog(self):
        """Safety line: apply_tool_updates modifies only tools; modernize backlog
        (architecture) is never auto-applied."""
        applied_targets = []
        auditor = SelfAuditor([], StubOracle({}, {}), StubProber(), StubFrontier([]),
                              update_autonomy="auto", log=lambda *_: None)
        rep = self._report()
        auditor.apply_tool_updates(rep, updater=lambda t: applied_targets.append(t) or True)
        self.assertEqual(sorted(applied_targets), ["hydra", "nuclei"])
        self.assertNotIn("adaptive thinking", applied_targets)
        # backlog is left intact for the operator
        self.assertEqual(rep.modernize_backlog,
                         [{"source": "Anthropic", "item": "adaptive thinking"}])


class CadenceTests(unittest.TestCase):
    def test_no_last_run_is_due(self):
        self.assertTrue(SelfAuditor.due(None))

    def test_recent_run_not_due(self):
        recent = self_audit._utc_now().isoformat() + "Z"
        self.assertFalse(SelfAuditor.due(recent, interval_days=30))

    def test_old_run_is_due(self):
        self.assertTrue(SelfAuditor.due("2000-01-01T00:00:00", interval_days=30))


class RegistryWiringTests(unittest.TestCase):
    def test_registry_is_fully_classified(self):
        """Every HALO tool is either mapped to a binary or explicitly internal."""
        classified = set(self_audit.HALO_TOOL_BINARIES) | self_audit.INTERNAL_TOOLS
        self.assertEqual(classified, set(halo_tools.SUPPORTED_TOOLS))

    def test_for_halo_maps_registry_to_binaries_and_skips_internal(self):
        auditor = SelfAuditor.for_halo(StubOracle({}, {}), StubProber(),
                                       frontier=StubFrontier([]))
        self.assertIn("nmap", auditor.tools)
        self.assertIn("sqlmap", auditor.tools)
        self.assertNotIn("run_command", auditor.tools)
        self.assertNotIn("run_nmap", auditor.tools)
        self.assertEqual(len(auditor.tools), len(self_audit.HALO_TOOL_BINARIES))


class ModuleHealthProbeTests(unittest.TestCase):
    def test_reports_missing_module_as_unhealthy(self):
        probe = ModuleHealthProbe(modules=["engagement",
                                           "definitely_not_a_real_module_xyz"])
        result = probe.check()
        self.assertTrue(result["engagement"])
        self.assertFalse(result["definitely_not_a_real_module_xyz"])

    def test_real_core_modules_import_clean(self):
        probe = ModuleHealthProbe()
        result = probe.check()
        self.assertTrue(all(result.values()), f"unhealthy: {result}")


class DeprecationTests(unittest.TestCase):
    def test_report_and_due_emit_no_deprecation_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            rep = SelfAuditReport()
            SelfAuditor.due(None)
        self.assertTrue(rep.ran_at.endswith("Z"))


if __name__ == "__main__":
    unittest.main()
