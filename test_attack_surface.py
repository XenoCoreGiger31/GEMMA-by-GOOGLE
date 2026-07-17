"""
Unit tests for the graduated attack-surface modules (Phase 04).

Covers the inventory parser/differ (asm_inventory) and the authorization-gated
continuous scanner (continuous_scanner), including its wiring to the engagement
safety spine's ScopeGuard. Standard library only; the scanner is exercised with
a stub PortProbe so no real network traffic is generated.
"""

import unittest
import warnings
from unittest import mock

import asm_inventory
from asm_inventory import Asset
from continuous_scanner import ContinuousScanner, ScanResult
from engagement import Engagement, EngagementContext


INVENTORY_MD = """\
# heading text that is not a table

| ID | Asset / name | Tech + version | Self-hosted / 3rd-party | Auth method | Deployed here | Web? DB? API? | Exposed ports/endpoints | Owner | Last audited | Notes / known issues |
|----|--------------|----------------|--------------------------|-------------|---------------|---------------|--------------------------|-------|--------------|----------------------|
| AS-0001 | _e.g. marketing site_ | _e.g. Nginx_ | _self-hosted_ | _SSH_ | _static_ | web | 80,443 | _you_ | _YYYY-MM-DD_ | _fill in_ |
| AS-0100 | api-gw | Kong 3.4 | self-hosted | mTLS | prod API | API | 443,8001 | ops | 2026-07-01 | admin 8001 exposed |
"""


class StubProbe:
    """Deterministic PortProbe: returns a preset open-port set, touches nothing."""

    def __init__(self, open_set):
        self.open_set = set(open_set)
        self.calls = []

    def open_ports(self, host, ports):
        self.calls.append(host)
        return {p for p in ports if p in self.open_set}


def _engagement(scope_targets):
    ctx = EngagementContext(
        role="Security Researcher",
        task="Authorized testing",
        authorization="Written approval",
        purpose="Find and patch",
        scope_targets=scope_targets,
        operator="chris",
    )
    return Engagement(ctx)


class InventoryParseTests(unittest.TestCase):
    def test_parse_skips_template_and_seed_rows_and_extracts_real_asset(self):
        assets = asm_inventory.parse(INVENTORY_MD)
        self.assertEqual([a.id for a in assets], ["AS-0100"])
        self.assertEqual(assets[0].name, "api-gw")
        self.assertEqual(assets[0].tech, "Kong 3.4")
        self.assertEqual(assets[0].ports_set(), {"443", "8001"})


class InventoryDiffTests(unittest.TestCase):
    def test_diff_detects_ports_opened_removed_and_tech_drift(self):
        old = [Asset(id="AS-1", name="a", tech="Nginx 1.24", ports="80"),
               Asset(id="AS-2", name="b", tech="Kong 3.4", ports="443")]
        new = [Asset(id="AS-1", name="a", tech="Nginx 1.25", ports="80,443")]
        events = asm_inventory.diff(old, new)
        types = {e["type"] for e in events}
        self.assertIn("ports_opened", types)
        self.assertIn("removed", types)
        self.assertIn("tech_drift", types)
        opened = next(e for e in events if e["type"] == "ports_opened")
        self.assertEqual(opened["detail"], ["443"])
        removed = next(e for e in events if e["type"] == "removed")
        self.assertEqual(removed["asset"], "AS-2")


class ScannerAuthorizationTests(unittest.TestCase):
    def test_refuses_out_of_scope_host(self):
        scanner = ContinuousScanner(in_scope=lambda h: h == "10.0.0.5",
                                    probe=StubProbe({80}))
        with self.assertRaises(PermissionError):
            scanner.scan_host("10.0.0.9")

    def test_accepts_in_scope_host(self):
        scanner = ContinuousScanner(in_scope=lambda h: h == "10.0.0.5",
                                    probe=StubProbe({80, 443}))
        res = scanner.scan_host("10.0.0.5", ports=[80, 22, 443])
        self.assertIsInstance(res, ScanResult)
        self.assertEqual(set(res.open_ports), {80, 443})


class EngagementWiringTests(unittest.TestCase):
    def test_for_engagement_uses_scope_guard(self):
        eng = _engagement(["10.0.0.5"])
        scanner = ContinuousScanner.for_engagement(eng, probe=StubProbe({80}))
        res = scanner.scan_host("10.0.0.5")
        self.assertEqual(set(res.open_ports), {80})
        with self.assertRaises(PermissionError):
            scanner.scan_host("10.0.0.9")

    def test_cidr_scope_authorizes_contained_ip(self):
        eng = _engagement(["10.0.0.0/24"])
        scanner = ContinuousScanner.for_engagement(eng, probe=StubProbe({22}))
        res = scanner.scan_host("10.0.0.77")
        self.assertEqual(set(res.open_ports), {22})
        with self.assertRaises(PermissionError):
            scanner.scan_host("10.0.1.1")


class SweepTests(unittest.TestCase):
    def test_sweep_skips_out_of_scope_hosts_and_scans_the_rest(self):
        events = []
        eng = _engagement(["10.0.0.5"])
        scanner = ContinuousScanner.for_engagement(
            eng, probe=StubProbe({80}), on_event=events.append)
        snap = scanner.sweep(["10.0.0.5", "10.0.0.9"])
        self.assertIn("10.0.0.5", snap)
        self.assertNotIn("10.0.0.9", snap)
        self.assertTrue(any(e["type"] == "out_of_scope" and e["host"] == "10.0.0.9"
                            for e in events))


class SnapshotDiffTests(unittest.TestCase):
    def test_diff_snapshot_flags_newly_opened_port_for_ttp_chain(self):
        events = []
        scanner = ContinuousScanner(in_scope=lambda h: True, on_event=events.append)
        prev = ScanResult(host="10.0.0.5", open_ports=[80])
        curr = ScanResult(host="10.0.0.5", open_ports=[80, 443])
        out = scanner.diff_snapshot("10.0.0.5", prev, curr)
        opened = [e for e in out if e["type"] == "port_opened"]
        self.assertEqual([e["port"] for e in opened], [443])
        self.assertEqual(opened[0]["action"], "hand to ttp_chain.validate")

    def test_diff_snapshot_flags_closed_port(self):
        events = []
        scanner = ContinuousScanner(in_scope=lambda h: True, on_event=events.append)
        prev = ScanResult(host="10.0.0.5", open_ports=[80, 443])
        curr = ScanResult(host="10.0.0.5", open_ports=[80])
        out = scanner.diff_snapshot("10.0.0.5", prev, curr)
        self.assertEqual([e["port"] for e in out if e["type"] == "port_closed"], [443])

    def test_first_sight_treats_all_open_ports_as_newly_opened(self):
        scanner = ContinuousScanner(in_scope=lambda h: True, on_event=lambda e: None)
        curr = ScanResult(host="10.0.0.5", open_ports=[22, 80])
        out = scanner.diff_snapshot("10.0.0.5", None, curr)
        self.assertEqual(sorted(e["port"] for e in out if e["type"] == "port_opened"),
                         [22, 80])


class CertExpiryTests(unittest.TestCase):
    def test_cert_expiring_event_emitted_when_near_expiry(self):
        events = []
        scanner = ContinuousScanner(in_scope=lambda h: True,
                                    probe=StubProbe({443}), on_event=events.append)
        with mock.patch("continuous_scanner._tls_days_to_expiry", return_value=5):
            res = scanner.scan_host("10.0.0.5")
        self.assertEqual(res.tls_expiry_days.get(443), 5)
        self.assertTrue(any(e["type"] == "cert_expiring" and e["port"] == 443
                            and e["days"] == 5 for e in events))

    def test_no_cert_event_when_expiry_comfortably_far(self):
        events = []
        scanner = ContinuousScanner(in_scope=lambda h: True,
                                    probe=StubProbe({443}), on_event=events.append)
        with mock.patch("continuous_scanner._tls_days_to_expiry", return_value=200):
            scanner.scan_host("10.0.0.5")
        self.assertFalse(any(e["type"] == "cert_expiring" for e in events))


class DeprecationTests(unittest.TestCase):
    def test_scan_emits_no_deprecation_warning(self):
        scanner = ContinuousScanner(in_scope=lambda h: True, probe=StubProbe({80}))
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            res = scanner.scan_host("127.0.0.1")
        self.assertTrue(res.scanned_at)


if __name__ == "__main__":
    unittest.main()
