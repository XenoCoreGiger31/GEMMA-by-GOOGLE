"""
Unit tests for the live frontier-currency feed (Phase 07, outward eye).

The outward eye reaches out to public sources (GitHub releases, MITRE ATT&CK,
model endpoints) and diffs them against what HALO has, producing the modernize
backlog. Here every HTTP call is served by a stub http_get, so the tests run
fully offline and deterministically — and the offline-resilience test proves the
feed degrades to its curated fallback when a live source fails.
"""

import unittest

from self_audit import FrontierAdvance
from frontier_feed import (CuratedSource, GitHubReleasesSource,
                           MitreAttackSource, ModelsEndpointSource,
                           PublicFrontierFeed)


def make_stub_get(routes):
    """routes: dict mapping a URL substring -> JSON payload. Unmatched -> raise."""
    def _get(url, **_):
        for frag, payload in routes.items():
            if frag in url:
                return payload
        raise RuntimeError(f"no stub route for {url}")
    return _get


class GitHubReleasesSourceTests(unittest.TestCase):
    def test_emits_advance_for_newer_release(self):
        get = make_stub_get({"projectdiscovery/nuclei/releases/latest":
                             {"tag_name": "v3.3.0"}})
        src = GitHubReleasesSource(repos={"nuclei": "projectdiscovery/nuclei"},
                                   have={"nuclei": "3.1.0"})
        advances = src.fetch(get)
        self.assertEqual(len(advances), 1)
        self.assertFalse(advances[0].halo_has)
        self.assertIn("nuclei", advances[0].item)

    def test_current_release_marked_adopted(self):
        get = make_stub_get({"nuclei/releases/latest": {"tag_name": "v3.1.0"}})
        src = GitHubReleasesSource(repos={"nuclei": "projectdiscovery/nuclei"},
                                   have={"nuclei": "3.1.0"})
        advances = src.fetch(get)
        self.assertTrue(advances[0].halo_has)

    def test_one_failing_repo_does_not_sink_the_others(self):
        def get(url, **_):
            if "nuclei" in url:
                raise RuntimeError("404 / rate limited")
            if "httpx" in url:
                return {"tag_name": "v1.6.0"}
            raise RuntimeError(f"no route for {url}")
        src = GitHubReleasesSource(
            repos={"nuclei": "projectdiscovery/nuclei",
                   "httpx": "projectdiscovery/httpx"},
            have={"nuclei": "3.1.0", "httpx": "1.5.0"})
        advances = src.fetch(get)
        self.assertTrue(any("httpx" in a.item for a in advances))

    def test_watchlist_tool_not_installed_is_new_asset(self):
        get = make_stub_get({"projectdiscovery/naabu/releases/latest":
                             {"tag_name": "v2.1.0"}})
        src = GitHubReleasesSource(repos={"naabu": "projectdiscovery/naabu"},
                                   have={})  # HALO does not have naabu
        advances = src.fetch(get)
        self.assertFalse(advances[0].halo_has)


class MitreAttackSourceTests(unittest.TestCase):
    def test_emits_advance_when_attack_version_newer(self):
        get = make_stub_get({"attack-stix-data/releases/latest":
                             {"tag_name": "v15.1"}})
        src = MitreAttackSource(have_version="14.1")
        advances = src.fetch(get)
        self.assertEqual(len(advances), 1)
        self.assertFalse(advances[0].halo_has)
        self.assertEqual(advances[0].source, "MITRE")


class ModelsEndpointSourceTests(unittest.TestCase):
    def test_emits_advance_for_unknown_models_only(self):
        get = make_stub_get({"/models": {"data": [{"id": "new-decider-r2"},
                                                  {"id": "known-model"}]}})
        src = ModelsEndpointSource(providers={"local": "http://127.0.0.1:1234/v1"},
                                   known={"known-model"})
        advances = src.fetch(get)
        items = [a.item for a in advances]
        self.assertIn("new-decider-r2", " ".join(items))
        self.assertNotIn("known-model", " ".join(items))

    def test_one_failing_provider_does_not_sink_the_others(self):
        def get(url, **_):
            if "good" in url:
                return {"data": [{"id": "brand-new"}]}
            raise RuntimeError("provider down")
        src = ModelsEndpointSource(
            providers={"down": "http://down/v1", "good": "http://good/v1"},
            known=set())
        advances = src.fetch(get)
        self.assertTrue(any("brand-new" in a.item for a in advances))


class CuratedSourceTests(unittest.TestCase):
    def test_always_returns_its_list(self):
        items = [FrontierAdvance("Anthropic", "adaptive thinking", False, "high")]
        src = CuratedSource(items)
        self.assertEqual(src.fetch(http_get=None), items)


class PublicFrontierFeedTests(unittest.TestCase):
    def test_degrades_to_curated_when_a_live_source_fails(self):
        class Exploding:
            def fetch(self, http_get):
                raise RuntimeError("offline")

        curated = [FrontierAdvance("MITRE", "latest ATT&CK", False, "medium")]
        logs = []
        feed = PublicFrontierFeed(sources=[Exploding(), CuratedSource(curated)],
                                  http_get=lambda u, **_: {}, log=logs.append)
        advances = feed.advances()
        self.assertEqual([a.item for a in advances], ["latest ATT&CK"])
        self.assertTrue(any("Exploding" in m for m in logs))

    def test_dedupes_same_source_and_item(self):
        dup = FrontierAdvance("MITRE", "latest ATT&CK", False, "medium")
        feed = PublicFrontierFeed(sources=[CuratedSource([dup]), CuratedSource([dup])],
                                  http_get=lambda u, **_: {}, log=lambda *_: None)
        self.assertEqual(len(feed.advances()), 1)

    def test_aggregates_across_sources(self):
        get = make_stub_get({"nuclei/releases/latest": {"tag_name": "v3.3.0"},
                             "attack-stix-data/releases/latest": {"tag_name": "v15.1"}})
        feed = PublicFrontierFeed(sources=[
            GitHubReleasesSource({"nuclei": "projectdiscovery/nuclei"},
                                 {"nuclei": "3.1.0"}),
            MitreAttackSource(have_version="14.1"),
        ], http_get=get, log=lambda *_: None)
        sources = {a.source for a in feed.advances()}
        self.assertIn("MITRE", sources)


if __name__ == "__main__":
    unittest.main()
