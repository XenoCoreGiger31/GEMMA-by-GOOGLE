"""
Unit tests for agent_loop.parse_engagement_command().

Regression cover for the `engage multi <target>` routing bug: a space-separated
"multi" was not matched by the `engage-multi ` (hyphen) branch, fell through to
the single-agent `engage ` branch, and produced target="multi <ip>" — which the
scope gate then refused ("🚫 multi 203.0.113.3 refused at engagement start").

Standard library only. HALO_LOG_DIR is redirected to a temp dir before importing
agent_loop so module import side effects don't touch a real log path.
"""

import os
import tempfile
import unittest

os.environ["HALO_LOG_DIR"] = tempfile.mkdtemp()

import agent_loop  # noqa: E402  (must follow the HALO_LOG_DIR override above)

parse = agent_loop.parse_engagement_command


class TestParseEngagementCommand(unittest.TestCase):
    def test_hyphen_multi_routes_to_multi(self):
        self.assertEqual(parse("engage-multi 203.0.113.3"),
                         ("multi", "203.0.113.3"))

    def test_space_multi_routes_to_multi(self):
        # The bug: this used to fall through to single with target "multi 192...".
        self.assertEqual(parse("engage multi 203.0.113.3"),
                         ("multi", "203.0.113.3"))

    def test_single_engage_routes_to_single(self):
        self.assertEqual(parse("engage 203.0.113.3"),
                         ("single", "203.0.113.3"))

    def test_multi_never_leaks_into_single_target(self):
        # Whichever separator, the target must never carry the word "multi".
        for cmd in ("engage-multi 10.0.0.5", "engage multi 10.0.0.5"):
            mode, target = parse(cmd)
            self.assertEqual(mode, "multi")
            self.assertNotIn("multi", target)

    def test_case_insensitive(self):
        self.assertEqual(parse("ENGAGE MULTI 203.0.113.3"),
                         ("multi", "203.0.113.3"))
        self.assertEqual(parse("Engage 203.0.113.3"),
                         ("single", "203.0.113.3"))

    def test_surrounding_whitespace_trimmed(self):
        self.assertEqual(parse("  engage multi   203.0.113.3  "),
                         ("multi", "203.0.113.3"))

    def test_non_engage_command_returns_none(self):
        mode, target = parse("scan the box")
        self.assertIsNone(mode)
        self.assertEqual(target, "scan the box")

    def test_bare_engage_word_is_not_an_engagement(self):
        # "engage" with no trailing space/target is a plain goal, not a route.
        mode, _ = parse("engage")
        self.assertIsNone(mode)


if __name__ == "__main__":
    unittest.main()
