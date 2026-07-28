"""
Unit tests for report_generator.build_report.

Covers both input formats accepted by report_generator.py:
  * a structured JSON session file (see logger.py), and
  * a plain-text .log file.

Standard library only (unittest + tempfile); no external dependencies.
"""

import json
import os
import tempfile
import unittest

from report_generator import build_report


class BuildReportTests(unittest.TestCase):
    def _build_and_read(self, filename: str, contents: str) -> str:
        """Write contents to filename in a temp dir, build a report from it,
        assert the HTML was produced, and return the rendered HTML text."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, filename)
            output_path = os.path.join(tmpdir, "session.html")
            with open(input_path, "w") as f:
                f.write(contents)

            returned = build_report(input_path, output_path)

            self.assertEqual(returned, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, "r") as f:
                return f.read()

    def test_json_session_produces_report_with_finding(self) -> None:
        """A JSON session with an open-port tool result surfaces that finding."""
        session = {
            "session_id": "test-json",
            "started_at": "2025-01-01T00:00:00",
            "ended_at": "2025-01-01T00:01:00",
            "events": [
                {
                    "timestamp": "2025-01-01T00:00:30",
                    "event_type": "tool_call",
                    "data": {
                        "tool": "run_nmap",
                        "result": "22/tcp open ssh",
                    },
                }
            ],
        }

        html_content = self._build_and_read("session.json", json.dumps(session))

        self.assertIn("22/tcp open ssh", html_content)
        self.assertIn("test-json", html_content)

    def test_plain_text_log_produces_report_with_finding(self) -> None:
        """A plain-text log surfaces its [+] and open-port lines as findings."""
        log_lines = [
            "starting scan",
            "[+] host 10.0.0.1 is up",
            "port 22 open ssh",
            "done",
        ]

        html_content = self._build_and_read("session.log", "\n".join(log_lines))

        self.assertIn("[+] host 10.0.0.1 is up", html_content)
        self.assertIn("port 22 open ssh", html_content)


if __name__ == "__main__":
    unittest.main()
