"""Unit tests for report_generator.build_report.

Covers both input formats supported by report_generator.py:
  * a structured JSON session file, and
  * a plain-text log file.
"""

import json
import os
import tempfile
import unittest

from report_generator import build_report


class BuildReportTests(unittest.TestCase):
    def test_json_session_produces_report_with_finding(self):
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

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "session.json")
            output_path = os.path.join(tmpdir, "session.html")
            with open(input_path, "w") as f:
                json.dump(session, f)

            returned = build_report(input_path, output_path)

            self.assertEqual(returned, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, "r") as f:
                html_content = f.read()
            self.assertIn("22/tcp open ssh", html_content)
            self.assertIn("test-json", html_content)

    def test_plain_text_log_produces_report_with_finding(self):
        log_lines = [
            "starting scan",
            "[+] host 10.0.0.1 is up",
            "port 22 open ssh",
            "done",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "session.log")
            output_path = os.path.join(tmpdir, "session.html")
            with open(input_path, "w") as f:
                f.write("\n".join(log_lines))

            returned = build_report(input_path, output_path)

            self.assertEqual(returned, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, "r") as f:
                html_content = f.read()
            self.assertIn("[+] host 10.0.0.1 is up", html_content)
            self.assertIn("port 22 open ssh", html_content)


if __name__ == "__main__":
    unittest.main()
