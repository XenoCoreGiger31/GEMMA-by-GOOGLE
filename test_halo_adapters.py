"""Offline tests for the model adapter and shared response parser.

Injects a fake HTTP transport so no network or `requests` install is needed.
Standard library only.
"""

import os
import tempfile
import unittest

from halo_adapters import parse_model_response, LMStudioModelClient


class ParseResponseTests(unittest.TestCase):
    def test_clean_object(self):
        self.assertEqual(
            parse_model_response('{"chain": [{"tool": "run_nmap"}]}'),
            {"chain": [{"tool": "run_nmap"}]},
        )

    def test_strips_code_fences_and_trailing_commas(self):
        raw = '```json\n{"chain": [{"tool": "run_nmap",}],}\n```'
        self.assertEqual(parse_model_response(raw), {"chain": [{"tool": "run_nmap"}]})

    def test_salvages_standalone_tool_objects(self):
        raw = 'noise {"tool": "run_nmap"} more {"tool": "run_httpx"} tail'
        self.assertEqual(
            parse_model_response(raw),
            {"chain": [{"tool": "run_nmap"}, {"tool": "run_httpx"}]},
        )

    def test_unrecoverable_returns_empty_chain(self):
        self.assertEqual(parse_model_response("not json at all"), {"chain": []})


class FakeResponse:
    def __init__(self, content):
        self._content = content

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class ModelClientTests(unittest.TestCase):
    def test_complete_assembles_prompt_and_parses(self):
        captured = {}

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["system"] = json["messages"][0]["content"]
            captured["user"] = json["messages"][1]["content"]
            return FakeResponse('{"chain": [{"tool": "run_httpx", "target": "x"}]}')

        client = LMStudioModelClient(engagement_preamble="PREAMBLE-MARKER",
                                     post=fake_post)
        out = client.complete("SYSTEM-BODY", "scan the target for open ports")
        self.assertEqual(out, {"chain": [{"tool": "run_httpx", "target": "x"}]})
        self.assertIn("PREAMBLE-MARKER", captured["system"])
        self.assertIn("SYSTEM-BODY", captured["system"])
        self.assertEqual(captured["user"], "scan the target for open ports")

    def test_complete_injects_selected_skills(self):
        import pathlib
        import skills
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "recon.md"), "w") as f:
                f.write("---\nname: recon-playbook\n"
                        "description: reconnaissance guidance\n---\n"
                        "SKILL-BODY-MARKER")
            saved = skills.SKILLS_DIR
            skills.SKILLS_DIR = pathlib.Path(d)
            try:
                def fake_post(url, json=None, timeout=None):
                    fake_post.system = json["messages"][0]["content"]
                    return FakeResponse('{"chain": []}')

                client = LMStudioModelClient(post=fake_post)
                client.complete("SYS", "run reconnaissance on the host")
                self.assertIn("SKILL-BODY-MARKER", fake_post.system)
            finally:
                skills.SKILLS_DIR = saved


if __name__ == "__main__":
    unittest.main()
