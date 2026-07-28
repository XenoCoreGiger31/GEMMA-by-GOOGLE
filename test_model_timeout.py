"""The model call must not ride the 300s tool-timeout wall.

Live bug: call_model passed timeout=TOOL_TIMEOUT (300s, sized for long scans), so a
single hung LM Studio request stalled the whole engagement for 5 minutes (port 21 in
session_20260723_112744). The model call gets its own tight, env-overridable timeout.
"""
import agent_loop
import halo_config


class _FakeResp:
    def json(self):
        return {"choices": [{"message": {"content": '{"chain": []}'}}]}


def test_call_model_uses_tight_model_timeout(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["timeout"] = timeout
        return _FakeResp()

    monkeypatch.setattr(agent_loop.requests, "post", fake_post)
    monkeypatch.setattr(agent_loop, "select_relevant_skills", lambda goal: [])
    monkeypatch.setattr(agent_loop, "SYSTEM_PROMPT", "system")

    agent_loop.call_model("scan the host")

    assert captured["timeout"] is not None, "model call inherited no explicit timeout"
    assert captured["timeout"] < agent_loop.TOOL_TIMEOUT, "still riding the 300s wall"
    assert captured["timeout"] == halo_config.MODEL_TIMEOUT


def test_model_timeout_is_env_overridable(monkeypatch):
    monkeypatch.setenv("HALO_MODEL_TIMEOUT", "45")
    import importlib
    importlib.reload(halo_config)
    assert halo_config.MODEL_TIMEOUT == 45
    importlib.reload(halo_config)  # restore default for other tests
