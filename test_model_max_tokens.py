"""The model call must cap max_tokens so a rambling reasoning model can't
run the wall clock up.

Live bug: neither call_model (agent_loop) nor _default_model_call (policy_agent)
sent a max_tokens ceiling. A reasoning 12B emits long chains of thought before the
JSON action, so single generations ran ~90s (the observed MODEL_TIMEOUT ceiling),
turning a handful of policy steps into a 40-minute engagement. Capping output
tokens bounds each call to the JSON it actually needs.
"""
import importlib

import agent_loop
import policy_agent
import halo_config


class _FakeResp:
    def json(self):
        return {"choices": [{"message": {"content": '{"chain": []}'}}]}
    def raise_for_status(self):
        pass


def test_call_model_caps_max_tokens(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        return _FakeResp()

    monkeypatch.setattr(agent_loop.requests, "post", fake_post)
    monkeypatch.setattr(agent_loop, "select_relevant_skills", lambda goal: [])
    monkeypatch.setattr(agent_loop, "SYSTEM_PROMPT", "system")

    agent_loop.call_model("scan the host")

    assert captured["payload"].get("max_tokens") == halo_config.MODEL_MAX_TOKENS


def test_policy_model_call_caps_max_tokens(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        return _FakeResp()

    monkeypatch.setattr(policy_agent.requests, "post", fake_post)

    policy_agent._default_model_call("system", "user")

    assert captured["payload"].get("max_tokens") == halo_config.MODEL_MAX_TOKENS


def test_max_tokens_is_env_overridable(monkeypatch):
    monkeypatch.setenv("HALO_MODEL_MAX_TOKENS", "256")
    importlib.reload(halo_config)
    assert halo_config.MODEL_MAX_TOKENS == 256
    importlib.reload(halo_config)  # restore default for other tests
