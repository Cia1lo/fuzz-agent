import sys
from types import SimpleNamespace

import pytest

from fuzz_agent.subagents import _llm


class FakeCompletions:
    def create(self, **kwargs):
        FakeOpenAI.last_request = kwargs
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content='{"ok": true}')),
            ],
        )


class FakeOpenAI:
    instances = []
    last_request = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.chat = SimpleNamespace(completions=FakeCompletions())
        self.instances.append(self)


def test_call_llm_json_uses_openai_compatible_client(monkeypatch):
    FakeOpenAI.instances = []
    FakeOpenAI.last_request = None
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.example/v1")

    out = _llm.call_llm_json("system prompt", "user prompt", model="test-model")

    assert out == {"ok": True}
    assert FakeOpenAI.instances[0].kwargs == {
        "api_key": "test-key",
        "base_url": "https://gateway.example/v1",
    }
    assert FakeOpenAI.last_request["model"] == "test-model"
    assert FakeOpenAI.last_request["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "user prompt"},
    ]


def test_call_llm_requires_openai_api_key(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        _llm.call_llm("system", "user")
