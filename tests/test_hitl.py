import asyncio

from fuzz_agent.hitl import AlwaysAllow, AlwaysDeny, CLIPrompt, select


def test_always_allow_returns_true():
    assert asyncio.run(AlwaysAllow().confirm("k", {})) is True


def test_always_deny_returns_false():
    assert asyncio.run(AlwaysDeny().confirm("k", {})) is False


def test_cli_prompt_y(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert asyncio.run(CLIPrompt().confirm("k", {})) is True


def test_cli_prompt_n(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert asyncio.run(CLIPrompt().confirm("k", {})) is False


def test_cli_prompt_default_empty_is_false(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    assert asyncio.run(CLIPrompt().confirm("k", {})) is False


def test_select_env(monkeypatch):
    monkeypatch.setenv("FUZZ_AGENT_HITL", "deny")
    assert isinstance(select(None), AlwaysDeny)
