"""Tiny OpenAI-compatible LLM wrapper used by every subagent.

Why this exists:
  - Subagents are context-isolated workers. They each call an LLM with a
    narrow system prompt and return small structured output.
  - The OpenAI client supports both OpenAI and OpenAI-compatible providers
    through OPENAI_API_KEY and optional OPENAI_BASE_URL.
"""
from __future__ import annotations

import json
import os
from typing import Any, cast

DEFAULT_MODEL = os.environ.get("FUZZ_AGENT_MODEL", "gpt-4o-mini")


def _client() -> Any:  # lazy import so the package is importable without openai installed
    try:
        from openai import OpenAI  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError(
            "openai package not installed. `pip install openai` and set OPENAI_API_KEY."
        ) from e

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    kwargs: dict[str, str] = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return OpenAI(**kwargs)


def call_llm(system: str, user: str, *,
             max_tokens: int = 2048,
             model: str = DEFAULT_MODEL) -> str:
    """Single-turn OpenAI-compatible chat completion call."""
    client = _client()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0,
        max_tokens=max_tokens,
    )
    choice = resp.choices[0] if resp.choices else None
    if choice is None or choice.message.content is None:
        return ""
    return cast(str, choice.message.content)


def call_llm_json(system: str, user: str, *, max_tokens: int = 2048,
                  model: str = DEFAULT_MODEL) -> Any:
    """Same as call_llm but parses JSON, with one retry on malformed output."""
    raw = call_llm(system, user, max_tokens=max_tokens, model=model)
    try:
        return json.loads(_strip_fences(raw))
    except json.JSONDecodeError:
        retry = call_llm(
            system,
            user + "\n\nReturn JSON ONLY. No prose, no markdown fences.",
            max_tokens=max_tokens,
            model=model,
        )
        return json.loads(_strip_fences(retry))


# Backward-compatible aliases for existing integrations.
call_claude = call_llm
call_claude_json = call_llm_json


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.endswith("```"):
            s = s[: -3]
        if s.startswith("json"):
            s = s[4:]
    return s.strip()
