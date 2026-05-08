"""Tiny Claude wrapper used by every subagent.

Why this exists:
  - Subagents are context-isolated workers. They each call Claude with a
    narrow system prompt and return small structured output.
  - Reusing the same system prompt across calls is the common case, so we
    enable prompt caching by default (cache_control=ephemeral).
"""
from __future__ import annotations

import json
import os
from typing import Any

DEFAULT_MODEL = os.environ.get("FUZZ_AGENT_MODEL", "claude-sonnet-4-6")


def _client():  # lazy import so the package is importable without anthropic installed
    try:
        from anthropic import Anthropic
    except ImportError as e:
        raise RuntimeError(
            "anthropic package not installed. `pip install anthropic` and set ANTHROPIC_API_KEY."
        ) from e
    return Anthropic()


def call_claude(system: str, user: str, *,
                max_tokens: int = 2048,
                model: str = DEFAULT_MODEL) -> str:
    """Single-turn Claude call. System prompt is cached (ephemeral)."""
    client = _client()
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=[{"type": "text", "text": system,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")


def call_claude_json(system: str, user: str, *, max_tokens: int = 2048,
                     model: str = DEFAULT_MODEL) -> Any:
    """Same as call_claude but parses JSON, with one retry on malformed output."""
    raw = call_claude(system, user, max_tokens=max_tokens, model=model)
    try:
        return json.loads(_strip_fences(raw))
    except json.JSONDecodeError:
        retry = call_claude(
            system,
            user + "\n\nReturn JSON ONLY. No prose, no markdown fences.",
            max_tokens=max_tokens, model=model,
        )
        return json.loads(_strip_fences(retry))


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.endswith("```"):
            s = s[: -3]
        if s.startswith("json"):
            s = s[4:]
    return s.strip()
