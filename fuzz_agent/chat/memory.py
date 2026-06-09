"""Prompt memory helpers for chat sessions."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .session import ChatSession, ChatTurn

if TYPE_CHECKING:
    from ..state.store import CampaignStore

RECENT_HISTORY_CHAR_BUDGET = 8000
SUMMARY_KEEP_RECENT_TURNS = 12
SUMMARY_CHAR_BUDGET = 2000
WORKING_MEMORY_VALUE_BUDGET = 500


def note_intent(session: ChatSession, *, intent: str, command: str) -> None:
    """Update structured working memory after intent parsing."""
    session.working_memory["last_intent"] = intent
    session.working_memory["last_command"] = _shorten(command, WORKING_MEMORY_VALUE_BUDGET)


def note_reply(session: ChatSession, reply: str) -> None:
    session.working_memory["last_reply"] = _shorten(reply, WORKING_MEMORY_VALUE_BUDGET)


def note_error(session: ChatSession, error: str) -> None:
    session.working_memory["last_error"] = _shorten(error, WORKING_MEMORY_VALUE_BUDGET)


def refresh_session_summary(session: ChatSession) -> None:
    """Maintain a bounded extractive summary of older turns."""
    if len(session.history) <= SUMMARY_KEEP_RECENT_TURNS:
        return
    older = session.history[:-SUMMARY_KEEP_RECENT_TURNS]
    session.summary = _summarize_turns(older, SUMMARY_CHAR_BUDGET)


def build_intent_prompt(
    session: ChatSession,
    text: str,
    *,
    store: "CampaignStore | None" = None,
) -> str:
    return build_chat_memory_prompt(session, text, store=store)


def build_chat_memory_prompt(
    session: ChatSession,
    text: str,
    *,
    store: "CampaignStore | None" = None,
) -> str:
    """Build the common memory prelude used by chat and intent LLM calls."""
    refresh_session_summary(session)
    return (
        f"Active campaign id: {session.active_campaign_id or 'none'}\n"
        f"Known target path: {session.target_path or 'none'}\n"
        f"Working memory:\n{_working_memory_json(session)}\n\n"
        f"Conversation summary:\n{session.summary or 'none'}\n\n"
        f"Active campaign snapshot:\n{_campaign_snapshot(session, store)}\n\n"
        f"Recent conversation:\n{recent_history(session)}\n\n"
        f"User message: {text}"
    )


def recent_history(
    session: ChatSession,
    *,
    char_budget: int = RECENT_HISTORY_CHAR_BUDGET,
) -> str:
    """Return as many recent turns as fit in the character budget."""
    if not session.history:
        return "none"
    lines: list[str] = []
    used = 0
    for turn in reversed(session.history):
        line = _format_turn(turn)
        needed = len(line) + (1 if lines else 0)
        if lines and used + needed > char_budget:
            break
        if not lines and needed > char_budget:
            return _shorten(line, char_budget)
        lines.append(line)
        used += needed
    lines.reverse()
    return "\n".join(lines) if lines else "none"


def _working_memory_json(session: ChatSession) -> str:
    if not session.working_memory:
        return "none"
    return json.dumps(session.working_memory, ensure_ascii=False, indent=2, default=str)


def _campaign_snapshot(session: ChatSession, store: "CampaignStore | None") -> str:
    if store is None or not session.active_campaign_id:
        return "none"
    cid = session.active_campaign_id
    lines = [f"campaign_id: {cid}"]
    try:
        stats = store.latest_stats(cid)
    except Exception:  # noqa: BLE001
        stats = None
    if stats is not None:
        lines.extend([
            f"status: {stats.status.value}",
            f"elapsed_sec: {stats.elapsed_sec}",
            f"execs_total: {stats.execs_total}",
            f"execs_per_sec: {stats.execs_per_sec:.2f}",
            f"edges_covered: {stats.edges_covered}",
            f"edges_total: {stats.edges_total if stats.edges_total is not None else 'unknown'}",
            f"corpus_size: {stats.corpus_size}",
            f"unique_crashes: {stats.unique_crashes}",
        ])
    try:
        crashes = store.list_crashes(cid)
    except Exception:  # noqa: BLE001
        crashes = []
    if crashes:
        crash_bits = [
            f"{crash.crash_id}:{crash.status.value}:{crash.sanitizer_kind or 'unknown'}"
            for crash in crashes[:3]
        ]
        lines.append(f"recent_crashes: {', '.join(crash_bits)}")
    try:
        trace = store.list_agent_trace(cid)
    except Exception:  # noqa: BLE001
        trace = []
    if trace:
        lines.append("recent_agent_trace:")
        for row in trace[-3:]:
            if not isinstance(row, dict):
                continue
            decision = _dict_field(row, "decision")
            observation = _dict_field(row, "observation")
            action = decision.get("action", "")
            reason = _shorten(str(decision.get("reason", "")), 120)
            diagnostics = _shorten(str(observation.get("diagnostics", "")), 160)
            phase = row.get("phase", "")
            lines.append(f"- {phase}: {action} - {reason}; diagnostics={diagnostics}")
    return "\n".join(lines)


def _summarize_turns(turns: list[ChatTurn], char_budget: int) -> str:
    lines: list[str] = []
    for turn in turns:
        content = " ".join(turn.content.split())
        if not content:
            continue
        lines.append(_shorten(f"{turn.role}: {content}", 240))
    summary = "\n".join(lines)
    if not summary:
        return ""
    return _shorten(summary, char_budget)


def _format_turn(turn: ChatTurn) -> str:
    return f"{turn.role}: {turn.content}"


def _dict_field(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _shorten(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1] + "…"
