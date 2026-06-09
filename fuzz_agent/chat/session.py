"""In-memory state for one chat conversation."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ChatTurn:
    role: str
    content: str
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChatTurn":
        role = data.get("role")
        content = data.get("content")
        created_at = data.get("created_at")
        return cls(
            role=role if isinstance(role, str) else "assistant",
            content=content if isinstance(content, str) else "",
            created_at=created_at if isinstance(created_at, str) else _utc_now(),
        )


@dataclass
class ChatSession:
    session_id: str = "default"
    active_campaign_id: str | None = None
    target_path: str | None = None
    summary: str = ""
    working_memory: dict[str, Any] = field(default_factory=dict)
    history: list[ChatTurn] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def add_turn(self, role: str, content: str) -> None:
        self.history.append(ChatTurn(role=role, content=content))
        self.updated_at = _utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "active_campaign_id": self.active_campaign_id,
            "target_path": self.target_path,
            "summary": self.summary,
            "working_memory": self.working_memory,
            "history": [turn.to_dict() for turn in self.history],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChatSession":
        session_id = data.get("session_id")
        active_campaign_id = data.get("active_campaign_id")
        target_path = data.get("target_path")
        summary = data.get("summary")
        working_memory = data.get("working_memory")
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")
        history = data.get("history")
        return cls(
            session_id=session_id if isinstance(session_id, str) else "default",
            active_campaign_id=active_campaign_id if isinstance(active_campaign_id, str) else None,
            target_path=target_path if isinstance(target_path, str) else None,
            summary=summary if isinstance(summary, str) else "",
            working_memory=working_memory if isinstance(working_memory, dict) else {},
            history=[
                ChatTurn.from_dict(turn)
                for turn in history
                if isinstance(turn, dict)
            ] if isinstance(history, list) else [],
            created_at=created_at if isinstance(created_at, str) else _utc_now(),
            updated_at=updated_at if isinstance(updated_at, str) else _utc_now(),
        )
