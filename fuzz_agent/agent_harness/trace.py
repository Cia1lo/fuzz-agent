"""Trace records for agent harness decisions and tool feedback."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AgentTraceRecord:
    """One structured step in the outer agent harness loop."""

    step: int
    phase: str
    observation: dict[str, Any]
    decision: dict[str, Any]
    action: dict[str, Any]
    result: dict[str, Any]
    score: dict[str, Any]
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AgentTraceRecorder:
    """In-memory trace collector; CampaignStore owns durable JSONL persistence."""

    def __init__(self) -> None:
        self._records: list[AgentTraceRecord] = []

    def record(
        self,
        *,
        phase: str,
        observation: dict[str, Any],
        decision: dict[str, Any],
        action: dict[str, Any],
        result: dict[str, Any],
        score: dict[str, Any],
    ) -> AgentTraceRecord:
        rec = AgentTraceRecord(
            step=len(self._records) + 1,
            phase=phase,
            observation=observation,
            decision=decision,
            action=action,
            result=result,
            score=score,
        )
        self._records.append(rec)
        return rec

    @property
    def records(self) -> list[AgentTraceRecord]:
        return list(self._records)
