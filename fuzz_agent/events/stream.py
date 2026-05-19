"""Asyncio event bus + plateau detector.

The bus is an in-process pub/sub. Engines publish FuzzEvents; orchestrator
and any number of subagents subscribe per campaign_id. On close(), all
subscribers receive a sentinel and the async generator exits cleanly.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Optional, Union

from ..state.models import EventKind, FuzzEvent

_SENTINEL: object = object()
_QueueItem = Union[FuzzEvent, object]


class EventBus:
    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue[_QueueItem]]] = defaultdict(list)
        self._closed: set[str] = set()

    def publish(self, ev: FuzzEvent) -> None:
        if ev.campaign_id in self._closed:
            return
        for q in self._queues.get(ev.campaign_id, ()):
            q.put_nowait(ev)

    async def subscribe(self, campaign_id: str) -> AsyncIterator[FuzzEvent]:
        q: asyncio.Queue[_QueueItem] = asyncio.Queue()
        self._queues[campaign_id].append(q)
        try:
            while True:
                item = await q.get()
                if item is _SENTINEL:
                    return
                assert isinstance(item, FuzzEvent)
                yield item
        finally:
            try:
                self._queues[campaign_id].remove(q)
            except ValueError:
                pass

    def close(self, campaign_id: str) -> None:
        self._closed.add(campaign_id)
        for q in self._queues.get(campaign_id, ()):
            q.put_nowait(_SENTINEL)


class PlateauDetector:
    """Emit a synthetic PLATEAU event if no NEW_COVERAGE seen for `idle_sec`."""

    def __init__(self, idle_sec: int = 300) -> None:
        self.idle_sec = idle_sec
        self._last_coverage: Optional[datetime] = None
        self._last_plateau_emitted_at: Optional[datetime] = None

    def reset(self) -> None:
        self._last_coverage = datetime.now(timezone.utc)
        self._last_plateau_emitted_at = None

    def feed(self, ev: FuzzEvent) -> Optional[FuzzEvent]:
        now = ev.ts or datetime.now(timezone.utc)
        if ev.kind == EventKind.NEW_COVERAGE:
            self._last_coverage = now
            self._last_plateau_emitted_at = None
            return None
        if self._last_coverage is None:
            self._last_coverage = now
            return None
        if now - self._last_coverage < timedelta(seconds=self.idle_sec):
            return None
        # debounce: emit at most once per idle window
        if (self._last_plateau_emitted_at and
                now - self._last_plateau_emitted_at < timedelta(seconds=self.idle_sec)):
            return None
        self._last_plateau_emitted_at = now
        return FuzzEvent(
            kind=EventKind.PLATEAU,
            campaign_id=ev.campaign_id,
            ts=now,
            payload={"idle_sec": self.idle_sec},
        )
