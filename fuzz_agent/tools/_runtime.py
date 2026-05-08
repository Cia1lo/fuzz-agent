"""Process-wide singletons used by the tool layer.

The tool layer is stateful — it has to remember campaign_id → engine/process.
Rather than thread state through every tool function, we keep one Runtime
instance with the store, the event bus, and the running engine adapters.
"""
from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Optional

from ..engines import AtherisEngine, LibFuzzerEngine
from ..engines.base import FuzzEngine
from ..events.stream import EventBus
from .. import sandbox
from ..state.models import EngineKind
from ..state.store import CampaignStore


class Runtime:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root or os.environ.get("FUZZ_AGENT_HOME") or Path.cwd())
        self.store = CampaignStore(self.root)
        self.bus = EventBus()
        selected_sandbox = sandbox.select(None)
        self._engines: dict[EngineKind, FuzzEngine] = {
            EngineKind.LIBFUZZER: LibFuzzerEngine(sandbox=selected_sandbox),
            EngineKind.ATHERIS: AtherisEngine(),
        }
        # campaign_id -> (engine, asyncio.Task)
        self.running: dict[str, tuple[FuzzEngine, asyncio.Task]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def engine(self, kind: EngineKind) -> FuzzEngine:
        if kind not in self._engines:
            raise NotImplementedError(f"engine not implemented: {kind}")
        return self._engines[kind]

    # ---- background asyncio loop (so sync tools can launch async campaigns) ----
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._loop.run_forever, daemon=True, name="fuzz-agent-loop",
            )
            self._thread.start()
        return self._loop

    def submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop())


_singleton: Optional[Runtime] = None


def runtime() -> Runtime:
    global _singleton
    if _singleton is None:
        _singleton = Runtime()
    return _singleton
