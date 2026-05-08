"""Background campaign launcher for the web UI."""
from __future__ import annotations

import time
from pathlib import Path

from ..orchestrator import CampaignGoal, Orchestrator
from ..state.models import EngineKind
from ..tools import _runtime


def submit_campaign(path: str, time_sec: int, engine_name: str) -> str:
    """Schedule an orchestrated campaign and return the newest campaign id."""
    rt = _runtime.runtime()
    before = {row["cid"] for row in rt.store.list_campaigns()}
    goal = CampaignGoal(
        target_path=Path(path),
        time_budget_sec=time_sec,
        engine=EngineKind(engine_name),
    )
    orch = Orchestrator(rt.store, rt.bus)
    rt.submit(orch.run(goal))

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        for row in rt.store.list_campaigns():
            if row["cid"] not in before:
                return row["cid"]
        time.sleep(0.2)

    campaigns = rt.store.list_campaigns()
    if not campaigns:
        raise RuntimeError("campaign did not become ready")
    return campaigns[0]["cid"]
