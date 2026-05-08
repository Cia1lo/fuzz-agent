"""triage_crashes — delegate to crash-triage subagent, persist results."""
from __future__ import annotations

from ..state.models import CrashRecord
from ..subagents import crash_triage
from ._runtime import runtime


def triage_crashes_impl(campaign_id: str, top_n: int) -> list[CrashRecord]:
    rt = runtime()
    paths = rt.store.paths(campaign_id)
    crashes = crash_triage(campaign_id, paths["crash_dir"], top_n)
    for c in crashes:
        rt.store.save_crash(c)
    return crashes
