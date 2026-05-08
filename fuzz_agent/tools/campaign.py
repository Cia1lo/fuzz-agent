"""Campaign control tools: start / query / stop.

start_fuzz_campaign_impl launches the engine on the runtime's background
event loop and pipes events through the EventBus + CampaignStore.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from ..state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStats,
    CampaignStatus,
)
from ._runtime import runtime


async def _drive(rt, cid: str, eng, cfg: CampaignConfig) -> None:
    rt.store.update_status(cid, CampaignStatus.RUNNING)
    try:
        async for ev in eng.run(cfg):
            engine_cid = ev.campaign_id
            ev = _retag(ev, cid)  # engine assigned its own id; rebind to ours
            rt.store.record_event(ev)
            rt.bus.publish(ev)
            stats = eng.stats(engine_cid)
            stats.campaign_id = cid
            rt.store.record_stats(stats)
        if hasattr(eng, "collect_coverage"):
            try:
                summary = eng.collect_coverage(cfg, cfg.artifact)
                if summary is not None and summary.exists():
                    coverage_path = rt.store.paths(cid)["coverage"]
                    coverage_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(summary, coverage_path)
                    stats = rt.store.latest_stats(cid) or _pending_stats(cid)
                    stats.edges_total = _edges_total_from_report(coverage_path)
                    rt.store.record_stats(stats)
            except Exception:
                pass
        rt.store.update_status(cid, CampaignStatus.STOPPED)
    except Exception as e:  # noqa: BLE001
        rt.store.update_status(cid, CampaignStatus.FAILED)
        from ..state.models import EventKind, FuzzEvent
        rt.store.record_event(FuzzEvent(
            kind=EventKind.ENGINE_ERROR, campaign_id=cid,
            ts=datetime.now(timezone.utc), payload={"error": str(e)},
        ))
    finally:
        rt.bus.close(cid)
        rt.running.pop(cid, None)


def _retag(ev, cid: str):
    ev.campaign_id = cid
    return ev


def _edges_total_from_report(path: Path) -> int | None:
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if parts and parts[0] == "TOTAL" and len(parts) > 1:
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def _pending_stats(cid: str) -> CampaignStats:
    return CampaignStats(
        campaign_id=cid,
        status=CampaignStatus.STOPPED,
        elapsed_sec=0,
        execs_total=0,
        execs_per_sec=0.0,
        edges_covered=0,
        edges_total=None,
        corpus_size=0,
        unique_crashes=0,
        last_new_coverage_sec_ago=None,
    )


def start_fuzz_campaign_impl(artifact: BuildArtifact, corpus_dir: Path,
                             time_budget_sec: int,
                             dictionary_path: Optional[Path]) -> str:
    rt = runtime()
    cfg = CampaignConfig(
        artifact=artifact, corpus_dir=corpus_dir,
        crash_dir=corpus_dir.parent / "crashes",
        dictionary_path=dictionary_path,
        time_budget_sec=time_budget_sec,
    )
    cid = rt.store.new_campaign(cfg)
    eng = rt.engine(artifact.engine)
    fut = rt.submit(_drive(rt, cid, eng, cfg))
    rt.running[cid] = (eng, fut)  # type: ignore[assignment]
    return cid


def query_status_impl(campaign_id: str) -> CampaignStats:
    rt = runtime()
    s = rt.store.latest_stats(campaign_id)
    if s is not None:
        return s
    # If never recorded yet, synthesize a pending stat.
    from ..state.models import CampaignStats as CS
    return CS(
        campaign_id=campaign_id, status=CampaignStatus.PENDING,
        elapsed_sec=0, execs_total=0, execs_per_sec=0.0,
        edges_covered=0, edges_total=None, corpus_size=0,
        unique_crashes=0, last_new_coverage_sec_ago=None,
    )


def stop_campaign_impl(campaign_id: str) -> None:
    rt = runtime()
    pair = rt.running.get(campaign_id)
    if not pair:
        return
    eng, _ = pair
    rt.submit(eng.stop(campaign_id))
