"""Campaign control tools: start / query / stop.

start_fuzz_campaign_impl launches the engine on the runtime's background
event loop and pipes events through the EventBus + CampaignStore.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from ..engines.base import FuzzEngine
from ..state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStats,
    CampaignStatus,
    EventKind,
    FuzzEvent,
)
from ._runtime import Runtime, runtime


async def _drive(rt: Runtime, cid: str, eng: FuzzEngine, cfg: CampaignConfig) -> None:
    rt.store.update_status(cid, CampaignStatus.RUNNING)
    try:
        async for ev in eng.run(cfg):
            rt.store.record_event(ev)
            rt.bus.publish(ev)
            stats = eng.stats(cid)
            rt.store.record_stats(stats)
        rt.store.record_stats(eng.stats(cid))
        if hasattr(eng, "collect_coverage"):
            try:
                summary = eng.collect_coverage(cfg, cfg.artifact)
                if summary is not None and summary.exists():
                    stats = rt.store.latest_stats(cid) or _pending_stats(cid)
                    stats.edges_total = _edges_total_from_report(summary)
                    rt.store.record_stats(stats)
            except Exception as e:  # noqa: BLE001
                rt.store.record_event(FuzzEvent(
                    kind=EventKind.ENGINE_ERROR,
                    campaign_id=cid,
                    ts=datetime.now(timezone.utc),
                    payload={"coverage_error": str(e)},
                ))
        rt.store.update_status(cid, CampaignStatus.STOPPED)
    except Exception as e:  # noqa: BLE001
        rt.store.update_status(cid, CampaignStatus.FAILED)
        rt.store.record_event(FuzzEvent(
            kind=EventKind.ENGINE_ERROR, campaign_id=cid,
            ts=datetime.now(timezone.utc), payload={"error": str(e)},
        ))
    finally:
        rt.bus.close(cid)
        rt.running.pop(cid, None)


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


def _copy_seed_corpus(src: Path, dst: Path) -> None:
    if not src.exists() or src.resolve() == dst.resolve():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        if path.is_file():
            rel = path.relative_to(src)
            out = dst / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out)


def start_fuzz_campaign_impl(artifact: BuildArtifact, corpus_dir: Path,
                             time_budget_sec: int,
                             dictionary_path: Optional[Path],
                             resumed_from: Optional[str] = None) -> str:
    rt = runtime()
    cfg = CampaignConfig(
        artifact=artifact, corpus_dir=corpus_dir,
        crash_dir=corpus_dir.parent / "crashes",
        dictionary_path=dictionary_path,
        time_budget_sec=time_budget_sec,
        resumed_from=resumed_from,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    _copy_seed_corpus(corpus_dir, paths["corpus_dir"])
    cfg = CampaignConfig(
        artifact=artifact,
        corpus_dir=paths["corpus_dir"],
        crash_dir=paths["crash_dir"],
        dictionary_path=dictionary_path,
        time_budget_sec=time_budget_sec,
        campaign_id=cid,
        resumed_from=resumed_from,
    )
    rt.store.update_meta(cid, cfg)
    eng = rt.engine(artifact.engine)
    fut = rt.submit(_drive(rt, cid, eng, cfg))
    rt.running[cid] = (eng, fut)
    return cid


def resume_campaign_impl(campaign_id: str, time_budget_sec: Optional[int]) -> str:
    rt = runtime()
    cfg = rt.store.campaign_config(campaign_id)
    if cfg is None:
        raise KeyError(f"unknown campaign: {campaign_id}")
    paths = rt.store.paths(campaign_id)
    budget = time_budget_sec or cfg.time_budget_sec
    return start_fuzz_campaign_impl(
        cfg.artifact,
        paths["corpus_dir"],
        budget,
        cfg.dictionary_path,
        resumed_from=campaign_id,
    )


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
