"""Orchestrator — the main agent's control loop.

Glues tools + event bus + subagents together. The LLM-driven decision points
are explicit methods; everything else is deterministic plumbing so the same
loop can run with or without an LLM in the loop.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import subagents, tools
from .tools import _runtime
from .events.stream import EventBus, PlateauDetector
from .hitl import AlwaysAllow, HITL
from .state.models import (
    BuildArtifact,
    CampaignStats,
    CampaignStatus,
    EngineKind,
    EventKind,
    FuzzEvent,
    HarnessSpec,
    TargetProfile,
)
from .state.store import CampaignStore
from .subagents import exploit_assessor


@dataclass
class CampaignGoal:
    target_path: Path
    time_budget_sec: int
    max_unique_crashes: int = 50
    coverage_plateau_sec: int = 300
    max_plateau_restarts: int = 3
    auto_triage: bool = True
    engine: EngineKind = EngineKind.LIBFUZZER
    invariants: tuple[str, ...] = ("round_trip",)


class Orchestrator:
    def __init__(self, store: CampaignStore, bus: EventBus, hitl: HITL | None = None):
        self.store = store
        self.bus = bus
        self.hitl = hitl or AlwaysAllow()
        self.plateau = PlateauDetector()
        self._plateau_hits = 0
        self._active_cid: str | None = None
        self._artifact = None
        self._engine = None

    async def run(self, goal: CampaignGoal) -> dict:
        target = await self._analyze(goal.target_path)
        if not target.entry_points:
            raise RuntimeError(f"No fuzz entry points detected under {goal.target_path}")
        spec = await self._make_harness(target, goal)
        artifact = await self._build(spec)
        cid = await self._launch(artifact, goal)
        try:
            while True:
                await self._supervise(self._active_cid, goal)
                if self._active_cid == cid:
                    break
                cid = self._active_cid
        finally:
            await self._finalize(cid, goal)
        return self.store.summary(cid)

    # ---- supervision ----
    async def _supervise(self, cid: str, goal: CampaignGoal) -> None:
        self.plateau = PlateauDetector(idle_sec=goal.coverage_plateau_sec)
        self.plateau.reset()
        async for ev in self.bus.subscribe(cid):
            synth = self.plateau.feed(ev)
            if synth is not None:
                self.bus.publish(synth)  # re-enter loop with synthetic plateau

            handler = {
                EventKind.NEW_CRASH:    self._on_new_crash,
                EventKind.NEW_COVERAGE: self._on_new_coverage,
                EventKind.PLATEAU:      self._on_plateau,
                EventKind.OOM:          self._on_oom,
                EventKind.ENGINE_ERROR: self._on_engine_error,
            }.get(ev.kind)
            if handler is not None:
                try:
                    await handler(ev, goal)
                except Exception as e:  # noqa: BLE001
                    self.store.record_event(FuzzEvent(
                        kind=EventKind.ENGINE_ERROR, campaign_id=cid,
                        ts=datetime.now(timezone.utc),
                        payload={"handler_error": str(e), "src": ev.kind.value},
                    ))

            stats = self._stats(cid)
            if self._should_stop(stats, goal):
                await self._stop(cid)
                return

    # ---- decision points ----
    async def _analyze(self, path: Path) -> TargetProfile:
        return tools.analyze_target(str(path))

    async def _make_harness(self, target: TargetProfile, goal: CampaignGoal) -> HarnessSpec:
        entry = target.entry_points[0]  # first heuristic; LLM could re-rank
        return tools.generate_harness(target, entry, goal.engine, list(goal.invariants))

    async def _build(self, spec: HarnessSpec) -> BuildArtifact:
        return tools.build_target(spec, None)

    async def _launch(self, artifact: BuildArtifact, goal: CampaignGoal) -> str:
        seed_dir = artifact.binary_path.parent.parent / "corpus"
        seed_dir.mkdir(parents=True, exist_ok=True)
        cid = tools.start_fuzz_campaign(
            artifact, str(seed_dir), goal.time_budget_sec,
            None,
        )
        self._artifact = artifact
        self._engine = tools._runtime.runtime().engine(artifact.engine)
        self._active_cid = cid
        return cid

    def _stats(self, cid: str) -> CampaignStats:
        return tools.query_status(cid)

    async def _stop(self, cid: str) -> None:
        tools.stop_campaign(cid)

    async def _finalize(self, cid: str, goal: CampaignGoal) -> None:
        if not goal.auto_triage:
            return
        triaged = tools.triage_crashes(cid, top_n=goal.max_unique_crashes)
        artifact = self._artifact
        engine = self._engine
        for c in triaged:
            if artifact is not None and engine is not None:
                try:
                    out_path = c.input_path.parent / (c.input_path.name + ".min")
                    minimized = engine.minimize(artifact, c.input_path, out_path)
                    c.minimized_path = minimized
                except Exception as e:
                    self.store.record_event(FuzzEvent(
                        kind=EventKind.ENGINE_ERROR, campaign_id=cid,
                        ts=datetime.now(timezone.utc),
                        payload={"minimize_error": str(e), "crash_id": c.crash_id},
                    ))
            try:
                from .subagents._symbolize import symbolize
                c.top_frames = symbolize(
                    c.top_frames,
                    binary=(artifact.binary_path if artifact else None),
                )
            except Exception:
                pass
            assessed = subagents.exploit_assessor(c, goal.target_path)
            from .state.models import Severity
            if assessed.severity in (Severity.CRITICAL, Severity.HIGH):
                allowed = await self.hitl.confirm("severe_crash_report", {
                    "crash_id": assessed.crash_id,
                    "severity": assessed.severity.value,
                    "top_frames": assessed.top_frames[:5],
                    "notes": (assessed.exploitability_notes or "")[:300],
                })
                if not allowed:
                    assessed.exploitability_notes = (
                        "[REDACTED — pending human review] "
                        + (assessed.exploitability_notes or "")
                    )
            self.store.save_crash(assessed)
        self.store.update_status(cid, CampaignStatus.STOPPED)

    # ---- event handlers ----
    async def _on_new_crash(self, ev: FuzzEvent, goal: CampaignGoal) -> None:
        if goal.auto_triage:
            tools.triage_crashes(ev.campaign_id, top_n=goal.max_unique_crashes)

    async def _on_new_coverage(self, ev: FuzzEvent, goal: CampaignGoal) -> None:
        return

    async def _on_plateau(self, ev: FuzzEvent, goal: CampaignGoal) -> None:
        self._plateau_hits += 1
        tools.mutate_strategy(ev.campaign_id, hint="plateau: explore uncovered branches")
        if self._plateau_hits > goal.max_plateau_restarts:
            return
        allowed = await self.hitl.confirm("plateau_restart", {
            "campaign_id": ev.campaign_id,
            "hits": self._plateau_hits,
        })
        if not allowed:
            return
        stats = self._stats(ev.campaign_id)
        remaining = max(60, goal.time_budget_sec - stats.elapsed_sec)
        tools.stop_campaign(ev.campaign_id)
        new_cid = tools.start_fuzz_campaign(
            self._artifact,
            str(self.store.paths(ev.campaign_id)["corpus_dir"]),
            remaining,
            None,
        )
        self._active_cid = new_cid
        self.plateau = PlateauDetector(idle_sec=goal.coverage_plateau_sec)
        self.plateau.reset()

    async def _on_oom(self, ev: FuzzEvent, goal: CampaignGoal) -> None:
        return  # could lower memory cap or shrink seeds

    async def _on_engine_error(self, ev: FuzzEvent, goal: CampaignGoal) -> None:
        return  # surfaced via store; no auto-recovery yet

    @staticmethod
    def _should_stop(stats: CampaignStats, goal: CampaignGoal) -> bool:
        if stats.status in (CampaignStatus.STOPPED, CampaignStatus.FAILED):
            return True
        if stats.elapsed_sec >= goal.time_budget_sec:
            return True
        if stats.unique_crashes >= goal.max_unique_crashes:
            return True
        return False
