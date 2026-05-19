"""Orchestrator — the main agent's control loop.

Glues tools + event bus + subagents together. The LLM-driven decision points
are explicit methods; everything else is deterministic plumbing so the same
loop can run with or without an LLM in the loop.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import subagents, tools
from .agent_harness import (
    AgentHarnessResult,
    AgentHarnessSession,
    AgentObservation,
    CoverageStrategyPolicy,
    HarnessAction,
    HarnessBuildError,
    ValidationResult,
)
from .agent_harness.validators import validate_crash_not_from_harness
from .engines.base import FuzzEngine
from .events.stream import EventBus, PlateauDetector
from .hitl import AlwaysAllow, HITL
from .state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStats,
    CampaignStatus,
    EngineKind,
    EventKind,
    FuzzEvent,
    HarnessSpec,
    TargetProfile,
)
from .state.store import CampaignStore


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
        self._artifact: BuildArtifact | None = None
        self._engine: FuzzEngine | None = None
        self._harness_result: AgentHarnessResult | None = None
        self._coverage_policy = CoverageStrategyPolicy()

    async def run(self, goal: CampaignGoal) -> dict[str, Any]:
        target = await self._analyze(goal.target_path)
        if not target.entry_points:
            raise RuntimeError(f"No fuzz entry points detected under {goal.target_path}")
        try:
            harness_result = await self._prepare_harness(target, goal)
        except HarnessBuildError as exc:
            self._persist_failed_agent_trace(target, goal, exc)
            raise
        artifact = harness_result.artifact
        cid = await self._launch(artifact, goal)
        self._persist_agent_trace(cid, harness_result)
        try:
            while True:
                active_cid = self._active_cid
                if active_cid is None:
                    raise RuntimeError("campaign launch did not set active campaign id")
                await self._supervise(active_cid, goal)
                if self._active_cid == cid:
                    break
                next_cid = self._active_cid
                if next_cid is None:
                    raise RuntimeError("active campaign id was cleared during supervision")
                cid = next_cid
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
        return self._generate_harness(target, entry, goal, attempt=1, diagnostics=None)

    def _generate_harness(
        self,
        target: TargetProfile,
        entry: str,
        goal: CampaignGoal,
        *,
        attempt: int,
        diagnostics: str | None,
    ) -> HarnessSpec:
        return tools.generate_harness(
            target,
            entry,
            goal.engine,
            list(goal.invariants),
            attempt=attempt,
            diagnostics=diagnostics,
        )

    async def _build(self, spec: HarnessSpec) -> BuildArtifact:
        return tools.build_target(spec, None)

    async def _prepare_harness(
        self,
        target: TargetProfile,
        goal: CampaignGoal,
    ) -> AgentHarnessResult:
        spec = await self._make_harness(target, goal)
        artifact = await self._build_with_retries(target, spec, goal)
        if self._harness_result is None:
            self._harness_result = AgentHarnessResult(
                spec=spec,
                artifact=artifact,
                attempts=[],
                trace_records=[],
            )
        return self._harness_result

    async def _build_with_retries(
        self,
        target: TargetProfile,
        spec: HarnessSpec,
        goal: CampaignGoal,
        max_attempts: int = 3,
    ) -> BuildArtifact:
        session = AgentHarnessSession(
            target=target,
            entry=spec.entry,
            engine=goal.engine,
            invariants=list(goal.invariants),
            generate_harness=lambda attempt, diagnostics: self._generate_harness(
                target,
                spec.entry,
                goal,
                attempt=attempt,
                diagnostics=diagnostics,
            ),
            build=self._build,
            smoke_run=self._smoke_run,
            target_reached=self._target_reached,
            max_attempts=max_attempts,
        )
        result = await session.run(initial_spec=spec)
        self._harness_result = result
        return result.artifact

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

    def _persist_agent_trace(self, cid: str, result: AgentHarnessResult) -> None:
        for record in result.trace_records:
            self.store.record_agent_trace(cid, record)

    def _persist_failed_agent_trace(
        self,
        target: TargetProfile,
        goal: CampaignGoal,
        exc: HarnessBuildError,
    ) -> str:
        session_id = self.store.new_agent_session({
            "target_path": str(target.root),
            "engine": goal.engine.value,
            "status": "failed",
            "error": str(exc),
        })
        for record in exc.trace_records:
            self.store.record_agent_session_trace(session_id, record)
        return session_id

    async def _smoke_run(self, artifact: BuildArtifact) -> ValidationResult:
        engine = tools._runtime.runtime().engine(artifact.engine)
        smoke_dir = artifact.binary_path.parent.parent / "smoke"
        corpus_dir = smoke_dir / "corpus"
        crash_dir = smoke_dir / "crashes"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        crash_dir.mkdir(parents=True, exist_ok=True)
        seed = corpus_dir / "empty"
        if not seed.exists():
            seed.write_bytes(b"")
        cfg = CampaignConfig(
            artifact=artifact,
            corpus_dir=corpus_dir,
            crash_dir=crash_dir,
            dictionary_path=None,
            time_budget_sec=1,
            max_memory_mb=512,
            campaign_id="smoke",
            extra_args=["-runs=1"],
        )
        try:
            async for ev in engine.run(cfg):
                if ev.kind == EventKind.NEW_CRASH:
                    return ValidationResult("smoke_run", False, f"crash: {ev.payload}")
                if ev.kind == EventKind.ENGINE_ERROR:
                    return ValidationResult("smoke_run", False, f"engine_error: {ev.payload}")
        except Exception as exc:  # noqa: BLE001
            return ValidationResult("smoke_run", False, f"{type(exc).__name__}: {exc}")
        finally:
            try:
                await engine.stop("smoke")
            except Exception:
                pass
        return ValidationResult("smoke_run", True, "short engine run completed")

    async def _target_reached(
        self,
        spec: HarnessSpec,
        artifact: BuildArtifact,
    ) -> ValidationResult:
        del artifact
        from .agent_harness.validators import validate_target_referenced_by_harness

        return validate_target_referenced_by_harness(spec)

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
            harness_check = validate_crash_not_from_harness(
                c,
                artifact.harness_source_path if artifact else None,
                _read_crash_report(c.reproduce_log_path),
            )
            assessed = subagents.exploit_assessor(c, goal.target_path)
            if not harness_check.passed:
                self.store.record_event(FuzzEvent(
                    kind=EventKind.ENGINE_ERROR, campaign_id=cid,
                    ts=datetime.now(timezone.utc),
                    payload={
                        "harness_fault_suspected": harness_check.detail,
                        "crash_id": assessed.crash_id,
                    },
                ))
                assessed.exploitability_notes = (
                    "[HARNESS FAULT SUSPECTED] "
                    + harness_check.detail
                    + "\n"
                    + (assessed.exploitability_notes or "")
                )
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
        observation = AgentObservation(
            kind="coverage_plateau",
            summary="plateau: explore uncovered branches",
            diagnostics=str(ev.payload),
            artifacts={
                "coverage_uncovered": self.store.paths(ev.campaign_id)["coverage_uncovered"],
                "coverage_summary": self.store.paths(ev.campaign_id)["coverage_summary"],
            },
            raw={"event": ev},
        )
        decision = self._coverage_policy.decide(observation)
        strategy: dict[str, Any] = {}
        if decision.action in (HarnessAction.ADD_SEED, HarnessAction.ADD_DICTIONARY):
            strategy = tools.mutate_strategy(
                ev.campaign_id,
                hint=str(decision.payload.get("hint") or observation.summary),
            )
        self.store.record_agent_trace(ev.campaign_id, {
            "phase": "coverage_plateau",
            "observation": observation,
            "decision": decision,
            "action": {"tool_chain": ["mutate_strategy"] if strategy else []},
            "result": strategy,
            "score": {},
        })
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
        if self._artifact is None:
            raise RuntimeError("cannot restart plateau campaign without build artifact")
        new_cid = tools.start_fuzz_campaign(
            self._artifact,
            str(self.store.paths(ev.campaign_id)["corpus_dir"]),
            remaining,
            strategy.get("dictionary_path"),
            resumed_from=ev.campaign_id,
        )
        if self._harness_result is not None:
            self._persist_agent_trace(new_cid, self._harness_result)
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


def _read_crash_report(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None
