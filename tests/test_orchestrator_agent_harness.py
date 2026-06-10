from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzz_agent.agent_harness import AgentHarnessResult, HarnessBuildError
from fuzz_agent.events.stream import EventBus
from fuzz_agent.hitl import AlwaysDeny
from fuzz_agent.orchestrator import CampaignGoal, Orchestrator
from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    EngineKind,
    EventKind,
    FuzzEvent,
    HarnessSpec,
    Language,
    TargetProfile,
)
from fuzz_agent.state.store import CampaignStore


class FailingHarnessOrchestrator(Orchestrator):
    async def _analyze(self, path: Path) -> TargetProfile:
        return TargetProfile(
            root=path,
            language=Language.CPP,
            entry_points=["ParseThing"],
            build_system="cmake",
        )

    async def _make_harness(self, target: TargetProfile, goal: CampaignGoal) -> HarnessSpec:
        return self._spec(target, 1)

    def _generate_harness(
        self,
        target: TargetProfile,
        entry: str,
        goal: CampaignGoal,
        *,
        attempt: int,
        diagnostics: str | None,
    ) -> HarnessSpec:
        return self._spec(target, attempt)

    async def _build(self, spec: HarnessSpec):
        log = spec.target.root / ".fuzz" / "build" / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"attempt {spec.attempt} failed", encoding="utf-8")
        raise RuntimeError("compile failed")

    @staticmethod
    def _spec(target: TargetProfile, attempt: int) -> HarnessSpec:
        source = target.root / ".fuzz" / "harness" / "ParseThing" / f"attempt_{attempt}.cc"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("bad harness", encoding="utf-8")
        return HarnessSpec(
            target=target,
            entry="ParseThing",
            engine=EngineKind.LIBFUZZER,
            source_path=source,
            attempt=attempt,
        )


def test_orchestrator_persists_failed_agent_trace_before_campaign(tmp_path):
    store = CampaignStore(tmp_path)
    orch = FailingHarnessOrchestrator(store, EventBus())

    with pytest.raises(HarnessBuildError):
        asyncio.run(orch.run(CampaignGoal(target_path=tmp_path, time_budget_sec=1)))

    sessions = list((tmp_path / "state" / "agent_sessions").iterdir())
    assert len(sessions) == 1
    trace = store.list_agent_session_trace(sessions[0].name)
    assert len(trace) == 3
    assert trace[-1]["decision"]["action"] == "stop_failed"


def test_orchestrator_prefers_byte_oriented_entry_point(tmp_path):
    (tmp_path / "parser.cc").write_text(
        "int InitConfig();\n"
        "int ParseBytes(const unsigned char *data, unsigned long size) { return 0; }\n",
        encoding="utf-8",
    )
    target = TargetProfile(
        root=tmp_path,
        language=Language.CPP,
        entry_points=["InitConfig", "ParseBytes"],
        build_system="cmake",
    )
    orch = Orchestrator(CampaignStore(tmp_path / "state-root"), EventBus())

    entry = orch._select_entry_point(
        target,
        CampaignGoal(target_path=tmp_path, time_budget_sec=1),
    )

    assert entry == "ParseBytes"


def test_orchestrator_records_policy_decision_for_plateau(tmp_path, monkeypatch, make_stats):
    store = CampaignStore(tmp_path)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = store.new_campaign(cfg)
    store.record_stats(make_stats(cid, edges_covered=13))
    calls: list[tuple[str, str]] = []

    def fake_mutate(campaign_id: str, hint: str):
        calls.append((campaign_id, hint))
        return {"dictionary_path": str(tmp_path / "extra.dict")}

    monkeypatch.setattr("fuzz_agent.orchestrator.tools.mutate_strategy", fake_mutate)
    orch = Orchestrator(store, EventBus(), hitl=AlwaysDeny())

    asyncio.run(orch._on_plateau(
        FuzzEvent(
            kind=EventKind.PLATEAU,
            campaign_id=cid,
            ts=datetime.now(timezone.utc),
            payload={"idle_sec": 1},
        ),
        CampaignGoal(target_path=tmp_path, time_budget_sec=10),
    ))

    trace = store.list_agent_trace(cid)
    assert calls == [(cid, "plateau: explore uncovered branches")]
    assert trace[-1]["phase"] == "coverage_plateau"
    assert trace[-1]["decision"]["action"] == "add_dictionary"
    assert trace[-1]["observation"]["kind"] == "coverage_plateau"
    assert trace[-1]["score"]["coverage_delta"] == 0
    assert trace[-1]["score"]["edges_before"] == 13


def test_orchestrator_records_coverage_delta_trace(tmp_path):
    store = CampaignStore(tmp_path)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = store.new_campaign(cfg)
    orch = Orchestrator(store, EventBus())
    orch._coverage_baselines[cid] = 13

    asyncio.run(orch._on_new_coverage(
        FuzzEvent(
            kind=EventKind.NEW_COVERAGE,
            campaign_id=cid,
            ts=datetime.now(timezone.utc),
            payload={"edges": 21},
        ),
        CampaignGoal(target_path=tmp_path, time_budget_sec=10),
    ))

    trace = store.list_agent_trace(cid)
    assert trace[-1]["phase"] == "coverage_delta"
    assert trace[-1]["score"]["coverage_delta"] == 8
    assert trace[-1]["score"]["edges_before"] == 13
    assert trace[-1]["score"]["edges_after"] == 21
    assert trace[-1]["score"]["target_reached"] is None


def test_orchestrator_rebuilds_harness_from_plateau_input_model(
    tmp_path,
    monkeypatch,
    make_stats,
):
    store = CampaignStore(tmp_path)
    old_artifact = BuildArtifact(
        binary_path=tmp_path / "old_fuzz",
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "old_build.log",
        harness_source_path=tmp_path / ".fuzz" / "harness" / "ParseThing" / "attempt_1.cc",
    )
    cfg = CampaignConfig(
        artifact=old_artifact,
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = store.new_campaign(cfg)
    store.record_stats(make_stats(cid, edges_covered=13))
    target = TargetProfile(
        root=tmp_path,
        language=Language.CPP,
        entry_points=["ParseThing"],
        build_system="cmake",
    )
    spec = HarnessSpec(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        source_path=old_artifact.harness_source_path,
        attempt=1,
    )
    new_artifact = BuildArtifact(
        binary_path=tmp_path / "new_fuzz",
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "new_build.log",
        harness_source_path=tmp_path / ".fuzz" / "harness" / "ParseThing" / "attempt_2.cc",
    )

    strategy = {
        "dictionary_path": str(tmp_path / "extra.dict"),
        "harness_modeling_hint": "Preserve magic bytes 'MAGI' before payload.",
        "input_model_path": str(tmp_path / "input_model.json"),
        "input_model": {"tokens": ["MAGI"], "fields": [{"name": "magic"}], "confidence": 0.8},
        "added_seeds": [],
        "dict_additions": ["MAGI"],
    }
    monkeypatch.setattr("fuzz_agent.orchestrator.tools.mutate_strategy", lambda *_args, **_kwargs: strategy)
    monkeypatch.setattr("fuzz_agent.orchestrator.tools.stop_campaign", lambda *_: None)
    monkeypatch.setattr("fuzz_agent.orchestrator.tools.start_fuzz_campaign", lambda *_args, **_kwargs: "nextcid")
    orch = Orchestrator(store, EventBus())
    orch._artifact = old_artifact
    orch._harness_result = AgentHarnessResult(
        spec=spec,
        artifact=old_artifact,
        attempts=[],
        trace_records=[],
    )

    def fake_generate(target, entry, goal, *, attempt, diagnostics):
        assert "MAGI" in diagnostics
        source = tmp_path / ".fuzz" / "harness" / entry / f"attempt_{attempt}.cc"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("new harness", encoding="utf-8")
        return HarnessSpec(
            target=target,
            entry=entry,
            engine=goal.engine,
            source_path=source,
            attempt=attempt,
        )

    async def fake_build_with_retries(target, next_spec, goal, max_attempts=3):
        del target, goal, max_attempts
        orch._harness_result = AgentHarnessResult(
            spec=next_spec,
            artifact=new_artifact,
            attempts=[],
            trace_records=[],
        )
        return new_artifact

    monkeypatch.setattr(orch, "_generate_harness", fake_generate)
    monkeypatch.setattr(orch, "_build_with_retries", fake_build_with_retries)

    asyncio.run(orch._on_plateau(
        FuzzEvent(
            kind=EventKind.PLATEAU,
            campaign_id=cid,
            ts=datetime.now(timezone.utc),
            payload={"idle_sec": 1},
        ),
        CampaignGoal(target_path=tmp_path, time_budget_sec=10),
    ))

    trace = store.list_agent_trace(cid)
    assert any(row["phase"] == "coverage_input_model" for row in trace)
    assert orch._artifact == new_artifact
