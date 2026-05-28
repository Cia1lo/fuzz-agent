import asyncio
import dataclasses
import importlib
from datetime import datetime, timezone

from fuzz_agent import tools
import fuzz_agent.orchestrator as orchestrator_module
from fuzz_agent.events.stream import EventBus
from fuzz_agent.hitl import AlwaysAllow, AlwaysDeny
from fuzz_agent.orchestrator import CampaignGoal, Orchestrator
from fuzz_agent.state.models import (
    BuildArtifact,
    CrashRecord,
    EngineKind,
    Severity,
)
from fuzz_agent.state.store import CampaignStore


class FakeEngine:
    def minimize(self, artifact, input_path, out_path, timeout_sec=60):
        out_path.write_bytes(input_path.read_bytes())
        return out_path

    def reproduce(self, artifact, input_path, timeout_sec=30):
        return None


class FinalizeOrchestrator(Orchestrator):
    async def _make_harness(self, target, goal):
        return None

    async def _build(self, spec):
        return self._artifact

    async def _launch(self, artifact, goal):
        self._artifact = artifact
        self._engine = FakeEngine()
        self._active_cid = "cid"
        return self._active_cid


def _seeded_orchestrator(tmp_path, hitl):
    store = CampaignStore(tmp_path)
    cid = "cid"
    paths = store.paths(cid)
    paths["crash_dir"].mkdir(parents=True, exist_ok=True)
    crash_path = paths["crash_dir"] / "crash-input"
    crash_path.write_bytes(b"crash")

    crash = CrashRecord(
        crash_id="crash-1",
        campaign_id=cid,
        input_path=crash_path,
        minimized_path=None,
        stack_hash="stack-1",
        top_frames=["0x1234"],
        sanitizer_kind="heap-buffer-overflow",
        discovered_at=datetime.now(timezone.utc),
    )
    store.save_crash(crash)

    artifact = BuildArtifact(
        binary_path=tmp_path / "build" / "fuzz-target",
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
    )
    artifact.binary_path.parent.mkdir(parents=True, exist_ok=True)
    artifact.binary_path.write_text("binary", encoding="utf-8")

    orch = FinalizeOrchestrator(store, EventBus(), hitl=hitl)
    orch._artifact = artifact
    orch._engine = FakeEngine()
    orch._active_cid = cid
    return orch, store, cid, crash


def _patch_finalize_dependencies(monkeypatch, crash):
    def fake_assessor(record, source_root):
        return dataclasses.replace(
            record,
            severity=Severity.CRITICAL,
            exploitability_notes="bad",
        )

    monkeypatch.setattr(orchestrator_module, "assess_exploitability", fake_assessor)
    monkeypatch.setattr(tools, "triage_crashes", lambda campaign_id, top_n: [crash])


def test_finalize_redacts_critical_when_hitl_denies(tmp_path, monkeypatch):
    orch, store, cid, crash = _seeded_orchestrator(tmp_path, AlwaysDeny())
    _patch_finalize_dependencies(monkeypatch, crash)

    goal = CampaignGoal(target_path=tmp_path, time_budget_sec=10)
    asyncio.run(orch._finalize(cid, goal))

    saved = store.list_crashes(cid)[0]
    assert saved.exploitability_notes.startswith("[REDACTED")
    assert saved.minimized_path == crash.input_path.parent / (crash.input_path.name + ".min")


def test_finalize_does_not_redact_critical_when_hitl_allows(tmp_path, monkeypatch):
    orch, store, cid, crash = _seeded_orchestrator(tmp_path, AlwaysAllow())
    _patch_finalize_dependencies(monkeypatch, crash)

    goal = CampaignGoal(target_path=tmp_path, time_budget_sec=10)
    asyncio.run(orch._finalize(cid, goal))

    saved = store.list_crashes(cid)[0]
    assert not saved.exploitability_notes.startswith("[REDACTED")
    assert saved.minimized_path == crash.input_path.parent / (crash.input_path.name + ".min")


def test_finalize_assessor_survives_submodule_import(tmp_path, monkeypatch):
    orch, store, cid, crash = _seeded_orchestrator(tmp_path, AlwaysAllow())
    second_path = crash.input_path.parent / "crash-input-2"
    second_path.write_bytes(b"crash2")
    second = dataclasses.replace(
        crash,
        crash_id="crash-2",
        input_path=second_path,
        stack_hash="stack-2",
    )
    store.save_crash(second)

    importlib.import_module("fuzz_agent.subagents.exploit_assessor")
    monkeypatch.setattr(tools, "triage_crashes", lambda campaign_id, top_n: [crash, second])

    goal = CampaignGoal(target_path=tmp_path, time_budget_sec=10)
    asyncio.run(orch._finalize(cid, goal))

    saved = store.list_crashes(cid)
    assert {record.crash_id for record in saved} == {"crash-1", "crash-2"}
