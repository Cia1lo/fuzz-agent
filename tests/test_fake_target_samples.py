from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fuzz_agent.agent_harness import AgentHarnessSession, HarnessAction, ValidationResult
from fuzz_agent.agent_harness.validators import validate_crash_not_from_harness
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
    CrashRecord,
)
from fuzz_agent.state.store import CampaignStore

FIXTURES = Path(__file__).parent / "fixtures" / "fake_targets"


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    dst = tmp_path / name
    shutil.copytree(FIXTURES / name, dst)
    return dst


def _target(root: Path) -> TargetProfile:
    return TargetProfile(
        root=root,
        language=Language.CPP,
        entry_points=["ParseThing"],
        build_system="fake",
    )


def _spec(target: TargetProfile, attempt: int, source: str) -> HarnessSpec:
    path = target.root / ".fuzz" / "harness" / "ParseThing" / f"attempt_{attempt}.cc"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return HarnessSpec(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        source_path=path,
        attempt=attempt,
    )


async def _fake_build(spec: HarnessSpec) -> BuildArtifact:
    out_dir = spec.target.root / ".fuzz" / "build"
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
    log.write_text("fake build ok", encoding="utf-8")
    binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
    binary.write_text("fake binary", encoding="utf-8")
    return BuildArtifact(
        binary_path=binary,
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=log,
        harness_source_path=spec.source_path,
    )


def test_fake_target_not_reached_forces_second_harness_attempt(tmp_path):
    root = _copy_fixture(tmp_path, "cpp_target_not_reached")
    target = _target(root)

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        if attempt == 1:
            return _spec(target, attempt, "int LLVMFuzzerTestOneInput() { return 0; }")
        return _spec(
            target,
            attempt,
            "int ParseThing(const unsigned char*, unsigned long);\n"
            "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {\n"
            "  return ParseThing(d, s);\n"
            "}\n",
        )

    result = asyncio.run(AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=_fake_build,
        max_attempts=2,
    ).run())

    assert result.attempts[0].score.target_reached is False
    assert result.trace_records[0].decision["action"] is HarnessAction.REGENERATE_HARNESS
    assert result.attempts[1].score.target_reached is True
    assert result.trace_records[1].decision["action"] is HarnessAction.ACCEPT_HARNESS


def test_fake_smoke_crash_forces_repair_attempt(tmp_path):
    root = _copy_fixture(tmp_path, "cpp_smoke_crash")
    target = _target(root)
    smoke_calls = 0

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        return _spec(
            target,
            attempt,
            "int ParseThing(const unsigned char*, unsigned long);\n"
            "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {\n"
            "  return ParseThing(d, s);\n"
            "}\n",
        )

    async def smoke_run(artifact: BuildArtifact) -> ValidationResult:
        nonlocal smoke_calls
        smoke_calls += 1
        return ValidationResult("smoke_run", smoke_calls > 1, "startup crash" if smoke_calls == 1 else "ok")

    result = asyncio.run(AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=_fake_build,
        smoke_run=smoke_run,
        max_attempts=2,
    ).run())

    assert result.attempts[0].score.smoke_passed is False
    assert result.attempts[1].score.smoke_passed is True


def test_fake_harness_owned_crash_is_not_target_bug(tmp_path):
    root = _copy_fixture(tmp_path, "cpp_harness_owned_crash")
    harness = root / ".fuzz" / "harness" / "ParseThing" / "attempt_1.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("int LLVMFuzzerTestOneInput() { __builtin_trap(); }", encoding="utf-8")
    crash = CrashRecord(
        crash_id="harness-crash",
        campaign_id="cid",
        input_path=root / "crash",
        minimized_path=None,
        stack_hash="stack",
        top_frames=["LLVMFuzzerTestOneInput"],
        sanitizer_kind="trap",
        discovered_at=datetime.now(timezone.utc),
    )

    result = validate_crash_not_from_harness(crash, harness, "trap in LLVMFuzzerTestOneInput")

    assert not result.passed


def test_fake_real_target_crash_is_not_classified_as_harness_fault(tmp_path):
    root = _copy_fixture(tmp_path, "cpp_real_target_crash")
    harness = root / ".fuzz" / "harness" / "ParseThing" / "attempt_1.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("calls ParseThing", encoding="utf-8")
    crash = CrashRecord(
        crash_id="target-crash",
        campaign_id="cid",
        input_path=root / "crash",
        minimized_path=None,
        stack_hash="stack",
        top_frames=["ParseThing", "LLVMFuzzerTestOneInput"],
        sanitizer_kind="null-deref",
        discovered_at=datetime.now(timezone.utc),
    )

    result = validate_crash_not_from_harness(crash, harness, "crash in ParseThing")

    assert result.passed


def test_fake_plateau_records_policy_trace(tmp_path, monkeypatch):
    root = _copy_fixture(tmp_path, "cpp_plateau")
    store = CampaignStore(tmp_path)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=root / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=root / "build.log",
        ),
        corpus_dir=root / "corpus",
        crash_dir=root / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = store.new_campaign(cfg)
    paths = store.paths(cid)
    paths["coverage_uncovered"].write_text(
        (root / "coverage_uncovered.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "fuzz_agent.orchestrator.tools.mutate_strategy",
        lambda campaign_id, hint: {"dictionary_path": str(paths["base"] / "extra.dict")},
    )

    orch = Orchestrator(store, EventBus(), hitl=AlwaysDeny())
    asyncio.run(orch._on_plateau(
        FuzzEvent(
            kind=EventKind.PLATEAU,
            campaign_id=cid,
            ts=datetime.now(timezone.utc),
            payload={"idle_sec": 1},
        ),
        CampaignGoal(target_path=root, time_budget_sec=10),
    ))

    trace = store.list_agent_trace(cid)
    assert trace[-1]["phase"] == "coverage_plateau"
    assert trace[-1]["decision"]["action"] == "add_dictionary"
