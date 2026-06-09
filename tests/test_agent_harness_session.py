from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzz_agent.agent_harness import (
    AgentObservation,
    AgentHarnessSession,
    HarnessAction,
    HarnessAttemptObservation,
    HarnessBuildError,
    HarnessDecision,
    HarnessPolicy,
    LLMHarnessPolicy,
    ValidationResult,
    agent_observation_to_dict,
)
from fuzz_agent.agent_harness.validators import (
    validate_crash_not_from_harness,
    validate_target_reached_by_artifact,
    validate_target_referenced_by_harness,
)
from fuzz_agent.state.models import (
    BuildArtifact,
    CrashRecord,
    EngineKind,
    HarnessSpec,
    Language,
    TargetProfile,
)


def _target(root: Path) -> TargetProfile:
    return TargetProfile(
        root=root,
        language=Language.CPP,
        entry_points=["ParseThing"],
        build_system="cmake",
    )


def _spec(target: TargetProfile, attempt: int) -> HarnessSpec:
    harness = target.root / ".fuzz" / "harness" / "ParseThing" / f"attempt_{attempt}.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text(
        "int ParseThing(const unsigned char *, unsigned long);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "  return ParseThing(data, size);\n"
        "}\n",
        encoding="utf-8",
    )
    return HarnessSpec(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        source_path=harness,
        attempt=attempt,
    )


def test_agent_observation_schema_roundtrip():
    observation = AgentObservation(
        kind="harness_build_failure",
        summary="compile failed",
        diagnostics="missing include",
        validations=[ValidationResult("build_passed", False, "compile failed")],
        score={"compiled": False},
    )

    restored = AgentObservation.from_dict(agent_observation_to_dict(observation))

    assert restored.schema_version == observation.schema_version
    assert restored.kind == observation.kind
    assert restored.validations[0].name == "build_passed"
    assert restored.score == {"compiled": False}

    legacy = agent_observation_to_dict(observation)
    legacy.pop("schema_version")
    assert AgentObservation.from_dict(legacy).schema_version == observation.schema_version


def test_agent_harness_session_retries_with_build_diagnostics(tmp_path):
    target = _target(tmp_path)
    diagnostics_seen: list[str | None] = []

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        diagnostics_seen.append(diagnostics)
        return _spec(target, attempt)

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text(f"attempt {spec.attempt} build log", encoding="utf-8")
        if spec.attempt == 1:
            raise RuntimeError("compile failed")
        binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
        binary.write_text("binary", encoding="utf-8")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    first = generate(1, None)
    session = AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        max_attempts=3,
    )

    result = asyncio.run(session.run(initial_spec=first))

    assert result.artifact.binary_path.name == "fuzz_ParseThing_attempt_2"
    assert [a.attempt for a in result.attempts] == [1, 2]
    assert "compile failed" in diagnostics_seen[1]
    assert "attempt 1 build log" in diagnostics_seen[1]
    assert "Recent harness attempt memory" in diagnostics_seen[1]
    assert "attempt 1: build_failed" in diagnostics_seen[1]
    assert result.trace_records[0].observation["kind"] == "harness_build_failure"
    assert (
        AgentObservation.from_dict(result.trace_records[0].observation).kind
        == "harness_build_failure"
    )
    assert result.trace_records[1].observation["kind"] == "harness_accepted"
    assert result.trace_records[0].decision["action"] is HarnessAction.REGENERATE_HARNESS
    assert result.trace_records[1].decision["action"] is HarnessAction.ACCEPT_HARNESS


def test_agent_harness_session_classifies_build_failure(tmp_path):
    target = _target(tmp_path)

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        return _spec(target, attempt)

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text("fatal error: 'parser.h' file not found\n", encoding="utf-8")
        raise RuntimeError("compile failed")

    session = AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        max_attempts=1,
    )

    with pytest.raises(HarnessBuildError) as exc:
        asyncio.run(session.run())

    failure = exc.value.trace_records[0].observation["raw"]["build_failure"]
    assert failure["kind"] == "missing_include"
    assert failure["symbol"] == "parser.h"


def test_agent_harness_session_applies_patch_harness_action(tmp_path):
    target = _target(tmp_path)
    fixed_source = (
        "int ParseThing(const unsigned char *, unsigned long);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "  return ParseThing(data, size);\n"
        "}\n"
    )

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        spec = _spec(target, attempt)
        spec.source_path.write_text("bad harness", encoding="utf-8")
        return spec

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text("build log", encoding="utf-8")
        if "bad harness" in spec.source_path.read_text(encoding="utf-8"):
            raise RuntimeError("compile failed")
        binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
        binary.write_text("binary", encoding="utf-8")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    class PatchPolicy(HarnessPolicy):
        def decide(self, observation, *, attempt: int, max_attempts: int) -> HarnessDecision:
            if observation.kind == "harness_build_failure":
                return HarnessDecision(
                    HarnessAction.PATCH_HARNESS,
                    "replace bad harness source",
                    {"path": str(observation.artifacts["source_path"]), "source": fixed_source},
                )
            return super().decide(observation, attempt=attempt, max_attempts=max_attempts)

    result = asyncio.run(AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        policy=PatchPolicy(),
        max_attempts=2,
    ).run())

    assert result.spec.attempt == 2
    assert "ParseThing" in result.spec.source_path.read_text(encoding="utf-8")
    assert result.trace_records[0].action["applied"] is True
    assert result.trace_records[0].action["action_type"] == "patch_harness"


def test_agent_harness_session_applies_dictionary_action(tmp_path):
    target = _target(tmp_path)

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        return _spec(target, attempt)

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text("ok", encoding="utf-8")
        binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
        binary.write_text("binary", encoding="utf-8")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    async def target_reached(spec: HarnessSpec, artifact: BuildArtifact) -> ValidationResult:
        del artifact
        return ValidationResult("target_reached", spec.dictionary_path is not None, "needs dict")

    class DictionaryPolicy(HarnessPolicy):
        def decide(self, observation, *, attempt: int, max_attempts: int) -> HarnessDecision:
            if observation.kind == "harness_target_not_reached":
                return HarnessDecision(
                    HarnessAction.ADD_DICTIONARY,
                    "add magic token",
                    {"tokens": ["MAGIC"]},
                )
            return super().decide(observation, attempt=attempt, max_attempts=max_attempts)

    result = asyncio.run(AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        target_reached=target_reached,
        policy=DictionaryPolicy(),
        max_attempts=2,
    ).run())

    assert result.spec.dictionary_path is not None
    assert result.spec.dictionary_path.read_text(encoding="utf-8").splitlines() == ['"MAGIC"']


def test_agent_harness_session_changes_entry_point(tmp_path):
    target = TargetProfile(
        root=tmp_path,
        language=Language.CPP,
        entry_points=["ParseThing", "OtherThing"],
        build_system="cmake",
    )

    def generate_for_entry(entry: str, attempt: int, diagnostics: str | None) -> HarnessSpec:
        del diagnostics
        spec = _spec(target, attempt)
        source = spec.source_path.read_text(encoding="utf-8").replace("ParseThing", entry)
        path = spec.source_path.parent.parent / entry / f"attempt_{attempt}.cc"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return HarnessSpec(
            target=target,
            entry=entry,
            engine=EngineKind.LIBFUZZER,
            source_path=path,
            attempt=attempt,
        )

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text("ok", encoding="utf-8")
        binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
        binary.write_text("binary", encoding="utf-8")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    async def target_reached(spec: HarnessSpec, artifact: BuildArtifact) -> ValidationResult:
        del artifact
        return ValidationResult("target_reached", spec.entry == "OtherThing", spec.entry)

    class ChangeEntryPolicy(HarnessPolicy):
        def decide(self, observation, *, attempt: int, max_attempts: int) -> HarnessDecision:
            if observation.kind == "harness_target_not_reached":
                return HarnessDecision(
                    HarnessAction.CHANGE_ENTRY_POINT,
                    "try alternate parser",
                    {"entry": "OtherThing"},
                )
            return super().decide(observation, attempt=attempt, max_attempts=max_attempts)

    result = asyncio.run(AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=lambda attempt, diagnostics: generate_for_entry(
            "ParseThing",
            attempt,
            diagnostics,
        ),
        generate_harness_for_entry=generate_for_entry,
        build=build,
        target_reached=target_reached,
        policy=ChangeEntryPolicy(),
        max_attempts=2,
    ).run())

    assert result.spec.entry == "OtherThing"


def test_agent_harness_session_fails_after_validation_failures(tmp_path):
    target = _target(tmp_path)

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        return _spec(target, attempt)

    async def build(spec: HarnessSpec) -> BuildArtifact:
        log = spec.target.root / ".fuzz" / "build" / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("ok", encoding="utf-8")
        return BuildArtifact(
            binary_path=spec.target.root / ".fuzz" / "build" / "missing-binary",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    session = AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        max_attempts=2,
    )

    with pytest.raises(HarnessBuildError) as exc:
        asyncio.run(session.run())

    assert len(exc.value.attempts) == 2
    assert len(exc.value.trace_records) == 2
    assert exc.value.attempts[-1].validations[-2].name == "artifact_exists"


def test_agent_harness_session_uses_smoke_run_validation(tmp_path):
    target = _target(tmp_path)
    smoke_calls = 0

    def generate(attempt: int, diagnostics: str | None) -> HarnessSpec:
        return _spec(target, attempt)

    async def build(spec: HarnessSpec) -> BuildArtifact:
        out_dir = spec.target.root / ".fuzz" / "build"
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"
        log.write_text("ok", encoding="utf-8")
        binary = out_dir / f"fuzz_{spec.entry}_attempt_{spec.attempt}"
        binary.write_text("binary", encoding="utf-8")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=log,
            harness_source_path=spec.source_path,
        )

    async def smoke_run(artifact: BuildArtifact) -> ValidationResult:
        nonlocal smoke_calls
        smoke_calls += 1
        if smoke_calls == 1:
            return ValidationResult("smoke_run", False, "startup crash")
        return ValidationResult("smoke_run", True, "ok")

    session = AgentHarnessSession(
        target=target,
        entry="ParseThing",
        engine=EngineKind.LIBFUZZER,
        invariants=[],
        generate_harness=generate,
        build=build,
        smoke_run=smoke_run,
        max_attempts=2,
    )

    result = asyncio.run(session.run())

    assert [attempt.score.smoke_passed for attempt in result.attempts if attempt.score] == [
        False,
        True,
    ]
    assert [attempt.score.target_reached for attempt in result.attempts if attempt.score] == [
        None,
        True,
    ]
    assert result.trace_records[0].observation["kind"] == "harness_smoke_failure"
    assert (
        AgentObservation.from_dict(result.trace_records[0].observation).kind
        == "harness_smoke_failure"
    )
    assert result.trace_records[0].decision["action"] is HarnessAction.REGENERATE_HARNESS
    assert result.trace_records[1].decision["action"] is HarnessAction.ACCEPT_HARNESS


def test_target_referenced_validator_rejects_harness_that_never_calls_entry(tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    spec.source_path.write_text("int LLVMFuzzerTestOneInput() { return 0; }", encoding="utf-8")

    result = validate_target_referenced_by_harness(spec)

    assert not result.passed


def test_target_reached_artifact_validator_uses_symbol_evidence(monkeypatch, tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    binary = tmp_path / "fuzz"
    binary.write_text("binary", encoding="utf-8")
    artifact = BuildArtifact(
        binary_path=binary,
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
        harness_source_path=spec.source_path,
    )

    class Result:
        returncode = 0
        stdout = "00000000 T OtherEntry\n"

    monkeypatch.setattr("fuzz_agent.agent_harness.validators.shutil.which", lambda name: "/usr/bin/nm")
    monkeypatch.setattr("fuzz_agent.agent_harness.validators.subprocess.run", lambda *args, **kwargs: Result())

    result = validate_target_reached_by_artifact(spec, artifact)

    assert not result.passed
    assert "does not expose target symbol" in result.detail


def test_target_reached_artifact_validator_accepts_runtime_coverage(monkeypatch, tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    binary = tmp_path / "fuzz"
    binary.write_text("binary", encoding="utf-8")
    artifact = BuildArtifact(
        binary_path=binary,
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
        harness_source_path=spec.source_path,
    )

    class Result:
        returncode = 0
        stdout = "COVERED_FUNC: ParseThing\n"
        stderr = ""

    monkeypatch.setattr("fuzz_agent.agent_harness.validators.os.access", lambda *args: True)
    monkeypatch.setattr(
        "fuzz_agent.agent_harness.validators.subprocess.run",
        lambda *args, **kwargs: Result(),
    )

    result = validate_target_reached_by_artifact(spec, artifact)

    assert result.passed
    assert "runtime coverage" in result.detail


def test_target_reached_artifact_validator_accepts_coverage_summary(tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    binary = tmp_path / ".fuzz" / "build" / "fuzz"
    binary.parent.mkdir(parents=True)
    binary.write_text("binary", encoding="utf-8")
    (binary.parent / "coverage_summary.txt").write_text(
        "Filename Regions Cover\nparser.cc: ParseThing covered\n",
        encoding="utf-8",
    )
    artifact = BuildArtifact(
        binary_path=binary,
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
        harness_source_path=spec.source_path,
    )

    result = validate_target_reached_by_artifact(spec, artifact)

    assert result.passed
    assert "coverage artifact" in result.detail


def test_target_reached_artifact_validator_rejects_uncovered_entry(tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    binary = tmp_path / ".fuzz" / "build" / "fuzz"
    binary.parent.mkdir(parents=True)
    binary.write_text("binary", encoding="utf-8")
    (binary.parent / "coverage_uncovered.json").write_text(
        '[{"func": "ParseThing", "file": "parser.cc"}]',
        encoding="utf-8",
    )
    artifact = BuildArtifact(
        binary_path=binary,
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
        harness_source_path=spec.source_path,
    )

    result = validate_target_reached_by_artifact(spec, artifact)

    assert not result.passed
    assert "uncovered" in result.detail


def test_validate_crash_not_from_harness_flags_harness_top_frame(tmp_path):
    harness = tmp_path / "attempt_1.cc"
    crash = CrashRecord(
        crash_id="c",
        campaign_id="cid",
        input_path=tmp_path / "crash",
        minimized_path=None,
        stack_hash="s",
        top_frames=["attempt_1.cc: LLVMFuzzerTestOneInput"],
        sanitizer_kind="heap-buffer-overflow",
        discovered_at=datetime.now(timezone.utc),
    )

    result = validate_crash_not_from_harness(crash, harness)

    assert not result.passed


def test_validate_crash_not_from_harness_flags_rust_harness_panic(tmp_path):
    harness = tmp_path / "parse_attempt_1.rs"
    crash = CrashRecord(
        crash_id="c",
        campaign_id="cid",
        input_path=tmp_path / "crash",
        minimized_path=None,
        stack_hash="s",
        top_frames=["fuzz_target"],
        sanitizer_kind="panic",
        discovered_at=datetime.now(timezone.utc),
    )

    result = validate_crash_not_from_harness(
        crash,
        harness,
        "thread 'main' panicked at assertion failed in parse_attempt_1.rs",
    )

    assert not result.passed


def test_llm_harness_policy_validates_structured_decision(monkeypatch, tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    observation = HarnessAttemptObservation(
        attempt=1,
        entry=spec.entry,
        engine=spec.engine,
        source_path=spec.source_path,
        dictionary_path=None,
        build_log_path=None,
        build_passed=False,
        diagnostics="failed",
        validations=[ValidationResult("build_passed", False, "failed")],
        score=None,
    )

    monkeypatch.setattr(
        "fuzz_agent.subagents._llm.call_llm_json",
        lambda *args, **kwargs: {
            "action": "patch_harness",
            "reason": "missing include",
            "payload": {"path": str(spec.source_path), "source": spec.source_path.read_text()},
        },
    )

    decision = LLMHarnessPolicy().decide(observation, attempt=1, max_attempts=3)

    assert decision.action is HarnessAction.PATCH_HARNESS
    assert decision.payload["path"] == str(spec.source_path)


def test_llm_harness_policy_falls_back_on_unknown_action(monkeypatch, tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    observation = HarnessAttemptObservation(
        attempt=1,
        entry=spec.entry,
        engine=spec.engine,
        source_path=spec.source_path,
        dictionary_path=None,
        build_log_path=None,
        build_passed=False,
        diagnostics="failed",
        validations=[ValidationResult("build_passed", False, "failed")],
        score=None,
    )
    monkeypatch.setattr(
        "fuzz_agent.subagents._llm.call_llm_json",
        lambda *args, **kwargs: {"action": "shell_out", "reason": "bad", "payload": {}},
    )

    decision = LLMHarnessPolicy().decide(observation, attempt=1, max_attempts=3)

    assert decision.action is HarnessAction.REGENERATE_HARNESS
    assert decision.payload["fallback"] is True


def test_llm_harness_policy_rejects_patch_path_outside_current_harness(monkeypatch, tmp_path):
    target = _target(tmp_path)
    spec = _spec(target, 1)
    observation = HarnessAttemptObservation(
        attempt=1,
        entry=spec.entry,
        engine=spec.engine,
        source_path=spec.source_path,
        dictionary_path=None,
        build_log_path=None,
        build_passed=False,
        diagnostics="failed",
        validations=[ValidationResult("build_passed", False, "failed")],
        score=None,
    )
    monkeypatch.setattr(
        "fuzz_agent.subagents._llm.call_llm_json",
        lambda *args, **kwargs: {
            "action": "patch_harness",
            "reason": "try another path",
            "payload": {"path": str(tmp_path / "other.cc"), "patch": "x"},
        },
    )

    decision = LLMHarnessPolicy().decide(observation, attempt=1, max_attempts=3)

    assert decision.action is HarnessAction.REGENERATE_HARNESS
    assert decision.payload["fallback"] is True
