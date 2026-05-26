from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzz_agent.agent_harness import (
    AgentHarnessSession,
    HarnessAction,
    HarnessAttemptObservation,
    HarnessBuildError,
    LLMHarnessPolicy,
    ValidationResult,
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
    assert result.trace_records[0].observation["kind"] == "harness_build_failure"
    assert result.trace_records[1].observation["kind"] == "harness_accepted"
    assert result.trace_records[0].decision["action"] is HarnessAction.REGENERATE_HARNESS
    assert result.trace_records[1].decision["action"] is HarnessAction.ACCEPT_HARNESS


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
            "payload": {"path": str(spec.source_path)},
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
