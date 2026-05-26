"""Outer agent harness loop for generating and validating fuzz harnesses."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from ..state.models import BuildArtifact, EngineKind, HarnessSpec, TargetProfile
from .observation import (
    AgentObservation,
    HarnessAttemptObservation,
    ValidationResult,
    agent_observation_to_dict,
    observation_score_dict,
)
from .policy import HarnessAction, HarnessDecision, HarnessPolicy
from .trace import AgentTraceRecord, AgentTraceRecorder
from .validators import (
    score_build_attempt,
    validate_build_artifact,
    validate_target_referenced_by_harness,
)

GenerateHarness = Callable[[int, str | None], HarnessSpec]
BuildHarness = Callable[[HarnessSpec], Awaitable[BuildArtifact]]
SmokeRun = Callable[[BuildArtifact], Awaitable[ValidationResult]]
TargetReached = Callable[[HarnessSpec, BuildArtifact], Awaitable[ValidationResult]]


class HarnessBuildError(RuntimeError):
    """Raised when the agent cannot produce a valid buildable harness."""

    def __init__(
        self,
        message: str,
        attempts: list[HarnessAttemptObservation],
        trace_records: list[AgentTraceRecord],
    ) -> None:
        super().__init__(message)
        self.attempts = attempts
        self.trace_records = trace_records


@dataclass(frozen=True)
class AgentHarnessResult:
    spec: HarnessSpec
    artifact: BuildArtifact
    attempts: list[HarnessAttemptObservation]
    trace_records: list[AgentTraceRecord]


class AgentHarnessSession:
    """Generate, build, validate, and trace one fuzz harness until it is usable."""

    def __init__(
        self,
        *,
        target: TargetProfile,
        entry: str,
        engine: EngineKind,
        invariants: list[str],
        generate_harness: GenerateHarness,
        build: BuildHarness,
        smoke_run: SmokeRun | None = None,
        target_reached: TargetReached | None = None,
        policy: HarnessPolicy | None = None,
        max_attempts: int = 3,
        trace: AgentTraceRecorder | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.target = target
        self.entry = entry
        self.engine = engine
        self.invariants = invariants
        self.generate_harness = generate_harness
        self.build = build
        self.smoke_run = smoke_run
        self.target_reached = target_reached
        self.policy = policy or HarnessPolicy()
        self.max_attempts = max_attempts
        self.trace = trace or AgentTraceRecorder()
        self.attempts: list[HarnessAttemptObservation] = []

    async def run(self, initial_spec: HarnessSpec | None = None) -> AgentHarnessResult:
        diagnostics: str | None = None
        for attempt in range(1, self.max_attempts + 1):
            spec = (
                initial_spec
                if attempt == 1 and initial_spec is not None
                else self.generate_harness(attempt, diagnostics)
            )
            try:
                artifact = await self.build(spec)
            except Exception as exc:
                diagnostics = self._build_diagnostics(spec, exc)
                observation = self._record_failed_attempt(spec, attempt, diagnostics, exc)
                agent_observation = observation.to_agent_observation()
                decision = self.policy.decide(
                    agent_observation,
                    attempt=attempt,
                    max_attempts=self.max_attempts,
                )
                self._record_trace(
                    observation,
                    agent_observation=agent_observation,
                    decision=decision,
                    artifact=None,
                )
                if decision.action is HarnessAction.STOP_FAILED:
                    raise HarnessBuildError(
                        f"harness build failed after {attempt} attempts",
                        self.attempts,
                        self.trace.records,
                    ) from exc
                continue

            validations = validate_build_artifact(spec, artifact)
            if self.smoke_run is not None and all(v.passed for v in validations):
                validations.append(await self.smoke_run(artifact))
            if all(v.passed for v in validations):
                if self.target_reached is not None:
                    validations.append(await self.target_reached(spec, artifact))
                else:
                    validations.append(validate_target_referenced_by_harness(spec))
            diagnostics = self._validation_diagnostics(validations)
            observation = self._record_built_attempt(
                spec,
                artifact,
                attempt,
                diagnostics,
                validations,
            )
            agent_observation = observation.to_agent_observation()
            decision = self.policy.decide(
                agent_observation,
                attempt=attempt,
                max_attempts=self.max_attempts,
            )
            self._record_trace(
                observation,
                agent_observation=agent_observation,
                decision=decision,
                artifact=artifact,
            )
            if decision.action is HarnessAction.ACCEPT_HARNESS:
                return AgentHarnessResult(
                    spec=spec,
                    artifact=artifact,
                    attempts=list(self.attempts),
                    trace_records=self.trace.records,
                )
            if decision.action is HarnessAction.STOP_FAILED:
                raise HarnessBuildError(
                    f"harness validation failed after {attempt} attempts",
                    self.attempts,
                    self.trace.records,
                )
        raise RuntimeError("unreachable agent harness session state")

    def _record_failed_attempt(
        self,
        spec: HarnessSpec,
        attempt: int,
        diagnostics: str,
        exc: Exception,
    ) -> HarnessAttemptObservation:
        validations = [
            ValidationResult(
                name="build_passed",
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        ]
        score = score_build_attempt(
            compiled=False,
            source_path=spec.source_path,
            build_log_path=self._expected_build_log(spec),
            artifact_path=None,
            validations=validations,
        )
        observation = HarnessAttemptObservation(
            attempt=attempt,
            entry=spec.entry,
            engine=spec.engine,
            source_path=spec.source_path,
            dictionary_path=spec.dictionary_path,
            build_log_path=self._expected_build_log(spec),
            build_passed=False,
            diagnostics=diagnostics,
            validations=validations,
            score=score,
        )
        self.attempts.append(observation)
        return observation

    def _record_built_attempt(
        self,
        spec: HarnessSpec,
        artifact: BuildArtifact,
        attempt: int,
        diagnostics: str,
        validations: list[ValidationResult],
    ) -> HarnessAttemptObservation:
        score = score_build_attempt(
            compiled=True,
            source_path=spec.source_path,
            build_log_path=artifact.build_log_path,
            artifact_path=artifact.binary_path,
            validations=validations,
        )
        observation = HarnessAttemptObservation(
            attempt=attempt,
            entry=spec.entry,
            engine=spec.engine,
            source_path=spec.source_path,
            dictionary_path=spec.dictionary_path,
            build_log_path=artifact.build_log_path,
            build_passed=True,
            diagnostics=diagnostics,
            validations=validations,
            score=score,
        )
        self.attempts.append(observation)
        return observation

    def _record_trace(
        self,
        observation: HarnessAttemptObservation,
        *,
        agent_observation: AgentObservation,
        decision: HarnessDecision,
        artifact: BuildArtifact | None,
    ) -> None:
        score = observation_score_dict(agent_observation)
        trace_observation = agent_observation_to_dict(agent_observation)
        trace_observation.update({
            "attempt": observation.attempt,
            "entry": observation.entry,
            "engine": observation.engine,
            "source_path": observation.source_path,
            "dictionary_path": observation.dictionary_path,
            "build_log_path": observation.build_log_path,
        })
        self.trace.record(
            phase="harness_attempt",
            observation=trace_observation,
            decision={
                "action": decision.action,
                "reason": decision.reason,
                "payload": decision.payload,
                "max_attempts": self.max_attempts,
            },
            action={
                "tool_chain": ["generate_harness", "build_target"],
                "artifact_path": artifact.binary_path if artifact is not None else None,
            },
            result={
                "build_passed": observation.build_passed,
                "accepted": decision.action is HarnessAction.ACCEPT_HARNESS,
            },
            score=score,
        )

    @staticmethod
    def _expected_build_log(spec: HarnessSpec) -> Path:
        return spec.target.root / ".fuzz" / "build" / (
            f"build_{spec.entry}_attempt_{spec.attempt}.log"
        )

    @classmethod
    def _build_diagnostics(cls, spec: HarnessSpec, exc: Exception) -> str:
        log = cls._expected_build_log(spec)
        text = log.read_text(errors="replace")[-8000:] if log.exists() else ""
        return f"{type(exc).__name__}: {exc}\n\nBuild log tail:\n{text}"

    @staticmethod
    def _validation_diagnostics(validations: list[ValidationResult]) -> str:
        failed = [v for v in validations if not v.passed]
        if not failed:
            return "build and artifact validation passed"
        return "\n".join(f"{v.name}: {v.detail}" for v in failed)
