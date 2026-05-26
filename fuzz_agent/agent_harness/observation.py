"""Structured observations produced by the agent harness loop."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..state.models import EngineKind

AGENT_OBSERVATION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ValidationResult:
    """One machine-checkable validation result for a harness attempt."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class AgentObservation:
    """Unified observation consumed by agent policies outside harness attempts."""

    kind: str
    summary: str
    diagnostics: str = ""
    artifacts: dict[str, Any] = field(default_factory=dict)
    validations: list[ValidationResult] = field(default_factory=list)
    score: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    schema_version: int = AGENT_OBSERVATION_SCHEMA_VERSION

    @property
    def all_validations_passed(self) -> bool:
        return all(v.passed for v in self.validations)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentObservation:
        version = data.get("schema_version", AGENT_OBSERVATION_SCHEMA_VERSION)
        if version != AGENT_OBSERVATION_SCHEMA_VERSION:
            raise ValueError(f"unsupported AgentObservation schema_version: {version}")
        validations_raw = data.get("validations", [])
        validations = [
            ValidationResult(
                name=str(item.get("name", "")),
                passed=bool(item.get("passed", False)),
                detail=str(item.get("detail", "")),
            )
            for item in validations_raw
            if isinstance(item, dict)
        ]
        artifacts = data.get("artifacts", {})
        score = data.get("score", {})
        raw = data.get("raw", {})
        return cls(
            kind=str(data.get("kind", "")),
            summary=str(data.get("summary", "")),
            diagnostics=str(data.get("diagnostics", "")),
            artifacts=artifacts if isinstance(artifacts, dict) else {},
            validations=validations,
            score=score if isinstance(score, dict) else {},
            raw=raw if isinstance(raw, dict) else {},
            schema_version=version,
        )


@dataclass(frozen=True)
class AgentStepScore:
    """Compact score for comparing harness attempts and agent decisions."""

    compiled: bool
    smoke_passed: bool | None
    target_reached: bool | None
    build_log_available: bool
    harness_source_available: bool
    artifact_available: bool
    coverage_delta: int | None = None
    crash_reproducible: bool | None = None
    harness_fault_detected: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HarnessAttemptObservation:
    """What the agent harness observed after one generate/build attempt."""

    attempt: int
    entry: str
    engine: EngineKind
    source_path: Path | None
    dictionary_path: Path | None
    build_log_path: Path | None
    build_passed: bool
    diagnostics: str
    validations: list[ValidationResult] = field(default_factory=list)
    score: AgentStepScore | None = None
    build_failure: dict[str, str] = field(default_factory=dict)

    @property
    def is_accepted(self) -> bool:
        return self.build_passed and all(v.passed for v in self.validations)

    def to_agent_observation(self, *, kind: str | None = None) -> AgentObservation:
        """Convert legacy harness-attempt feedback into the unified policy shape."""
        resolved_kind = kind or _harness_attempt_kind(self)
        return AgentObservation(
            kind=resolved_kind,
            summary=_harness_attempt_summary(self, resolved_kind),
            diagnostics=self.diagnostics,
            artifacts={
                "attempt": self.attempt,
                "entry": self.entry,
                "engine": self.engine,
                "source_path": self.source_path,
                "dictionary_path": self.dictionary_path,
                "build_log_path": self.build_log_path,
            },
            validations=list(self.validations),
            score=self.score.to_dict() if self.score is not None else {},
            raw={
                "build_passed": self.build_passed,
                "accepted": self.is_accepted,
                "build_failure": self.build_failure,
            },
        )


def agent_observation_to_dict(observation: AgentObservation) -> dict[str, Any]:
    """Return a JSON-friendly dict while preserving Path/Enum values for store serialization."""
    return {
        "schema_version": observation.schema_version,
        "kind": observation.kind,
        "summary": observation.summary,
        "diagnostics": observation.diagnostics,
        "artifacts": observation.artifacts,
        "validations": [
            {"name": v.name, "passed": v.passed, "detail": v.detail}
            for v in observation.validations
        ],
        "score": dict(observation.score),
        "raw": observation.raw,
    }


def observation_score_dict(observation: AgentObservation | HarnessAttemptObservation) -> dict[str, Any]:
    if isinstance(observation, HarnessAttemptObservation):
        return observation.score.to_dict() if observation.score is not None else {}
    return dict(observation.score)


def observation_is_accepted(observation: AgentObservation | HarnessAttemptObservation) -> bool:
    if isinstance(observation, HarnessAttemptObservation):
        return observation.is_accepted
    return bool(
        observation.kind == "harness_accepted"
        or (
            observation.score.get("compiled") is True
            and observation.all_validations_passed
            and observation.validations
        )
    )


def observation_source_path(
    observation: AgentObservation | HarnessAttemptObservation | None,
) -> Path | None:
    if observation is None:
        return None
    if isinstance(observation, HarnessAttemptObservation):
        return observation.source_path
    source = observation.artifacts.get("source_path")
    return source if isinstance(source, Path) else Path(source) if isinstance(source, str) else None


def _harness_attempt_kind(observation: HarnessAttemptObservation) -> str:
    if observation.is_accepted:
        return "harness_accepted"
    if not observation.build_passed:
        return "harness_build_failure"
    failed = {v.name for v in observation.validations if not v.passed}
    if "smoke_run" in failed:
        return "harness_smoke_failure"
    if "target_reached" in failed:
        return "harness_target_not_reached"
    if failed:
        return "harness_validation_failure"
    return "harness_attempt"


def _harness_attempt_summary(
    observation: HarnessAttemptObservation,
    kind: str,
) -> str:
    if kind == "harness_accepted":
        return f"harness attempt {observation.attempt} accepted"
    failed = [v for v in observation.validations if not v.passed]
    if failed:
        return f"{kind}: {failed[0].name}"
    return f"{kind}: attempt {observation.attempt}"
