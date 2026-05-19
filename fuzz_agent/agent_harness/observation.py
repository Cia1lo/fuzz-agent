"""Structured observations produced by the agent harness loop."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..state.models import EngineKind


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

    @property
    def is_accepted(self) -> bool:
        return self.build_passed and all(v.passed for v in self.validations)
