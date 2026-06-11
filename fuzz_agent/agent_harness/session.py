"""Outer agent harness loop for generating and validating fuzz harnesses."""
from __future__ import annotations

import base64
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
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
    classify_build_failure,
    score_build_attempt,
    validate_build_artifact,
    validate_target_referenced_by_harness,
)

GenerateHarness = Callable[[int, str | None], HarnessSpec]
GenerateHarnessForEntry = Callable[[str, int, str | None], HarnessSpec]
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
        generate_harness_for_entry: GenerateHarnessForEntry | None = None,
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
        self.generate_harness_for_entry = generate_harness_for_entry
        self.build = build
        self.smoke_run = smoke_run
        self.target_reached = target_reached
        self.policy = policy or HarnessPolicy()
        self.max_attempts = max_attempts
        self.trace = trace or AgentTraceRecorder()
        self.attempts: list[HarnessAttemptObservation] = []

    async def run(self, initial_spec: HarnessSpec | None = None) -> AgentHarnessResult:
        diagnostics: str | None = None
        next_spec = initial_spec
        for attempt in range(1, self.max_attempts + 1):
            spec = (
                next_spec
                if next_spec is not None
                else self.generate_harness(attempt, diagnostics)
            )
            next_spec = None
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
                diagnostics = self._attempt_memory_diagnostics(diagnostics)
                next_spec, action_result = self._apply_decision_action(
                    decision,
                    spec,
                    attempt=attempt,
                    diagnostics=diagnostics,
                )
                self._record_trace(
                    observation,
                    agent_observation=agent_observation,
                    decision=decision,
                    artifact=None,
                    action_result=action_result,
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
            diagnostics = self._attempt_memory_diagnostics(diagnostics)
            next_spec, action_result = self._apply_decision_action(
                decision,
                spec,
                attempt=attempt,
                diagnostics=diagnostics,
            )
            self._record_trace(
                observation,
                agent_observation=agent_observation,
                decision=decision,
                artifact=artifact,
                action_result=action_result,
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
            build_failure=classify_build_failure(diagnostics),
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
        action_result: dict[str, object],
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
                "tool_chain": _tool_chain_for_decision(decision.action),
                "artifact_path": artifact.binary_path if artifact is not None else None,
                **action_result,
            },
            result={
                "build_passed": observation.build_passed,
                "accepted": decision.action is HarnessAction.ACCEPT_HARNESS,
            },
            score=score,
        )

    def _apply_decision_action(
        self,
        decision: HarnessDecision,
        spec: HarnessSpec,
        *,
        attempt: int,
        diagnostics: str,
    ) -> tuple[HarnessSpec | None, dict[str, object]]:
        if decision.action in {
            HarnessAction.ACCEPT_HARNESS,
            HarnessAction.STOP_FAILED,
            HarnessAction.REGENERATE_HARNESS,
        }:
            return None, {"applied": False}
        try:
            if decision.action is HarnessAction.PATCH_HARNESS:
                patched = self._apply_patch_harness_action(spec, decision.payload, attempt + 1)
                return patched, {
                    "applied": True,
                    "next_source_path": patched.source_path,
                    "action_type": decision.action.value,
                }
            if decision.action is HarnessAction.ADD_DICTIONARY:
                updated = self._apply_add_dictionary_action(spec, decision.payload, attempt + 1)
                return updated, {
                    "applied": True,
                    "dictionary_path": updated.dictionary_path,
                    "action_type": decision.action.value,
                }
            if decision.action is HarnessAction.ADD_SEED:
                seed_path = self._apply_add_seed_action(spec, decision.payload)
                updated = self._copy_spec_for_attempt(spec, attempt + 1)
                return updated, {
                    "applied": True,
                    "seed_path": seed_path,
                    "next_source_path": updated.source_path,
                    "action_type": decision.action.value,
                }
            if decision.action is HarnessAction.CHANGE_ENTRY_POINT:
                changed = self._apply_change_entry_point_action(
                    decision.payload,
                    attempt + 1,
                    diagnostics,
                )
                return changed, {
                    "applied": True,
                    "entry": changed.entry,
                    "next_source_path": changed.source_path,
                    "action_type": decision.action.value,
                }
        except Exception as exc:  # noqa: BLE001
            return None, {
                "applied": False,
                "action_type": decision.action.value,
                "error": f"{type(exc).__name__}: {exc}",
            }
        return None, {"applied": False, "action_type": decision.action.value}

    def _apply_patch_harness_action(
        self,
        spec: HarnessSpec,
        payload: dict[str, object],
        next_attempt: int,
    ) -> HarnessSpec:
        path = payload.get("path")
        if not isinstance(path, str) or Path(path).resolve() != spec.source_path.resolve():
            raise ValueError("patch_harness path must match current harness source")
        source_value = payload.get("source")
        if isinstance(source_value, str):
            patched_source = source_value
        else:
            patch_value = payload.get("patch")
            if not isinstance(patch_value, str) or not patch_value:
                raise ValueError("patch_harness requires non-empty source or patch")
            original = spec.source_path.read_text(encoding="utf-8", errors="replace")
            patched_source = _apply_source_patch(original, patch_value)
        next_spec = self._copy_spec_for_attempt(spec, next_attempt, source=patched_source)
        return next_spec

    def _apply_add_dictionary_action(
        self,
        spec: HarnessSpec,
        payload: dict[str, object],
        next_attempt: int,
    ) -> HarnessSpec:
        tokens = payload.get("tokens", [])
        if not isinstance(tokens, list):
            raise ValueError("add_dictionary tokens must be a list")
        next_spec = self._copy_spec_for_attempt(spec, next_attempt)
        dict_path = next_spec.dictionary_path or next_spec.source_path.with_suffix(".dict")
        existing: set[str] = set()
        if dict_path.exists():
            for line in dict_path.read_text(encoding="utf-8").splitlines():
                token = line.strip().strip('"')
                if token:
                    existing.add(token)
        dict_path.parent.mkdir(parents=True, exist_ok=True)
        with dict_path.open("a", encoding="utf-8") as f:
            for item in tokens:
                token = str(item).strip().strip('"')
                if not token or token in existing:
                    continue
                existing.add(token)
                f.write(f'"{token}"\n')
        return replace(next_spec, dictionary_path=dict_path)

    def _apply_add_seed_action(
        self,
        spec: HarnessSpec,
        payload: dict[str, object],
    ) -> Path:
        name = payload.get("name")
        bytes_b64 = payload.get("bytes_b64")
        if not isinstance(name, str) or not name:
            raise ValueError("add_seed requires seed name")
        if not isinstance(bytes_b64, str) or not bytes_b64:
            raise ValueError("add_seed requires bytes_b64")
        seed_dir = spec.target.root / ".fuzz" / "corpus"
        seed_dir.mkdir(parents=True, exist_ok=True)
        seed_path = seed_dir / _safe_file_name(name)
        seed_path.write_bytes(base64.b64decode(bytes_b64))
        return seed_path

    def _apply_change_entry_point_action(
        self,
        payload: dict[str, object],
        next_attempt: int,
        diagnostics: str,
    ) -> HarnessSpec:
        entry = payload.get("entry")
        if not isinstance(entry, str) or not entry:
            raise ValueError("change_entry_point requires entry")
        if entry not in self.target.entry_points:
            raise ValueError(f"entry not in target profile: {entry}")
        if self.generate_harness_for_entry is None:
            raise ValueError("generate_harness_for_entry callback is not configured")
        self.entry = entry
        return self.generate_harness_for_entry(entry, next_attempt, diagnostics)

    def _copy_spec_for_attempt(
        self,
        spec: HarnessSpec,
        next_attempt: int,
        *,
        source: str | None = None,
    ) -> HarnessSpec:
        next_source_path = _attempt_path(spec.source_path, next_attempt)
        next_source_path.parent.mkdir(parents=True, exist_ok=True)
        if source is None:
            source = spec.source_path.read_text(encoding="utf-8", errors="replace")
        next_source_path.write_text(source, encoding="utf-8")
        return replace(spec, source_path=next_source_path, attempt=next_attempt)

    @staticmethod
    def _expected_build_log(spec: HarnessSpec) -> Path:
        return spec.target.root / ".fuzz" / "build" / (
            f"build_{spec.entry}_attempt_{spec.attempt}.log"
        )

    @classmethod
    def _build_diagnostics(cls, spec: HarnessSpec, exc: Exception) -> str:
        log = cls._expected_build_log(spec)
        text = _build_log_tail(log)
        return f"{type(exc).__name__}: {exc}\n\nBuild log tail:\n{text}"

    @staticmethod
    def _validation_diagnostics(validations: list[ValidationResult]) -> str:
        failed = [v for v in validations if not v.passed]
        if not failed:
            return "build and artifact validation passed"
        return "\n".join(f"{v.name}: {v.detail}" for v in failed)

    def _attempt_memory_diagnostics(self, latest_diagnostics: str) -> str:
        if not self.attempts:
            return latest_diagnostics
        lines = ["Recent harness attempt memory:"]
        for observation in self.attempts[-3:]:
            status = "build_passed" if observation.build_passed else "build_failed"
            failed = [v for v in observation.validations if not v.passed]
            failed_text = ", ".join(f"{v.name}: {v.detail}" for v in failed) or "none"
            lines.extend([
                f"- attempt {observation.attempt}: {status}",
                f"  entry: {observation.entry}",
                f"  failed_validations: {_shorten(failed_text, 500)}",
            ])
            if observation.build_failure:
                lines.append(f"  build_failure: {observation.build_failure}")
            if observation.diagnostics:
                lines.append(f"  diagnostics_tail: {_shorten(observation.diagnostics, 1200)}")
        if latest_diagnostics:
            lines.extend(["", "Latest full diagnostics:", latest_diagnostics])
        return "\n".join(lines)


def _tool_chain_for_decision(action: HarnessAction) -> list[str]:
    if action is HarnessAction.PATCH_HARNESS:
        return ["patch_harness", "build_target"]
    if action is HarnessAction.ADD_DICTIONARY:
        return ["add_dictionary", "build_target"]
    if action is HarnessAction.ADD_SEED:
        return ["add_seed", "build_target"]
    if action is HarnessAction.CHANGE_ENTRY_POINT:
        return ["change_entry_point", "generate_harness", "build_target"]
    return ["generate_harness", "build_target"]


def _safe_file_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return cleaned or "seed"


def _attempt_path(path: Path, attempt: int) -> Path:
    match = re.match(r"attempt_\d+(\.[^.]+)$", path.name)
    if match:
        return path.with_name(f"attempt_{attempt}{match.group(1)}")
    return path.with_name(f"{path.stem}_attempt_{attempt}{path.suffix}")


def _apply_source_patch(original: str, patch: str) -> str:
    if not patch.lstrip().startswith(("---", "@@")):
        return patch
    return _apply_unified_diff(original, patch)


def _apply_unified_diff(original: str, patch: str) -> str:
    original_lines = original.splitlines(keepends=True)
    patch_lines = patch.splitlines(keepends=True)
    out: list[str] = []
    original_index = 0
    index = 0
    saw_hunk = False
    hunk_re = re.compile(r"@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@")
    while index < len(patch_lines):
        line = patch_lines[index]
        if line.startswith(("--- ", "+++ ")):
            index += 1
            continue
        match = hunk_re.match(line)
        if match is None:
            index += 1
            continue
        saw_hunk = True
        old_start = int(match.group("old_start")) - 1
        if old_start < original_index:
            raise ValueError("overlapping patch hunks")
        out.extend(original_lines[original_index:old_start])
        original_index = old_start
        index += 1
        while index < len(patch_lines) and not patch_lines[index].startswith("@@ "):
            hunk_line = patch_lines[index]
            prefix = hunk_line[:1]
            body = hunk_line[1:]
            if prefix == " ":
                if original_index >= len(original_lines):
                    raise ValueError("patch context exceeds original source")
                out.append(original_lines[original_index])
                original_index += 1
            elif prefix == "-":
                if original_index >= len(original_lines):
                    raise ValueError("patch removal exceeds original source")
                original_index += 1
            elif prefix == "+":
                out.append(body)
            elif prefix == "\\":
                pass
            else:
                break
            index += 1
    if not saw_hunk:
        raise ValueError("patch_harness unified diff did not contain a hunk")
    out.extend(original_lines[original_index:])
    return "".join(out)


def _build_log_tail(path: Path) -> str:
    return path.read_text(errors="replace")[-8000:] if path.exists() else ""


def _shorten(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1] + "..."
