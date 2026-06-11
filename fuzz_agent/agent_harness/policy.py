"""Decision policy for the outer agent harness loop."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .observation import (
    AgentObservation,
    HarnessAttemptObservation,
    agent_observation_to_dict,
    observation_is_accepted,
    observation_score_dict,
    observation_source_path,
)

_TERMINAL_BUILD_FAILURE_KINDS = {
    "missing_fuzzer_runtime",
    "unsupported_fuzzer_sanitizer",
    "missing_target_source",
}


class HarnessAction(str, Enum):
    ACCEPT_HARNESS = "accept_harness"
    REGENERATE_HARNESS = "regenerate_harness"
    PATCH_HARNESS = "patch_harness"
    ADD_SEED = "add_seed"
    ADD_DICTIONARY = "add_dictionary"
    CHANGE_ENTRY_POINT = "change_entry_point"
    STOP_FAILED = "stop_failed"


@dataclass(frozen=True)
class HarnessDecision:
    action: HarnessAction
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)


class HarnessPolicy:
    """Default deterministic policy; LLM-backed policies can implement this shape."""

    def decide(
        self,
        observation: AgentObservation | HarnessAttemptObservation,
        *,
        attempt: int,
        max_attempts: int,
    ) -> HarnessDecision:
        if observation_is_accepted(observation):
            return HarnessDecision(
                action=HarnessAction.ACCEPT_HARNESS,
                reason="all validations passed",
            )
        terminal = _terminal_build_failure_decision(observation)
        if terminal is not None:
            return terminal
        if attempt >= max_attempts:
            return HarnessDecision(
                action=HarnessAction.STOP_FAILED,
                reason="attempt budget exhausted",
            )
        return HarnessDecision(
            action=HarnessAction.REGENERATE_HARNESS,
            reason="validation or build feedback requires another harness attempt",
        )


class CoverageStrategyPolicy:
    """Default policy for coverage plateau observations."""

    def decide(self, observation: AgentObservation) -> HarnessDecision:
        if observation.kind != "coverage_plateau":
            return HarnessDecision(
                action=HarnessAction.STOP_FAILED,
                reason=f"unsupported coverage policy observation: {observation.kind}",
            )
        return HarnessDecision(
            action=HarnessAction.ADD_DICTIONARY,
            reason="coverage plateau should try coverage-guided seed and dictionary mutation",
            payload={"hint": observation.summary},
        )


class LLMHarnessPolicy(HarnessPolicy):
    """LLM-backed policy that still returns only validated structured decisions."""

    _SYSTEM = """You choose the next action for a fuzz harness engineering loop.
Return strict JSON only:
{"action": "...", "reason": "...", "payload": {...}}
Allowed actions:
- accept_harness
- regenerate_harness
- patch_harness
- add_seed
- add_dictionary
- change_entry_point
- stop_failed
Do not include prose or markdown."""

    def decide(
        self,
        observation: AgentObservation | HarnessAttemptObservation,
        *,
        attempt: int,
        max_attempts: int,
    ) -> HarnessDecision:
        if observation_is_accepted(observation):
            return HarnessDecision(
                action=HarnessAction.ACCEPT_HARNESS,
                reason="all validations passed",
            )
        terminal = _terminal_build_failure_decision(observation)
        if terminal is not None:
            return terminal
        if attempt >= max_attempts:
            return HarnessDecision(
                action=HarnessAction.STOP_FAILED,
                reason="attempt budget exhausted",
            )
        try:
            from ..subagents._llm import call_llm_json

            raw = call_llm_json(
                self._SYSTEM,
                _observation_prompt(observation, attempt, max_attempts),
                max_tokens=512,
            )
            return _parse_llm_decision(raw, observation)
        except Exception as exc:  # noqa: BLE001
            return HarnessDecision(
                action=HarnessAction.REGENERATE_HARNESS,
                reason=f"llm_policy_failed: {type(exc).__name__}: {exc}",
                payload={"fallback": True},
            )


def _parse_llm_decision(
    raw: Any,
    observation: AgentObservation | HarnessAttemptObservation | None = None,
) -> HarnessDecision:
    if not isinstance(raw, dict):
        raise ValueError("policy output must be an object")
    action_raw = raw.get("action")
    if not isinstance(action_raw, str):
        raise ValueError("policy output action must be a string")
    try:
        action = HarnessAction(action_raw)
    except ValueError as exc:
        raise ValueError(f"unknown harness action: {action_raw}") from exc
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("policy output reason must be a non-empty string")
    payload = raw.get("payload", {})
    if not isinstance(payload, dict):
        raise ValueError("policy output payload must be an object")
    payload = _validate_payload(action, payload, observation)
    return HarnessDecision(action=action, reason=reason, payload=payload)


def _validate_payload(
    action: HarnessAction,
    payload: dict[str, Any],
    observation: AgentObservation | HarnessAttemptObservation | None,
) -> dict[str, Any]:
    if action is HarnessAction.PATCH_HARNESS:
        path = payload.get("path")
        patch = payload.get("patch")
        source = payload.get("source")
        if not isinstance(path, str) or not path:
            raise ValueError("patch_harness payload requires string path")
        if patch is None and source is None:
            raise ValueError("patch_harness payload requires patch or source")
        if patch is not None and not isinstance(patch, str):
            raise ValueError("patch_harness payload patch must be a string")
        if source is not None and not isinstance(source, str):
            raise ValueError("patch_harness payload source must be a string")
        source_path = observation_source_path(observation)
        if source_path is not None:
            requested = Path(path).expanduser()
            allowed = source_path.resolve()
            if requested.resolve() != allowed:
                raise ValueError("patch_harness path must be the current harness source")
    elif action is HarnessAction.ADD_SEED:
        name = payload.get("name")
        bytes_b64 = payload.get("bytes_b64")
        if not isinstance(name, str) or not name or "/" in name:
            raise ValueError("add_seed payload requires safe string name")
        if not isinstance(bytes_b64, str) or not bytes_b64:
            raise ValueError("add_seed payload requires bytes_b64")
    elif action is HarnessAction.ADD_DICTIONARY:
        tokens = payload.get("tokens", [])
        if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
            raise ValueError("add_dictionary payload tokens must be a string list")
    elif action is HarnessAction.CHANGE_ENTRY_POINT:
        entry = payload.get("entry")
        if not isinstance(entry, str) or not entry:
            raise ValueError("change_entry_point payload requires entry")
    elif action in {
        HarnessAction.ACCEPT_HARNESS,
        HarnessAction.REGENERATE_HARNESS,
        HarnessAction.STOP_FAILED,
    }:
        if payload and not isinstance(payload, dict):
            raise ValueError("payload must be an object")
    return payload


def _terminal_build_failure_decision(
    observation: AgentObservation | HarnessAttemptObservation,
) -> HarnessDecision | None:
    build_failure = _build_failure_dict(observation)
    kind = build_failure.get("kind")
    if kind not in _TERMINAL_BUILD_FAILURE_KINDS:
        return None
    hint = build_failure.get("hint") or "fix the build environment before retrying"
    return HarnessDecision(
        action=HarnessAction.STOP_FAILED,
        reason=f"non-retryable build failure: {kind}; {hint}",
        payload={"build_failure": build_failure},
    )


def _build_failure_dict(
    observation: AgentObservation | HarnessAttemptObservation,
) -> dict[str, str]:
    if isinstance(observation, HarnessAttemptObservation):
        return observation.build_failure
    raw = observation.raw.get("build_failure") if isinstance(observation.raw, dict) else None
    return raw if isinstance(raw, dict) else {}


def _observation_prompt(
    observation: AgentObservation | HarnessAttemptObservation,
    attempt: int,
    max_attempts: int,
) -> str:
    if isinstance(observation, HarnessAttemptObservation):
        unified = observation.to_agent_observation()
    else:
        unified = observation
    obs = agent_observation_to_dict(unified)
    validations = obs["validations"]
    score = observation_score_dict(unified)
    artifacts = obs["artifacts"]
    return (
        f"Attempt: {attempt}/{max_attempts}\n"
        f"Observation kind: {unified.kind}\n"
        f"Summary: {unified.summary}\n"
        f"Entry: {artifacts.get('entry', '')}\n"
        f"Engine: {artifacts.get('engine', '')}\n"
        f"Diagnostics:\n{unified.diagnostics[-4000:]}\n\n"
        f"Validations: {validations}\n"
        f"Score: {score}\n"
        "Choose the next action."
    )
