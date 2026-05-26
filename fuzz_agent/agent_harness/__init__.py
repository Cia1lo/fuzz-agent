"""Agent harness layer for generating, validating, and tracing fuzz harnesses."""
from __future__ import annotations

from .observation import (
    AgentObservation,
    AgentStepScore,
    HarnessAttemptObservation,
    ValidationResult,
    agent_observation_to_dict,
    observation_is_accepted,
    observation_score_dict,
)
from .policy import CoverageStrategyPolicy, HarnessAction, HarnessDecision, HarnessPolicy, LLMHarnessPolicy
from .session import AgentHarnessResult, AgentHarnessSession, HarnessBuildError
from .trace import AgentTraceRecord, AgentTraceRecorder

__all__ = [
    "AgentHarnessResult",
    "AgentHarnessSession",
    "AgentObservation",
    "AgentStepScore",
    "AgentTraceRecord",
    "AgentTraceRecorder",
    "agent_observation_to_dict",
    "CoverageStrategyPolicy",
    "HarnessAction",
    "HarnessAttemptObservation",
    "HarnessBuildError",
    "HarnessDecision",
    "HarnessPolicy",
    "LLMHarnessPolicy",
    "observation_is_accepted",
    "observation_score_dict",
    "ValidationResult",
]
