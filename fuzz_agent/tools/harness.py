"""generate_harness — thin facade over the harness-writer subagent."""
from __future__ import annotations

from ..state.models import EngineKind, HarnessSpec, TargetProfile
from ..subagents import harness_writer


def generate_harness_impl(target: TargetProfile, entry: str,
                          engine: EngineKind, invariants: list[str]) -> HarnessSpec:
    return harness_writer(target, entry, engine, invariants)
