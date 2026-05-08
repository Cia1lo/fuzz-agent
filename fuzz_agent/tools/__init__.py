"""Tool Layer — the *only* surface the Orchestrator agent calls.

Design rules (harness engineering):
  - Coarse-grained:  one tool ≈ one meaningful step.
  - Side effects explicit: every mutating call returns an ID + summary, never raw blobs.
  - Failure readable: errors are short strings the LLM can act on.
  - Idempotent where possible: same inputs → same campaign_id / artifact hash.

Each function below is what the Agent SDK exposes as a callable tool.
Implementations live in sibling modules; this file is the public surface.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..state.models import (
    BuildArtifact,
    CampaignStats,
    CrashRecord,
    EngineKind,
    HarnessSpec,
    Sanitizer,
    TargetProfile,
)


# ---- analysis & harness ----

def analyze_target(path: str) -> TargetProfile:
    """Identify language, build system, and likely fuzz entry points."""
    from .analyze import analyze_target_impl
    return analyze_target_impl(Path(path))


def generate_harness(
    target: TargetProfile,
    entry: str,
    engine: EngineKind = EngineKind.LIBFUZZER,
    invariants: Optional[list[str]] = None,
) -> HarnessSpec:
    """LLM-assisted: produce a harness source file for one entry point."""
    from .harness import generate_harness_impl
    return generate_harness_impl(target, entry, engine, invariants or [])


def build_target(
    spec: HarnessSpec,
    sanitizers: Optional[list[Sanitizer]] = None,
) -> BuildArtifact:
    """Compile harness + target + sanitizers into a runnable binary."""
    from .build import build_target_impl
    return build_target_impl(spec, sanitizers)


# ---- campaign control ----

def start_fuzz_campaign(
    artifact: BuildArtifact,
    corpus_dir: str,
    time_budget_sec: int,
    dictionary_path: Optional[str] = None,
) -> str:
    """Launch a fuzz campaign. Returns campaign_id; runs in the background."""
    from .campaign import start_fuzz_campaign_impl
    return start_fuzz_campaign_impl(
        artifact, Path(corpus_dir), time_budget_sec,
        Path(dictionary_path) if dictionary_path else None,
    )


def query_status(campaign_id: str) -> CampaignStats:
    """Cheap snapshot — safe to call frequently from the orchestrator loop."""
    from .campaign import query_status_impl
    return query_status_impl(campaign_id)


def stop_campaign(campaign_id: str) -> None:
    from .campaign import stop_campaign_impl
    return stop_campaign_impl(campaign_id)


# ---- triage & strategy (delegate to subagents) ----

def triage_crashes(campaign_id: str, top_n: int = 10) -> list[CrashRecord]:
    """Delegate crash dedup / minimization / root-cause to crash-triage subagent."""
    from .triage import triage_crashes_impl
    return triage_crashes_impl(campaign_id, top_n)


def mutate_strategy(campaign_id: str, hint: str) -> dict:
    """Adjust dictionary / mutation weights / add seeds based on coverage analysis."""
    from .strategy import mutate_strategy_impl
    return mutate_strategy_impl(campaign_id, hint)
