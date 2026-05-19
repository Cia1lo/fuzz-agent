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
from typing import Any, Optional

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
    attempt: int = 1,
    diagnostics: Optional[str] = None,
) -> HarnessSpec:
    """LLM-assisted: produce a harness source file for one entry point."""
    from .harness import generate_harness_impl
    return generate_harness_impl(
        target, entry, engine, invariants or [],
        attempt=attempt, diagnostics=diagnostics,
    )


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
    resumed_from: Optional[str] = None,
) -> str:
    """Launch a fuzz campaign. Returns campaign_id; runs in the background."""
    from .campaign import start_fuzz_campaign_impl
    return start_fuzz_campaign_impl(
        artifact, Path(corpus_dir), time_budget_sec,
        Path(dictionary_path) if dictionary_path else None,
        resumed_from=resumed_from,
    )


def query_status(campaign_id: str) -> CampaignStats:
    """Cheap snapshot — safe to call frequently from the orchestrator loop."""
    from .campaign import query_status_impl
    return query_status_impl(campaign_id)


def query_agent_trace(campaign_id: str) -> list[dict[str, Any]]:
    """Return the structured agent-harness trace for a campaign."""
    from . import _runtime
    return _runtime.runtime().store.list_agent_trace(campaign_id)


def read_run_log(campaign_id: str) -> str:
    """Return the persisted run log text for a campaign."""
    from .observe import read_run_log_impl
    return read_run_log_impl(campaign_id)


def read_build_log(campaign_id: str) -> str:
    """Return the persisted build log text for a campaign."""
    from .observe import read_build_log_impl
    return read_build_log_impl(campaign_id)


def read_coverage_summary(campaign_id: str) -> str:
    """Return the persisted coverage summary text for a campaign."""
    from .observe import read_coverage_summary_impl
    return read_coverage_summary_impl(campaign_id)


def read_agent_trace(campaign_id: str) -> list[dict[str, Any]]:
    """Alias for query_agent_trace; intended for read-only agent observations."""
    return query_agent_trace(campaign_id)


def classify_harness_fault(
    crash: CrashRecord,
    harness_source_path: Path | None,
    report: str | None = None,
) -> dict[str, Any]:
    """Return a structured harness-fault classification for a crash."""
    from .observe import classify_harness_fault_impl
    return classify_harness_fault_impl(crash, harness_source_path, report)


def stop_campaign(campaign_id: str) -> None:
    from .campaign import stop_campaign_impl
    return stop_campaign_impl(campaign_id)


def resume_campaign(campaign_id: str, time_budget_sec: Optional[int] = None) -> str:
    """Resume a persisted campaign as a new campaign seeded from its corpus."""
    from .campaign import resume_campaign_impl
    return resume_campaign_impl(campaign_id, time_budget_sec)


# ---- triage & strategy (delegate to subagents) ----

def triage_crashes(campaign_id: str, top_n: int = 10) -> list[CrashRecord]:
    """Delegate crash dedup / minimization / root-cause to crash-triage subagent."""
    from .triage import triage_crashes_impl
    return triage_crashes_impl(campaign_id, top_n)


def mutate_strategy(campaign_id: str, hint: str) -> dict[str, Any]:
    """Adjust dictionary / mutation weights / add seeds based on coverage analysis."""
    from .strategy import mutate_strategy_impl
    return mutate_strategy_impl(campaign_id, hint)
