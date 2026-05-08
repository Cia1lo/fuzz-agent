"""Subagent pool — context-isolated workers invoked via Claude Agent SDK.

Each subagent has a narrow, well-typed contract (input → structured summary).
The orchestrator never sees the raw context the subagent processes (large
crash logs, coverage maps, source dumps), only the JSON-serializable summary.

Contract for every subagent function:
    inputs:  small typed args (paths, IDs, hints).
    outputs: dataclass / dict with bounded size.
    side effects: writes are explicit and recorded in CampaignStore.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..state.models import CrashRecord, HarnessSpec, TargetProfile, EngineKind


# Each function below is a thin facade; the heavy lifting (LLM calls,
# context packing) lives in the corresponding module.

def harness_writer(target: TargetProfile, entry: str,
                   engine: EngineKind, invariants: list[str]) -> HarnessSpec:
    from .harness_writer import run as _run
    return _run(target, entry, engine, invariants)


def crash_triage(campaign_id: str, raw_crash_dir: Path,
                 top_n: int = 10) -> list[CrashRecord]:
    from .crash_triage import run as _run
    return _run(campaign_id, raw_crash_dir, top_n)


def corpus_curator(target: TargetProfile, out_dir: Path,
                   max_seeds: int = 200) -> list[Path]:
    from .corpus_curator import run as _run
    return _run(target, out_dir, max_seeds)


def coverage_analyst(campaign_id: str,
                     coverage_file: Path,
                     source_root: Path) -> dict:
    """Return: {"uncovered": [...], "suggested_seeds": [...], "dict_additions": [...]}"""
    from .coverage_analyst import run as _run
    return _run(campaign_id, coverage_file, source_root)


def exploit_assessor(crash: CrashRecord, source_root: Path) -> CrashRecord:
    """Augments crash with severity + exploitability_notes."""
    from .exploit_assessor import run as _run
    return _run(crash, source_root)
