"""Subagent pool — context-isolated workers invoked via an LLM client.

Each subagent has a narrow, well-typed contract (input → structured summary).
The orchestrator never sees the raw context the subagent processes (large
crash logs, coverage maps, source dumps), only the JSON-serializable summary.

Contract for every subagent function:
    inputs:  small typed args (paths, IDs, hints).
    outputs: dataclass / dict with bounded size.
    side effects: writes are explicit and recorded in CampaignStore.
"""
from __future__ import annotations

from .corpus_curator import run as corpus_curator
from .coverage_analyst import run as coverage_analyst
from .crash_triage import run as crash_triage
from .exploit_assessor import run as exploit_assessor
from .harness_writer import run as harness_writer
from .vulnerability_matcher import run as vulnerability_matcher

__all__ = [
    "corpus_curator",
    "coverage_analyst",
    "crash_triage",
    "exploit_assessor",
    "harness_writer",
    "vulnerability_matcher",
]
