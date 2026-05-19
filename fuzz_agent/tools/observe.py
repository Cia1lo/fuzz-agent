"""Read-only observation helpers for agent harness policy inputs."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent_harness.validators import validate_crash_not_from_harness
from ..state.models import CrashRecord
from ._runtime import runtime


def read_run_log_impl(campaign_id: str) -> str:
    return _read_text(runtime().store.paths(campaign_id)["run_log"])


def read_build_log_impl(campaign_id: str) -> str:
    cfg = runtime().store.campaign_config(campaign_id)
    if cfg is None:
        raise KeyError(f"unknown campaign: {campaign_id}")
    return _read_text(cfg.artifact.build_log_path)


def read_coverage_summary_impl(campaign_id: str) -> str:
    return _read_text(runtime().store.paths(campaign_id)["coverage_summary"])


def classify_harness_fault_impl(
    crash: CrashRecord,
    harness_source_path: Path | None,
    report: str | None = None,
) -> dict[str, Any]:
    result = validate_crash_not_from_harness(crash, harness_source_path, report)
    return {
        "name": result.name,
        "harness_fault_detected": not result.passed,
        "detail": result.detail,
    }


def _read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(str(path))
    return path.read_text(errors="replace")
