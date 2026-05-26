"""triage_crashes — delegate to crash-triage subagent, persist results."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..agent_harness.observation import (
    AgentObservation,
    ValidationResult,
    agent_observation_to_dict,
)
from ..agent_harness.validators import validate_crash_not_from_harness
from ..state.models import CrashRecord, CrashStatus
from ..state.store import CampaignStore
from ..subagents import crash_triage, vulnerability_matcher
from ._runtime import runtime


def triage_crashes_impl(campaign_id: str, top_n: int) -> list[CrashRecord]:
    rt = runtime()
    paths = rt.store.paths(campaign_id)
    crashes = crash_triage(campaign_id, paths["crash_dir"], top_n)
    cfg = rt.store.campaign_config(campaign_id)
    if cfg is None:
        unmatched_out: list[CrashRecord] = []
        for c in crashes:
            updated = _with_vulnerability_matches(c, None, _default_log_path(c.input_path))
            rt.store.save_crash(updated)
            unmatched_out.append(updated)
        return unmatched_out

    eng = rt.engine(cfg.artifact.engine)
    out: list[CrashRecord] = []
    for crash in crashes:
        log_path = crash.input_path.with_suffix(crash.input_path.suffix + ".log")
        try:
            report = eng.reproduce(cfg.artifact, crash.input_path)
        except Exception as e:  # noqa: BLE001
            report = f"reproduce_failed: {e}"
            confirmed = None
            status = CrashStatus.FLAKY
        else:
            confirmed = report is not None
            status = CrashStatus.CONFIRMED if confirmed else CrashStatus.NON_REPRODUCIBLE

        if report and not log_path.exists():
            log_path.write_text(report, encoding="utf-8")
        updated = replace(
            crash,
            status=status,
            reproducible=confirmed,
            reproduce_log_path=log_path if log_path.exists() else None,
        )
        updated = _with_vulnerability_matches(updated, report, log_path)
        rt.store.save_crash(updated)
        _record_crash_reproduce_observation(
            rt.store,
            campaign_id,
            updated,
            report,
            cfg.artifact.harness_source_path,
        )
        out.append(updated)
    return out


def _default_log_path(input_path: Path) -> Path:
    return input_path.with_suffix(input_path.suffix + ".log")


def _with_vulnerability_matches(
    crash: CrashRecord,
    report: str | None,
    log_path: Path,
) -> CrashRecord:
    match_report = report
    if match_report is None and log_path.exists():
        match_report = log_path.read_text(errors="replace")
    matches = vulnerability_matcher(crash, match_report)
    return replace(crash, vulnerability_matches=matches)


def _record_crash_reproduce_observation(
    store: CampaignStore,
    campaign_id: str,
    crash: CrashRecord,
    report: str | None,
    harness_source_path: Path | None,
) -> None:
    repro_passed = crash.reproducible is True
    validations = [
        ValidationResult(
            name="crash_reproducible",
            passed=repro_passed,
            detail=crash.status.value,
        )
    ]
    harness_check = validate_crash_not_from_harness(crash, harness_source_path, report)
    validations.append(harness_check)
    observation = AgentObservation(
        kind="crash_reproduce" if repro_passed else "crash_reproduce_failure",
        summary=f"crash {crash.crash_id} reproduce status: {crash.status.value}",
        diagnostics=(report or "")[-4000:],
        artifacts={
            "crash_id": crash.crash_id,
            "input_path": crash.input_path,
            "reproduce_log_path": crash.reproduce_log_path,
            "harness_source_path": harness_source_path,
        },
        validations=validations,
        score={
            "compiled": None,
            "smoke_passed": None,
            "target_reached": None,
            "coverage_delta": None,
            "crash_reproducible": crash.reproducible,
            "harness_fault_detected": not harness_check.passed,
        },
        raw={
            "sanitizer_kind": crash.sanitizer_kind,
            "top_frames": crash.top_frames[:5],
            "vulnerability_matches": crash.vulnerability_matches,
        },
    )
    store.record_agent_trace(campaign_id, {
        "phase": "crash_reproduce",
        "observation": agent_observation_to_dict(observation),
        "decision": {
            "action": "record_crash",
            "reason": "persist reproducibility and harness ownership evidence",
        },
        "action": {"tool_chain": ["triage_crashes", "engine.reproduce"]},
        "result": {
            "crash_id": crash.crash_id,
            "status": crash.status,
            "reproducible": crash.reproducible,
        },
        "score": observation.score,
    })
