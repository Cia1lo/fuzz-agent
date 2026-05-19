"""triage_crashes — delegate to crash-triage subagent, persist results."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..state.models import CrashRecord, CrashStatus
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
