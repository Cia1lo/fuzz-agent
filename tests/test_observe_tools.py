from __future__ import annotations

from datetime import datetime, timezone

from fuzz_agent.state.models import BuildArtifact, CampaignConfig, CrashRecord, EngineKind
from fuzz_agent.tools import (
    _runtime,
    classify_harness_fault,
    read_agent_trace,
    read_build_log,
    read_coverage_summary,
    read_run_log,
)
from fuzz_agent.tools._runtime import Runtime


def test_read_only_observation_tools(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    build_log = tmp_path / "build.log"
    build_log.write_text("build", encoding="utf-8")
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=build_log,
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    paths["run_log"].write_text("run", encoding="utf-8")
    paths["coverage_summary"].write_text("coverage", encoding="utf-8")
    rt.store.record_agent_trace(cid, {"phase": "harness_attempt"})

    assert read_run_log(cid) == "run"
    assert read_build_log(cid) == "build"
    assert read_coverage_summary(cid) == "coverage"
    assert read_agent_trace(cid) == [{"phase": "harness_attempt"}]


def test_classify_harness_fault_tool(tmp_path):
    harness = tmp_path / "attempt_1.cc"
    crash = CrashRecord(
        crash_id="c",
        campaign_id="cid",
        input_path=tmp_path / "crash",
        minimized_path=None,
        stack_hash="s",
        top_frames=["LLVMFuzzerTestOneInput"],
        sanitizer_kind="trap",
        discovered_at=datetime.now(timezone.utc),
    )

    result = classify_harness_fault(crash, harness, "trap in LLVMFuzzerTestOneInput")

    assert result["harness_fault_detected"] is True
