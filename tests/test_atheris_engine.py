import asyncio
import sys

from fuzz_agent.engines import atheris as atheris_module
from fuzz_agent.engines.atheris import AtherisEngine
from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    EngineKind,
    EventKind,
)


def _artifact(path):
    return BuildArtifact(
        binary_path=path,
        engine=EngineKind.ATHERIS,
        sanitizers=[],
        build_log_path=path.with_suffix(".build.log"),
        harness_source_path=path,
    )


def _cfg(tmp_path, harness, *, campaign_id="store-cid"):
    return CampaignConfig(
        artifact=_artifact(harness),
        corpus_dir=tmp_path / "campaign" / "corpus",
        crash_dir=tmp_path / "campaign" / "crashes",
        dictionary_path=None,
        time_budget_sec=5,
        campaign_id=campaign_id,
    )


def test_atheris_run_uses_campaign_id_and_writes_run_log(tmp_path):
    harness = tmp_path / "harness.py"
    harness.write_text(
        "print('#1 NEW cov: 11 ft: 2 corp: 1/1b', flush=True)\n",
        encoding="utf-8",
    )
    cfg = _cfg(tmp_path, harness)

    async def scenario():
        return [event async for event in AtherisEngine().run(cfg)]

    events = asyncio.run(scenario())

    assert events
    assert events[0].campaign_id == "store-cid"
    assert events[0].kind is EventKind.NEW_COVERAGE
    run_log = cfg.crash_dir.parent / "run.log"
    assert str(harness) in run_log.read_text(encoding="utf-8")
    assert f"{sys.executable}" in run_log.read_text(encoding="utf-8")


def test_atheris_run_emits_heartbeat_when_output_is_idle(tmp_path, monkeypatch):
    monkeypatch.setattr(atheris_module, "_HEARTBEAT_INTERVAL_SEC", 0.01)
    harness = tmp_path / "idle_harness.py"
    harness.write_text("import time\ntime.sleep(0.04)\n", encoding="utf-8")
    cfg = _cfg(tmp_path, harness)

    async def scenario():
        return [event async for event in AtherisEngine().run(cfg)]

    events = asyncio.run(scenario())

    heartbeats = [event for event in events if event.kind is EventKind.HEARTBEAT]
    assert heartbeats
    assert all(event.campaign_id == "store-cid" for event in heartbeats)
