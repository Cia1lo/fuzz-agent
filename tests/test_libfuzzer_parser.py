import asyncio
import sys
from datetime import datetime, timezone

from fuzz_agent.engines.libfuzzer import LibFuzzerEngine
from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    EngineKind,
    EventKind,
)


def _engine_with_campaign(cid: str = "cid") -> LibFuzzerEngine:
    engine = LibFuzzerEngine()
    engine._start_ts[cid] = datetime.now(timezone.utc)
    return engine


def test_parse_new_status_line_returns_coverage_event_and_updates_stats():
    engine = _engine_with_campaign()
    line = "#1234 NEW    cov: 567 ft: 890 corp: 12/345b lim: 4096 exec/s: 2400 rss: 50Mb"

    event = engine._parse_line("cid", line)
    stats = engine.stats("cid")

    assert event is not None
    assert event.kind is EventKind.NEW_COVERAGE
    assert event.payload["edges"] == 567
    assert stats.execs_total == 1234
    assert stats.edges_covered == 567
    assert stats.corpus_size == 12


def test_parse_status_line_with_no_coverage_increase_returns_none():
    engine = _engine_with_campaign()
    engine._parse_line("cid", "#1 NEW cov: 567 ft: 890 corp: 12/345b")

    event = engine._parse_line("cid", "#2 NEW cov: 567 ft: 891 corp: 13/346b")

    assert event is None


def test_parse_asan_crash_header_returns_crash_event():
    engine = _engine_with_campaign()
    line = "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."

    event = engine._parse_line("cid", line)

    assert event is not None
    assert event.kind is EventKind.NEW_CRASH
    assert event.payload["sanitizer"] == "AddressSanitizer"
    assert event.payload["kind"] == "heap-buffer-overflow"


def test_parse_libfuzzer_oom_returns_oom_event():
    engine = _engine_with_campaign()

    event = engine._parse_line("cid", "==12345==ERROR: libFuzzer: out-of-memory")

    assert event is not None
    assert event.kind is EventKind.OOM


def test_parse_unrelated_line_returns_none():
    engine = _engine_with_campaign()

    assert engine._parse_line("cid", "random unrelated line") is None


def test_run_uses_campaign_config_id_for_events(tmp_path):
    script = tmp_path / "fuzz"
    script.write_text(
        f"#!{sys.executable}\n"
        "print('#1 NEW cov: 7 ft: 9 corp: 1/1b', flush=True)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=script,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=5,
        campaign_id="store-cid",
    )

    async def scenario():
        engine = LibFuzzerEngine()
        events = [event async for event in engine.run(cfg)]
        return events

    events = asyncio.run(scenario())

    assert events
    assert events[0].campaign_id == "store-cid"


def test_run_emits_heartbeat_when_output_is_idle(tmp_path, monkeypatch):
    script = tmp_path / "fuzz"
    script.write_text(
        f"#!{sys.executable}\n"
        "import time\n"
        "time.sleep(0.12)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=script,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=5,
        campaign_id="store-cid",
    )
    monkeypatch.setattr("fuzz_agent.engines.libfuzzer._HEARTBEAT_INTERVAL_SEC", 0.02)

    async def scenario():
        engine = LibFuzzerEngine()
        events = [event async for event in engine.run(cfg)]
        return events

    events = asyncio.run(scenario())

    heartbeats = [event for event in events if event.kind is EventKind.HEARTBEAT]
    assert heartbeats
    assert heartbeats[0].campaign_id == "store-cid"


def test_run_writes_log_and_emits_error_tail_on_failure(tmp_path):
    script = tmp_path / "fuzz"
    script.write_text(
        f"#!{sys.executable}\n"
        "print('before failure', flush=True)\n"
        "raise SystemExit(3)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=script,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "campaign" / "crashes",
        dictionary_path=None,
        time_budget_sec=5,
        campaign_id="store-cid",
    )

    async def scenario():
        engine = LibFuzzerEngine()
        return [event async for event in engine.run(cfg)]

    events = asyncio.run(scenario())
    run_log = cfg.crash_dir.parent / "run.log"

    assert "before failure" in run_log.read_text(encoding="utf-8")
    errors = [event for event in events if event.kind is EventKind.ENGINE_ERROR]
    assert errors
    assert "before failure" in errors[0].payload["tail"]
