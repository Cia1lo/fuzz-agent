from datetime import datetime, timezone

from fuzz_agent.engines.libfuzzer import LibFuzzerEngine
from fuzz_agent.state.models import EventKind


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
