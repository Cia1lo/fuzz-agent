from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from fuzz_agent.state.models import CampaignStatus, CrashRecord, EngineKind, EventKind, Language, Severity


def test_crash_record_asdict_roundtrip_preserves_types():
    crash = CrashRecord(
        crash_id="crash-a",
        campaign_id="cid-a",
        input_path=Path("/tmp/input"),
        minimized_path=Path("/tmp/min"),
        stack_hash="abc123",
        top_frames=["parse_thing", "LLVMFuzzerTestOneInput"],
        sanitizer_kind="heap-buffer-overflow",
        discovered_at=datetime(2026, 1, 2, 3, 4, 5),
        severity=Severity.HIGH,
        exploitability_notes="reachable",
    )

    rebuilt = CrashRecord(**asdict(crash))

    assert rebuilt == crash
    assert isinstance(rebuilt.input_path, Path)
    assert isinstance(rebuilt.discovered_at, datetime)
    assert rebuilt.severity is Severity.HIGH


def test_enum_string_values_are_stable():
    assert CampaignStatus.RUNNING.value == "running"
    assert CampaignStatus.PENDING.value == "pending"
    assert EventKind.NEW_COVERAGE.value == "new_coverage"
    assert EventKind.NEW_CRASH.value == "new_crash"
    assert EventKind.PLATEAU.value == "plateau"
    assert EngineKind.CARGO_FUZZ.value == "cargo-fuzz"
    assert Language.RUST.value == "rust"
    assert Severity.CRITICAL.value == "critical"
