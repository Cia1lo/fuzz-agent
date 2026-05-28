import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStatus,
    EngineKind,
    EventKind,
    Sanitizer,
    Severity,
    CrashRecord,
    VulnerabilityMatch,
)
from fuzz_agent.state.store import CampaignStore


def _config(root: Path, name: str = "fuzz") -> CampaignConfig:
    return CampaignConfig(
        artifact=BuildArtifact(
            binary_path=root / name,
            engine=EngineKind.LIBFUZZER,
            sanitizers=[Sanitizer.ASAN],
            build_log_path=root / f"{name}.log",
        ),
        corpus_dir=root / "corpus",
        crash_dir=root / "crashes",
        dictionary_path=None,
        time_budget_sec=60,
    )


def test_new_campaign_creates_layout_and_row(store_root):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))
    paths = store.paths(cid)

    assert paths["base"].is_dir()
    assert paths["corpus_dir"].is_dir()
    assert paths["crash_dir"].is_dir()
    assert paths["meta"].is_file()
    row = store._db.execute("SELECT cid, status FROM campaigns WHERE cid=?", (cid,)).fetchone()
    assert row == (cid, "pending")


def test_record_event_appends_jsonl_and_inserts_row(store_root, make_event):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))
    event = make_event(cid, EventKind.NEW_COVERAGE, edges=12)

    store.record_event(event)

    lines = store.paths(cid)["events_log"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["payload"] == {"edges": 12}
    row = store._db.execute("SELECT kind, payload_json FROM events WHERE cid=?", (cid,)).fetchone()
    assert row[0] == "new_coverage"
    assert json.loads(row[1]) == {"edges": 12}


def test_agent_trace_appends_jsonl(store_root):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))

    store.record_agent_trace(cid, {"phase": "harness_attempt", "step": 1})
    store.record_agent_trace(cid, {"phase": "harness_attempt", "step": 2})

    trace = store.list_agent_trace(cid)
    assert trace == [
        {"phase": "harness_attempt", "step": 1},
        {"phase": "harness_attempt", "step": 2},
    ]
    assert store.paths(cid)["agent_trace"].is_file()


def test_agent_session_trace_persists_without_campaign(store_root):
    store = CampaignStore(store_root)
    session_id = store.new_agent_session({"status": "failed", "target_path": "/tmp/target"})

    store.record_agent_session_trace(session_id, {"phase": "harness_attempt", "step": 1})

    assert store.list_agent_session_trace(session_id) == [
        {"phase": "harness_attempt", "step": 1}
    ]
    assert store.agent_session_paths(session_id)["meta"].is_file()


def test_record_stats_upserts_one_latest_row(store_root, make_stats):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))

    store.record_stats(make_stats(cid, edges_covered=1))
    store.record_stats(make_stats(cid, edges_covered=9, execs_total=200))

    count = store._db.execute("SELECT COUNT(*) FROM stats WHERE cid=?", (cid,)).fetchone()[0]
    latest = store.latest_stats(cid)
    assert count == 1
    assert latest.edges_covered == 9
    assert latest.execs_total == 200


def test_list_campaigns_orders_newest_first_and_includes_stats(store_root, make_stats):
    store = CampaignStore(store_root)
    cid1 = store.new_campaign(_config(store_root / "one", "one"))
    cid2 = store.new_campaign(_config(store_root / "two", "two"))
    store.update_status(cid2, CampaignStatus.RUNNING)
    store.record_stats(make_stats(cid1, edges_covered=1))
    store.record_stats(make_stats(cid2, edges_covered=9, unique_crashes=2))

    campaigns = store.list_campaigns()

    assert [c["cid"] for c in campaigns] == [cid2, cid1]
    assert campaigns[0]["status"] == "running"
    assert campaigns[0]["stats"]["edges_covered"] == 9
    assert campaigns[0]["stats"]["unique_crashes"] == 2


def test_save_crash_and_list_crashes_roundtrip(store_root):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))
    crash = CrashRecord(
        crash_id="crash-1",
        campaign_id=cid,
        input_path=store.paths(cid)["crash_dir"] / "input",
        minimized_path=None,
        stack_hash="stack-abc",
        top_frames=["frame1", "frame2"],
        sanitizer_kind="use-after-free",
        discovered_at=datetime.now(timezone.utc),
        severity=Severity.CRITICAL,
        vulnerability_matches=[
            VulnerabilityMatch(
                rule_id="asan-use-after-free",
                title="Use-after-free",
                cwe="CWE-416",
                confidence=0.97,
                evidence=["use-after-free"],
            )
        ],
    )

    store.save_crash(crash)
    [saved] = store.list_crashes(cid)

    assert saved.stack_hash == "stack-abc"
    assert saved.top_frames == ["frame1", "frame2"]
    assert saved.severity is Severity.CRITICAL
    assert saved.vulnerability_matches[0].cwe == "CWE-416"


def test_save_crash_updates_campaign_index_on_conflict(store_root):
    store = CampaignStore(store_root)
    cid1 = store.new_campaign(_config(store_root / "one", "one"))
    cid2 = store.new_campaign(_config(store_root / "two", "two"))
    first = CrashRecord(
        crash_id="same-crash",
        campaign_id=cid1,
        input_path=store.paths(cid1)["crash_dir"] / "input",
        minimized_path=None,
        stack_hash="stack",
        top_frames=["frame"],
        sanitizer_kind="SEGV",
        discovered_at=datetime.now(timezone.utc),
    )
    second = dataclasses.replace(
        first,
        campaign_id=cid2,
        input_path=store.paths(cid2)["crash_dir"] / "input",
    )

    store.save_crash(first)
    store.save_crash(second)

    assert store.list_crashes(cid1) == []
    [saved] = store.list_crashes(cid2)
    assert saved.campaign_id == cid2


def test_list_crashes_recovers_legacy_stale_campaign_index(store_root):
    store = CampaignStore(store_root)
    cid1 = store.new_campaign(_config(store_root / "one", "one"))
    cid2 = store.new_campaign(_config(store_root / "two", "two"))
    crash = CrashRecord(
        crash_id="same-crash",
        campaign_id=cid2,
        input_path=store.paths(cid2)["crash_dir"] / "input",
        minimized_path=None,
        stack_hash="stack",
        top_frames=["frame"],
        sanitizer_kind="SEGV",
        discovered_at=datetime.now(timezone.utc),
    )
    store.save_crash(crash)
    store._db.execute("UPDATE crashes SET cid=? WHERE crash_id=?", (cid1, crash.crash_id))
    store._db.commit()

    assert store.list_crashes(cid1) == []
    [saved] = store.list_crashes(cid2)
    assert saved.campaign_id == cid2


def test_summary_returns_stats_crashes_and_paths(store_root, make_stats):
    store = CampaignStore(store_root)
    cid = store.new_campaign(_config(store_root))
    store.record_stats(make_stats(cid, edges_covered=7))
    store.save_crash(
        CrashRecord(
            crash_id="crash-1",
            campaign_id=cid,
            input_path=Path("input"),
            minimized_path=Path("min"),
            stack_hash="hash",
            top_frames=["top"],
            sanitizer_kind=None,
            discovered_at=datetime.now(timezone.utc),
            severity=Severity.LOW,
        )
    )

    summary = store.summary(cid)

    assert summary["stats"]["edges_covered"] == 7
    assert summary["crashes"][0]["stack_hash"] == "hash"
    assert set(summary["paths"]) >= {"base", "meta", "corpus_dir", "crash_dir", "events_log"}


def test_multiple_campaigns_in_same_store_do_not_collide(store_root, make_stats):
    store = CampaignStore(store_root)
    cid1 = store.new_campaign(_config(store_root / "one", "one"))
    cid2 = store.new_campaign(_config(store_root / "two", "two"))

    store.record_stats(make_stats(cid1, edges_covered=1))
    store.record_stats(make_stats(cid2, edges_covered=2))

    assert cid1 != cid2
    assert store.paths(cid1)["base"] != store.paths(cid2)["base"]
    assert store.latest_stats(cid1).edges_covered == 1
    assert store.latest_stats(cid2).edges_covered == 2
