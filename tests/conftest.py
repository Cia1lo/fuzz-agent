from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzz_agent.state.models import CampaignStats, CampaignStatus, EventKind, FuzzEvent


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    return tmp_path / "store"


@pytest.fixture
def make_event():
    def _make_event(cid: str, kind: EventKind | str, **payload) -> FuzzEvent:
        event_kind = kind if isinstance(kind, EventKind) else EventKind(kind)
        return FuzzEvent(
            kind=event_kind,
            campaign_id=cid,
            ts=payload.pop("ts", datetime.now(timezone.utc)),
            payload=payload,
        )

    return _make_event


@pytest.fixture
def make_stats():
    def _make_stats(cid: str, **overrides) -> CampaignStats:
        data = {
            "campaign_id": cid,
            "status": CampaignStatus.RUNNING,
            "elapsed_sec": 10,
            "execs_total": 1000,
            "execs_per_sec": 100.0,
            "edges_covered": 50,
            "edges_total": None,
            "corpus_size": 4,
            "unique_crashes": 0,
            "last_new_coverage_sec_ago": 1,
            "last_event_ts": datetime.now(timezone.utc),
        }
        data.update(overrides)
        return CampaignStats(**data)

    return _make_stats
