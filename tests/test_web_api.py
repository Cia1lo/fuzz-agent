from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    pytest.skip("fastapi is not installed", allow_module_level=True)

from fuzz_agent.state.models import BuildArtifact, CampaignConfig, EngineKind, Sanitizer
from fuzz_agent.tools import _runtime
from fuzz_agent.tools._runtime import Runtime
from fuzz_agent.web.server import app


@pytest.fixture
def web_rt(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    return rt


@pytest.fixture
def client(web_rt):
    return TestClient(app)


def _config(root: Path) -> CampaignConfig:
    return CampaignConfig(
        artifact=BuildArtifact(
            binary_path=root / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[Sanitizer.ASAN],
            build_log_path=root / "build.log",
        ),
        corpus_dir=root / "corpus",
        crash_dir=root / "crashes",
        dictionary_path=None,
        time_budget_sec=60,
    )


def test_index_renders(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Fuzz Agent" in response.text


def test_api_campaigns_empty(client):
    response = client.get("/api/campaigns")

    assert response.status_code == 200
    assert response.json() == []


def test_api_campaigns_after_seed(client, web_rt, make_stats):
    cid = web_rt.store.new_campaign(_config(web_rt.root))
    web_rt.store.record_stats(make_stats(cid, edges_covered=42))

    response = client.get("/api/campaigns")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["cid"] == cid
    assert data[0]["stats"]["edges_covered"] == 42


def test_api_campaign_summary_404(client):
    response = client.get("/api/campaigns/nonexistent")

    assert response.status_code == 404


def test_sse_replay_only(client, web_rt):
    cid = web_rt.store.new_campaign(_config(web_rt.root))
    log = web_rt.store.paths(cid)["events_log"]
    log.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {"kind": "heartbeat", "ts": datetime.now(timezone.utc).isoformat(), "payload": {"n": 1}},
        {"kind": "new_coverage", "ts": datetime.now(timezone.utc).isoformat(), "payload": {"edges": 2}},
    ]
    log.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    web_rt.bus.close(cid)

    with client.stream("GET", f"/api/campaigns/{cid}/events") as response:
        body = "".join(response.iter_text())

    assert response.status_code == 200
    assert body.count("event: replay") == 2
    assert '"kind": "heartbeat"' in body
    assert '"kind": "new_coverage"' in body
