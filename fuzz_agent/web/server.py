"""FastAPI server for the Fuzz Agent web UI."""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ..tools import _runtime, stop_campaign
from ._launcher import submit_campaign

app = FastAPI(title="Fuzz Agent")

_WEB_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=_WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=_WEB_DIR / "templates")


class CampaignRequest(BaseModel):
    path: str
    time_sec: int = Field(gt=0)
    engine: str


def _rt():
    return _runtime.runtime()


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict

        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return value


def _known_campaign(cid: str) -> bool:
    return any(row["cid"] == cid for row in _rt().store.list_campaigns())


def _tail_events(cid: str, limit: int = 50) -> list[dict]:
    log_path = _rt().store.paths(cid)["events_log"]
    if not log_path.exists():
        return []
    lines: deque[str] = deque(maxlen=limit)
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    events: list[dict] = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _campaign_meta(cid: str) -> dict:
    meta_path = _rt().store.paths(cid)["meta"]
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request, "index.html",
        {"campaigns": _rt().store.list_campaigns()},
    )


@app.get("/campaigns/{cid}")
async def campaign(request: Request, cid: str):
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return templates.TemplateResponse(
        request, "campaign.html",
        {
            "cid": cid,
            "summary": _rt().store.summary(cid),
            "meta": _campaign_meta(cid),
            "recent_events": _tail_events(cid),
            "crashes": [_jsonable(c) for c in _rt().store.list_crashes(cid)],
        },
    )


@app.get("/api/campaigns")
async def api_campaigns():
    return JSONResponse(_rt().store.list_campaigns())


@app.get("/api/campaigns/{cid}")
async def api_campaign(cid: str):
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse(_rt().store.summary(cid))


@app.get("/api/campaigns/{cid}/stats")
async def api_campaign_stats(cid: str):
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse(_jsonable(_rt().store.latest_stats(cid) or {}))


@app.get("/api/campaigns/{cid}/crashes")
async def api_campaign_crashes(cid: str):
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse([_jsonable(c) for c in _rt().store.list_crashes(cid)])


@app.post("/api/campaigns")
async def api_create_campaign(request: Request):
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        payload = await request.json()
    else:
        form = await request.form()
        payload = dict(form)
    body = CampaignRequest(**payload)
    cid = submit_campaign(body.path, body.time_sec, body.engine)
    return JSONResponse({"campaign_id": cid})


@app.post("/api/campaigns/{cid}/stop")
async def api_stop_campaign(cid: str):
    stop_campaign(cid)
    return JSONResponse({"ok": True})


@app.get("/api/campaigns/{cid}/events")
async def api_campaign_events(cid: str):
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")

    async def gen():
        for ev in _tail_events(cid):
            data = json.dumps(ev)
            yield f"event: replay\ndata: {data}\n\n"
        if cid in getattr(_rt().bus, "_closed", set()):
            return
        async for ev in _rt().bus.subscribe(cid):
            data = json.dumps(
                {"kind": ev.kind.value, "ts": ev.ts.isoformat(), "payload": ev.payload},
                default=str,
            )
            yield f"event: {ev.kind.value}\ndata: {data}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
