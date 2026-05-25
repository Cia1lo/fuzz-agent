"""FastAPI server for the Fuzz Agent web UI."""
from __future__ import annotations

import json
import os
import ipaddress
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, AsyncIterator, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ..chat import ChatSession, ConversationAgent
from ..tools import _runtime, stop_campaign
from ..tools._runtime import Runtime
from ._launcher import submit_campaign

app = FastAPI(title="Fuzz Agent")

_WEB_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=_WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=_WEB_DIR / "templates")
templates.env.globals["asset_version"] = (
    lambda: int((_WEB_DIR / "static" / "style.css").stat().st_mtime)
)


class CampaignRequest(BaseModel):
    path: str
    time_sec: int = Field(gt=0)
    engine: str


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    campaign_id: str | None = None


_chat_sessions: dict[str, ChatSession] = {}


def _rt() -> Runtime:
    return _runtime.runtime()


def _is_local_host(host: str | None) -> bool:
    if host is None or host in {"testclient", "localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@app.middleware("http")
async def local_only(
    request: Request,
    call_next: Callable[[Request], Awaitable[Any]],
) -> Any:
    if os.environ.get("FUZZ_AGENT_WEB_ALLOW_REMOTE") == "1":
        return await call_next(request)
    host = request.client.host if request.client else None
    if not _is_local_host(host):
        return JSONResponse({"detail": "remote access disabled"}, status_code=403)
    return await call_next(request)


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


def _tail_events(cid: str, limit: int = 50) -> list[dict[str, Any]]:
    log_path = _rt().store.paths(cid)["events_log"]
    if not log_path.exists():
        return []
    lines: deque[str] = deque(maxlen=limit)
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            events.append(cast(dict[str, Any], json.loads(line)))
        except json.JSONDecodeError:
            continue
    return events


def _campaign_meta(cid: str) -> dict[str, Any]:
    meta_path = _rt().store.paths(cid)["meta"]
    if not meta_path.exists():
        return {}
    try:
        return cast(dict[str, Any], json.loads(meta_path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return {}


def _read_text(path: Path) -> PlainTextResponse:
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return PlainTextResponse(path.read_text(errors="replace"))


def _chat_session_title(session: ChatSession) -> str:
    for turn in session.history:
        if turn.role == "user" and turn.content.strip():
            return _short_label(turn.content)
    if session.target_path:
        return _short_label(Path(session.target_path).name or session.target_path)
    if session.active_campaign_id:
        return f"campaign {session.active_campaign_id}"
    return "New session"


def _short_label(value: str, limit: int = 42) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _load_chat_session(session_id: str) -> ChatSession | None:
    cached = _chat_sessions.get(session_id)
    if cached is not None:
        return cached
    data = _rt().store.get_chat_session(session_id)
    if data is None:
        return None
    session = ChatSession.from_dict(data)
    _chat_sessions[session.session_id] = session
    return session


def _save_chat_session(session: ChatSession) -> None:
    _chat_sessions[session.session_id] = session
    _rt().store.save_chat_session(session.to_dict())


def _list_chat_sessions() -> list[ChatSession]:
    sessions: dict[str, ChatSession] = {}
    for data in _rt().store.list_chat_sessions():
        session = ChatSession.from_dict(data)
        cached = _chat_sessions.get(session.session_id)
        sessions[session.session_id] = cached or session
        _chat_sessions.setdefault(session.session_id, session)
    for session in _chat_sessions.values():
        if session.history:
            sessions[session.session_id] = session
    return sorted(sessions.values(), key=lambda session: session.updated_at, reverse=True)


def _chat_session_json(session: ChatSession, *, include_history: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "session_id": session.session_id,
        "title": _chat_session_title(session),
        "active_campaign_id": session.active_campaign_id,
        "target_path": session.target_path,
        "turn_count": len(session.history),
        "created_at": session.created_at,
        "updated_at": session.updated_at,
    }
    if include_history:
        data["history"] = [
            {"role": turn.role, "content": turn.content, "created_at": turn.created_at}
            for turn in session.history
        ]
    return data


@app.get("/")
async def index(request: Request) -> Any:
    return templates.TemplateResponse(
        request, "index.html",
        {"campaigns": _rt().store.list_campaigns()},
    )


@app.get("/chat")
async def chat_page(request: Request) -> Any:
    return templates.TemplateResponse(request, "chat.html", {})


@app.get("/campaigns/{cid}")
async def campaign(request: Request, cid: str) -> Any:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return templates.TemplateResponse(
        request, "campaign.html",
        {
            "cid": cid,
            "summary": _rt().store.summary(cid),
            "meta": _campaign_meta(cid),
            "recent_events": _tail_events(cid),
            "agent_trace": _rt().store.list_agent_trace(cid),
            "crashes": [_jsonable(c) for c in _rt().store.list_crashes(cid)],
        },
    )


@app.get("/api/campaigns")
async def api_campaigns() -> JSONResponse:
    return JSONResponse(_rt().store.list_campaigns())


@app.get("/api/chat/sessions")
async def api_chat_sessions() -> JSONResponse:
    return JSONResponse([
        _chat_session_json(session)
        for session in _list_chat_sessions()
    ])


@app.get("/api/chat/sessions/{session_id}")
async def api_chat_session(session_id: str) -> JSONResponse:
    session = _load_chat_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    return JSONResponse(_chat_session_json(session, include_history=True))


@app.post("/api/chat")
async def api_chat(body: ChatRequest) -> JSONResponse:
    session_id = body.session_id.strip() or "default"
    session = _load_chat_session(session_id) or ChatSession(session_id=session_id)
    if body.campaign_id:
        if not _known_campaign(body.campaign_id):
            raise HTTPException(status_code=404, detail="campaign not found")
        session.active_campaign_id = body.campaign_id
    agent = ConversationAgent(_rt().store, _rt().bus)
    reply = await agent.respond(session, body.message)
    _save_chat_session(session)
    return JSONResponse({
        "reply": reply,
        **_chat_session_json(session, include_history=True),
    })


@app.get("/api/campaigns/{cid}")
async def api_campaign(cid: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse(_rt().store.summary(cid))


@app.get("/api/campaigns/{cid}/stats")
async def api_campaign_stats(cid: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse(_jsonable(_rt().store.latest_stats(cid) or {}))


@app.get("/api/campaigns/{cid}/crashes")
async def api_campaign_crashes(cid: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse([_jsonable(c) for c in _rt().store.list_crashes(cid)])


@app.get("/api/campaigns/{cid}/crashes/{crash_id}")
async def api_campaign_crash(cid: str, crash_id: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    for crash in _rt().store.list_crashes(cid):
        if crash.crash_id == crash_id:
            return JSONResponse(_jsonable(crash))
    raise HTTPException(status_code=404, detail="crash not found")


@app.get("/api/campaigns/{cid}/agent-trace")
async def api_campaign_agent_trace(cid: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return JSONResponse(_rt().store.list_agent_trace(cid))


@app.get("/api/campaigns/{cid}/logs/run")
async def api_campaign_run_log(cid: str) -> PlainTextResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return _read_text(_rt().store.paths(cid)["run_log"])


@app.get("/api/campaigns/{cid}/logs/build")
async def api_campaign_build_log(cid: str) -> PlainTextResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    meta = _campaign_meta(cid)
    path = Path(meta.get("artifact", {}).get("build_log_path", ""))
    return _read_text(path)


@app.get("/api/campaigns/{cid}/harness")
async def api_campaign_harness(cid: str) -> PlainTextResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    meta = _campaign_meta(cid)
    path = Path(meta.get("artifact", {}).get("harness_source_path", ""))
    return _read_text(path)


@app.get("/api/campaigns/{cid}/coverage/summary")
async def api_campaign_coverage_summary(cid: str) -> PlainTextResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    return _read_text(_rt().store.paths(cid)["coverage_summary"])


@app.get("/api/campaigns/{cid}/coverage/uncovered")
async def api_campaign_coverage_uncovered(cid: str) -> JSONResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")
    path = _rt().store.paths(cid)["coverage_uncovered"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.post("/api/campaigns")
async def api_create_campaign(request: Request) -> JSONResponse:
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
async def api_stop_campaign(cid: str) -> JSONResponse:
    stop_campaign(cid)
    return JSONResponse({"ok": True})


@app.get("/api/campaigns/{cid}/events")
async def api_campaign_events(cid: str) -> StreamingResponse:
    if not _known_campaign(cid):
        raise HTTPException(status_code=404, detail="campaign not found")

    async def gen() -> AsyncIterator[str]:
        for replay in _tail_events(cid):
            data = json.dumps(replay)
            yield f"event: replay\ndata: {data}\n\n"
        if cid in getattr(_rt().bus, "_closed", set()):
            return
        async for event in _rt().bus.subscribe(cid):
            data = json.dumps(
                {"kind": event.kind.value, "ts": event.ts.isoformat(), "payload": event.payload},
                default=str,
            )
            yield f"event: {event.kind.value}\ndata: {data}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
