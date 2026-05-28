"""CampaignStore — persistence for campaigns, stats, events, crashes.

SQLite + filesystem layout:
    <root>/state/state.db
    <root>/state/campaigns/<cid>/{meta.json, corpus/, crashes/, coverage.profraw, events.jsonl}
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, cast

from .models import (
    CampaignConfig,
    CampaignStats,
    CampaignStatus,
    CrashStatus,
    CrashRecord,
    EventKind,
    FuzzEvent,
    Severity,
    VulnerabilityMatch,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    cid TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    meta_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stats (
    cid TEXT PRIMARY KEY,
    snapshot_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crashes (
    crash_id TEXT PRIMARY KEY,
    cid TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_cid ON events(cid);
CREATE INDEX IF NOT EXISTS idx_crashes_cid ON crashes(cid);
CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id TEXT PRIMARY KEY,
    updated_at TEXT NOT NULL,
    session_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON chat_sessions(updated_at);
"""


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def _to_jsonable(obj: Any) -> Any:
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (CampaignStatus, EventKind, Severity)) or hasattr(obj, "value"):
        return obj.value if hasattr(obj, "value") else str(obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    return obj


def _dumps(obj: Any) -> str:
    return json.dumps(_to_jsonable(obj), ensure_ascii=False)


class CampaignStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.state_dir = self.root / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "state.db"
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---------- paths ----------
    def paths(self, cid: str) -> dict[str, Path]:
        base = self.state_dir / "campaigns" / cid
        return {
            "base": base,
            "meta": base / "meta.json",
            "corpus_dir": base / "corpus",
            "crash_dir": base / "crashes",
            "coverage": base / "coverage.profraw",
            "coverage_summary": base / "coverage_summary.txt",
            "coverage_uncovered": base / "coverage_uncovered.json",
            "events_log": base / "events.jsonl",
            "agent_trace": base / "agent_trace.jsonl",
            "run_log": base / "run.log",
        }

    def agent_session_paths(self, session_id: str) -> dict[str, Path]:
        base = self.state_dir / "agent_sessions" / session_id
        return {
            "base": base,
            "agent_trace": base / "agent_trace.jsonl",
            "meta": base / "meta.json",
        }

    # ---------- campaigns ----------
    def new_campaign(self, cfg: CampaignConfig) -> str:
        cid = uuid.uuid4().hex[:12]
        p = self.paths(cid)
        for key in ("base", "corpus_dir", "crash_dir"):
            p[key].mkdir(parents=True, exist_ok=True)
        meta = _to_jsonable(cfg)
        _atomic_write(p["meta"], json.dumps(meta, indent=2, ensure_ascii=False))
        self._db.execute(
            "INSERT INTO campaigns(cid,status,created_at,meta_json) VALUES (?,?,?,?)",
            (cid, CampaignStatus.PENDING.value, datetime.now(timezone.utc).isoformat(), _dumps(cfg)),
        )
        self._db.commit()
        return cid

    def update_status(self, cid: str, status: CampaignStatus) -> None:
        self._db.execute("UPDATE campaigns SET status=? WHERE cid=?", (status.value, cid))
        self._db.commit()

    def update_meta(self, cid: str, cfg: CampaignConfig) -> None:
        p = self.paths(cid)
        meta = _to_jsonable(cfg)
        _atomic_write(p["meta"], json.dumps(meta, indent=2, ensure_ascii=False))
        self._db.execute("UPDATE campaigns SET meta_json=? WHERE cid=?", (_dumps(cfg), cid))
        self._db.commit()

    def campaign_config(self, cid: str) -> Optional[CampaignConfig]:
        row = self._db.execute("SELECT meta_json FROM campaigns WHERE cid=?", (cid,)).fetchone()
        if not row:
            return None
        from .models import BuildArtifact, EngineKind, Sanitizer

        d = json.loads(row[0])
        artifact = d["artifact"]
        artifact["binary_path"] = Path(artifact["binary_path"])
        artifact["engine"] = EngineKind(artifact["engine"])
        artifact["sanitizers"] = [Sanitizer(s) for s in artifact.get("sanitizers", [])]
        artifact["build_log_path"] = Path(artifact["build_log_path"])
        if artifact.get("harness_source_path"):
            artifact["harness_source_path"] = Path(artifact["harness_source_path"])
        cfg = {
            "artifact": BuildArtifact(**artifact),
            "corpus_dir": Path(d["corpus_dir"]),
            "crash_dir": Path(d["crash_dir"]),
            "dictionary_path": Path(d["dictionary_path"]) if d.get("dictionary_path") else None,
            "time_budget_sec": int(d["time_budget_sec"]),
            "max_memory_mb": int(d.get("max_memory_mb", 2048)),
            "extra_args": list(d.get("extra_args", [])),
            "campaign_id": d.get("campaign_id"),
            "resumed_from": d.get("resumed_from"),
        }
        return CampaignConfig(**cfg)

    def list_campaigns(self) -> list[dict[str, Any]]:
        """Return [{cid, status, created_at, stats}] ordered by created_at desc."""
        rows = self._db.execute(
            "SELECT c.cid, c.status, c.created_at, s.snapshot_json "
            "FROM campaigns c LEFT JOIN stats s ON s.cid = c.cid "
            "ORDER BY c.created_at DESC"
        ).fetchall()
        return [
            {
                "cid": cid,
                "status": status,
                "created_at": created_at,
                "stats": json.loads(stats_json) if stats_json else None,
            }
            for cid, status, created_at, stats_json in rows
        ]

    # ---------- events ----------
    def record_event(self, ev: FuzzEvent) -> None:
        p = self.paths(ev.campaign_id)
        line = _dumps({"kind": ev.kind.value, "ts": ev.ts.isoformat(), "payload": ev.payload})
        with p["events_log"].open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._db.execute(
            "INSERT INTO events(cid,kind,ts,payload_json) VALUES (?,?,?,?)",
            (ev.campaign_id, ev.kind.value, ev.ts.isoformat(), _dumps(ev.payload)),
        )
        self._db.commit()

    # ---------- agent trace ----------
    def record_agent_trace(self, cid: str, record: Any) -> None:
        p = self.paths(cid)
        with p["agent_trace"].open("a", encoding="utf-8") as f:
            f.write(_dumps(record) + "\n")

    def list_agent_trace(self, cid: str) -> list[dict[str, Any]]:
        path = self.paths(cid)["agent_trace"]
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out

    def new_agent_session(self, meta: dict[str, Any]) -> str:
        session_id = uuid.uuid4().hex[:12]
        paths = self.agent_session_paths(session_id)
        paths["base"].mkdir(parents=True, exist_ok=True)
        _atomic_write(paths["meta"], json.dumps(_to_jsonable(meta), indent=2, ensure_ascii=False))
        return session_id

    def record_agent_session_trace(self, session_id: str, record: Any) -> None:
        paths = self.agent_session_paths(session_id)
        paths["base"].mkdir(parents=True, exist_ok=True)
        with paths["agent_trace"].open("a", encoding="utf-8") as f:
            f.write(_dumps(record) + "\n")

    def list_agent_session_trace(self, session_id: str) -> list[dict[str, Any]]:
        path = self.agent_session_paths(session_id)["agent_trace"]
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out

    # ---------- chat sessions ----------
    def save_chat_session(self, session: dict[str, Any]) -> None:
        session = dict(session)
        session_id = session.get("session_id")
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("chat session must include a non-empty session_id")
        updated_at = session.get("updated_at")
        if not isinstance(updated_at, str) or not updated_at:
            updated_at = datetime.now(timezone.utc).isoformat()
            session["updated_at"] = updated_at
        self._db.execute(
            "INSERT INTO chat_sessions(session_id, updated_at, session_json) VALUES (?, ?, ?) "
            "ON CONFLICT(session_id) DO UPDATE SET "
            "updated_at=excluded.updated_at, session_json=excluded.session_json",
            (session_id, updated_at, json.dumps(_to_jsonable(session), ensure_ascii=False)),
        )
        self._db.commit()

    def get_chat_session(self, session_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT session_json FROM chat_sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        if isinstance(data, dict):
            return cast(dict[str, Any], data)
        return None

    def list_chat_sessions(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT session_json FROM chat_sessions ORDER BY updated_at DESC"
        ).fetchall()
        sessions: list[dict[str, Any]] = []
        for (payload,) in rows:
            data = json.loads(payload)
            if isinstance(data, dict):
                sessions.append(cast(dict[str, Any], data))
        return sessions

    # ---------- stats ----------
    def record_stats(self, stats: CampaignStats) -> None:
        self._db.execute(
            "INSERT INTO stats(cid,snapshot_json,updated_at) VALUES (?,?,?) "
            "ON CONFLICT(cid) DO UPDATE SET snapshot_json=excluded.snapshot_json, "
            "updated_at=excluded.updated_at",
            (stats.campaign_id, _dumps(stats), datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def latest_stats(self, cid: str) -> Optional[CampaignStats]:
        row = self._db.execute("SELECT snapshot_json FROM stats WHERE cid=?", (cid,)).fetchone()
        if not row:
            return None
        d = json.loads(row[0])
        d["status"] = CampaignStatus(d["status"])
        if d.get("last_event_ts"):
            d["last_event_ts"] = datetime.fromisoformat(d["last_event_ts"])
        # filter to fields the dataclass knows about
        allowed = {f.name for f in fields(CampaignStats)}
        return CampaignStats(**{k: v for k, v in d.items() if k in allowed})

    # ---------- crashes ----------
    def save_crash(self, crash: CrashRecord) -> None:
        self._db.execute(
            "INSERT INTO crashes(crash_id,cid,record_json) VALUES (?,?,?) "
            "ON CONFLICT(crash_id) DO UPDATE SET "
            "cid=excluded.cid, record_json=excluded.record_json",
            (crash.crash_id, crash.campaign_id, _dumps(crash)),
        )
        self._db.commit()

    def list_crashes(self, cid: str) -> list[CrashRecord]:
        direct_rows = self._db.execute(
            "SELECT record_json FROM crashes WHERE cid=?", (cid,)
        ).fetchall()
        allowed = {f.name for f in fields(CrashRecord)}

        def decode(raw: str) -> CrashRecord:
            d = json.loads(raw)
            d["input_path"] = Path(d["input_path"])
            if d.get("minimized_path"):
                d["minimized_path"] = Path(d["minimized_path"])
            if d.get("severity"):
                d["severity"] = Severity(d["severity"])
            if d.get("status"):
                d["status"] = CrashStatus(d["status"])
            if d.get("reproduce_log_path"):
                d["reproduce_log_path"] = Path(d["reproduce_log_path"])
            d["vulnerability_matches"] = [
                VulnerabilityMatch(**match)
                for match in d.get("vulnerability_matches", [])
                if isinstance(match, dict)
            ]
            if d.get("discovered_at"):
                d["discovered_at"] = datetime.fromisoformat(d["discovered_at"])
            return CrashRecord(**{k: v for k, v in d.items() if k in allowed})

        out: list[CrashRecord] = []
        seen: set[str] = set()
        for (raw,) in direct_rows:
            crash = decode(raw)
            if crash.campaign_id == cid:
                out.append(crash)
                seen.add(crash.crash_id)
        if direct_rows and len(out) == len(direct_rows):
            return out

        # Recover rows written by older versions where the index cid could be
        # stale after an ON CONFLICT update for the same global crash id.
        for (raw,) in self._db.execute("SELECT record_json FROM crashes").fetchall():
            crash = decode(raw)
            if crash.campaign_id == cid and crash.crash_id not in seen:
                out.append(crash)
                seen.add(crash.crash_id)
        return out

    # ---------- summary ----------
    def summary(self, cid: str) -> dict[str, Any]:
        stats = self.latest_stats(cid)
        return {
            "campaign_id": cid,
            "stats": _to_jsonable(stats) if stats else None,
            "crashes": [_to_jsonable(c) for c in self.list_crashes(cid)],
            "paths": {k: str(v) for k, v in self.paths(cid).items()},
        }
