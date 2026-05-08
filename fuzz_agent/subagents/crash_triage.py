"""crash-triage subagent: dedup + extract top frames from raw crash artifacts."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from ..state.models import CrashRecord

_FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<sym>[^\s]+)", re.MULTILINE)
_SAN_KIND_RE = re.compile(r"==\d+==ERROR: \w+Sanitizer: (?P<kind>[\w\-]+)")


def _read_log(crash_path: Path) -> str:
    for cand in (crash_path.with_suffix(crash_path.suffix + ".log"),
                 crash_path.parent / (crash_path.name + ".log")):
        if cand.exists():
            return cand.read_text(errors="replace")
    return ""


def _top_frames(log: str, n: int = 5) -> list[str]:
    return [m.group("sym") for m in _FRAME_RE.finditer(log)][:n]


def _sanitizer_kind(log: str) -> str | None:
    m = _SAN_KIND_RE.search(log)
    return m.group("kind") if m else None


def _stack_hash(frames: list[str], fallback_bytes: bytes) -> str:
    if frames:
        return hashlib.sha1("|".join(frames).encode()).hexdigest()[:16]
    return hashlib.sha1(fallback_bytes).hexdigest()[:16]


def run(campaign_id: str, raw_crash_dir: Path, top_n: int) -> list[CrashRecord]:
    seen: dict[str, CrashRecord] = {}
    if not raw_crash_dir.exists():
        return []
    for p in sorted(raw_crash_dir.iterdir()):
        if not p.is_file() or p.suffix == ".log":
            continue
        log = _read_log(p)
        frames = _top_frames(log)
        san_kind = _sanitizer_kind(log)
        h = _stack_hash(frames, p.read_bytes()[:4096])
        if h in seen:
            continue
        seen[h] = CrashRecord(
            crash_id=h, campaign_id=campaign_id,
            input_path=p, minimized_path=None, stack_hash=h,
            top_frames=frames, sanitizer_kind=san_kind,
            discovered_at=datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc),
        )
        if len(seen) >= top_n:
            break
    return list(seen.values())
