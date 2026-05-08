"""Best-effort crash frame symbolization."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_MODULE_SYM_RE = re.compile(r".+![^+]+(?:\+0x[0-9a-fA-F]+)?")
_LINE_INFO_RE = re.compile(r":\d+(?::\d+)?(?:\b|$)")


def _already_symbolized(frames: list[str]) -> bool:
    return any(_MODULE_SYM_RE.search(f) or _LINE_INFO_RE.search(f) for f in frames)


def symbolize(
    top_frames: list[str],
    binary: Path | None = None,
    timeout_sec: int = 5,
) -> list[str]:
    """Return symbolized frames when possible, otherwise the original frames."""
    if not top_frames or _already_symbolized(top_frames):
        return top_frames
    if binary is None:
        return top_frames

    tool = shutil.which("llvm-symbolizer")
    if tool is None:
        return top_frames

    addresses: list[str] = []
    frame_addr: list[str | None] = []
    for frame in top_frames:
        match = _HEX_RE.search(frame)
        if match is None:
            frame_addr.append(None)
            continue
        addr = match.group(0)
        addresses.append(addr)
        frame_addr.append(addr)

    if not addresses:
        return top_frames

    try:
        proc = subprocess.run(
            [tool, f"--obj={binary}"],
            input="\n".join(addresses) + "\n",
            text=True,
            capture_output=True,
            timeout=timeout_sec,
            check=False,
        )
    except Exception:
        return top_frames
    if proc.returncode != 0:
        return top_frames

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        return top_frames

    by_addr: dict[str, str] = {}
    idx = 0
    for addr in addresses:
        if idx >= len(lines):
            break
        func = lines[idx]
        loc = lines[idx + 1] if idx + 1 < len(lines) else ""
        idx += 2
        if func == "??" and (not loc or loc.startswith("??")):
            continue
        by_addr[addr] = f"{func} {loc}".strip()

    if not by_addr:
        return top_frames
    return [by_addr.get(addr, frame) if addr else frame for frame, addr in zip(top_frames, frame_addr)]
