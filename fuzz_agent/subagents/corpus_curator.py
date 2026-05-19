"""corpus-curator subagent: collect seed material for a target."""
from __future__ import annotations

import base64
import shutil
from pathlib import Path

from ..state.models import TargetProfile
from ._llm import call_llm_json

_LIKELY_DIRS = ("tests", "test", "examples", "example", "fixtures", "testdata", "samples")
_EXT_BY_LANG = {
    "json": (".json",), "xml": (".xml",), "pdf": (".pdf",), "yaml": (".yaml", ".yml"),
}

_SYSTEM = """You generate minimal seed inputs for fuzz testing. Output strict JSON only.
Schema: {"seeds": [{"name": "<short>", "bytes_b64": "<base64>"}]}
Each seed should be small (<2KB), legal-but-edge for the target's input format."""


def _scan_existing(root: Path, max_seeds: int) -> list[Path]:
    found: list[Path] = []
    for d in _LIKELY_DIRS:
        p = root / d
        if not p.exists():
            continue
        for f in p.rglob("*"):
            if f.is_file() and f.stat().st_size < 64 * 1024:
                found.append(f)
                if len(found) >= max_seeds:
                    return found
    return found


def run(target: TargetProfile, out_dir: Path, max_seeds: int) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    collected: list[Path] = []
    for src in _scan_existing(target.root, max_seeds):
        dst = out_dir / src.name
        try:
            shutil.copy2(src, dst)
            collected.append(dst)
        except OSError:
            continue

    if len(collected) < max_seeds:
        try:
            user = (
                f"Target: {target.language.value} project at {target.root}\n"
                f"Notes: {target.notes}\n"
                f"Generate up to {max(5, max_seeds - len(collected))} additional minimal seeds."
            )
            out = call_llm_json(_SYSTEM, user, max_tokens=2048)
            for i, s in enumerate(out.get("seeds", [])):
                if len(collected) >= max_seeds:
                    break
                name = s.get("name") or f"llm_{i}"
                blob = base64.b64decode(s["bytes_b64"])
                p = out_dir / f"llm_{name}"
                p.write_bytes(blob)
                collected.append(p)
        except Exception:
            pass  # best-effort
    return collected[:max_seeds]
