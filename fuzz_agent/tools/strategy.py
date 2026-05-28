"""mutate_strategy — adjust corpus / dictionary based on coverage analysis.

Currently a placeholder that calls coverage-analyst, writes any suggested
seeds & dict additions next to the active corpus, and returns a summary.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from ..subagents.coverage_analyst import run as coverage_analyst
from ._runtime import runtime


def mutate_strategy_impl(campaign_id: str, hint: str) -> dict[str, Any]:
    rt = runtime()
    paths = rt.store.paths(campaign_id)
    out = coverage_analyst(campaign_id, paths["coverage_uncovered"], paths["base"])
    seen_seed_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths["corpus_dir"].rglob("*")
        if p.is_file()
    }

    added_seeds: list[str] = []
    for s in out.get("suggested_seeds", []):
        try:
            blob = base64.b64decode(s["bytes_b64"])
        except Exception:
            continue
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen_seed_hashes:
            continue
        seen_seed_hashes.add(digest)
        name = s.get("name", "seed").replace("/", "_")
        p = paths["corpus_dir"] / f"strategy_{name}"
        p.write_bytes(blob)
        added_seeds.append(p.name)

    dict_path = paths["base"] / "extra.dict"
    existing_tokens: set[str] = set()
    if dict_path.exists():
        for line in dict_path.read_text(encoding="utf-8").splitlines():
            token = line.strip().strip('"')
            if token:
                existing_tokens.add(token)
    added_tokens: list[str] = []
    if out.get("dict_additions"):
        with dict_path.open("a", encoding="utf-8") as f:
            for tok in out["dict_additions"]:
                token = str(tok).strip().strip('"')
                if not token or token in existing_tokens:
                    continue
                existing_tokens.add(token)
                added_tokens.append(token)
                f.write(f'"{token}"\n')

    return {
        "campaign_id": campaign_id, "hint": hint,
        "added_seeds": added_seeds,
        "dict_additions": added_tokens,
        "dictionary_path": str(dict_path) if dict_path.exists() else None,
        "uncovered_summary": out.get("uncovered", []),
    }
