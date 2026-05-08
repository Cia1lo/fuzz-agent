"""mutate_strategy — adjust corpus / dictionary based on coverage analysis.

Currently a placeholder that calls coverage-analyst, writes any suggested
seeds & dict additions next to the active corpus, and returns a summary.
"""
from __future__ import annotations

import base64

from ..subagents import coverage_analyst
from ._runtime import runtime


def mutate_strategy_impl(campaign_id: str, hint: str) -> dict:
    rt = runtime()
    paths = rt.store.paths(campaign_id)
    out = coverage_analyst(campaign_id, paths["coverage"], paths["base"])

    added_seeds: list[str] = []
    for s in out.get("suggested_seeds", []):
        try:
            blob = base64.b64decode(s["bytes_b64"])
        except Exception:
            continue
        name = s.get("name", "seed").replace("/", "_")
        p = paths["corpus_dir"] / f"strategy_{name}"
        p.write_bytes(blob)
        added_seeds.append(p.name)

    dict_path = paths["base"] / "extra.dict"
    if out.get("dict_additions"):
        with dict_path.open("a", encoding="utf-8") as f:
            for tok in out["dict_additions"]:
                f.write(f'"{tok}"\n')

    return {
        "campaign_id": campaign_id, "hint": hint,
        "added_seeds": added_seeds,
        "dict_additions": out.get("dict_additions", []),
        "uncovered_summary": out.get("uncovered", []),
    }
