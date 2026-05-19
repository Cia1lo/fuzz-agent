"""coverage-analyst subagent: find uncovered code, suggest seeds & dict additions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from ._llm import call_llm_json

_SYSTEM = """You analyze fuzz coverage. Output strict JSON only.
Schema: {
  "uncovered": [{"file": "...", "func": "...", "lines": "..."}],
  "suggested_seeds": [{"name": "...", "bytes_b64": "...", "reason": "..."}],
  "dict_additions": ["..."]
}
Be concise; max 5 entries per list."""


def run(campaign_id: str, coverage_file: Path, source_root: Path) -> dict[str, Any]:
    if coverage_file.suffix == ".json" and coverage_file.exists():
        try:
            uncovered = json.loads(coverage_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            uncovered = []
        cov = json.dumps({"uncovered": uncovered}, indent=2)
    else:
        summary = coverage_file
        if coverage_file.name == "coverage_uncovered.json":
            summary = coverage_file.with_name("coverage_summary.txt")
        cov = summary.read_text(errors="replace") if summary.exists() else ""
    if not cov.strip():
        return {"uncovered": [], "suggested_seeds": [], "dict_additions": [],
                "error": "no coverage data"}
    snippet = cov[:8000]
    user = (
        f"Campaign: {campaign_id}\nSource root: {source_root}\n"
        f"Coverage report (truncated):\n{snippet}\n\n"
        "Identify the most impactful uncovered branches and propose seeds that "
        "would reach them. Return JSON only."
    )
    try:
        return cast(dict[str, Any], call_llm_json(_SYSTEM, user, max_tokens=2048))
    except Exception as e:
        return {"uncovered": [], "suggested_seeds": [], "dict_additions": [],
                "error": str(e)}
