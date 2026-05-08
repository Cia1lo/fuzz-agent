"""coverage-analyst subagent: find uncovered code, suggest seeds & dict additions."""
from __future__ import annotations

from pathlib import Path

from ._llm import call_claude_json

_SYSTEM = """You analyze fuzz coverage. Output strict JSON only.
Schema: {
  "uncovered": [{"file": "...", "func": "...", "lines": "..."}],
  "suggested_seeds": [{"name": "...", "bytes_b64": "...", "reason": "..."}],
  "dict_additions": ["..."]
}
Be concise; max 5 entries per list."""


def run(campaign_id: str, coverage_file: Path, source_root: Path) -> dict:
    cov = coverage_file.read_text(errors="replace") if coverage_file.exists() else ""
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
        return call_claude_json(_SYSTEM, user, max_tokens=2048)
    except Exception as e:
        return {"uncovered": [], "suggested_seeds": [], "dict_additions": [],
                "error": str(e)}
