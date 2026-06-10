"""mutate_strategy — adjust corpus / dictionary based on coverage analysis.

Calls coverage-analyst, writes any suggested seeds & dict additions next to the
active corpus, and persists an input model that can guide harness regeneration.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from ..subagents.coverage_analyst import run as coverage_analyst
from ._runtime import runtime


def mutate_strategy_impl(campaign_id: str, hint: str) -> dict[str, Any]:
    rt = runtime()
    paths = rt.store.paths(campaign_id)
    cfg = rt.store.campaign_config(campaign_id)
    source_root = _source_root_from_campaign(cfg, paths["base"])
    out = coverage_analyst(campaign_id, paths["coverage_uncovered"], source_root)
    input_model = _normal_input_model(out.get("input_model"))
    suggested_seeds = _combined_seed_suggestions(out, input_model)
    dict_additions = _combined_dict_additions(out, input_model)
    seen_seed_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths["corpus_dir"].rglob("*")
        if p.is_file()
    }

    added_seeds: list[str] = []
    for s in suggested_seeds:
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
    if dict_additions:
        with dict_path.open("a", encoding="utf-8") as f:
            for tok in dict_additions:
                token = str(tok).strip().strip('"')
                if not token or token in existing_tokens:
                    continue
                existing_tokens.add(token)
                added_tokens.append(token)
                f.write(f'"{token}"\n')

    input_model_path = paths["base"] / "input_model.json"
    if input_model:
        input_model_path.write_text(
            json.dumps(input_model, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    return {
        "campaign_id": campaign_id, "hint": hint,
        "added_seeds": added_seeds,
        "dict_additions": added_tokens,
        "dictionary_path": str(dict_path) if dict_path.exists() else None,
        "input_model_path": str(input_model_path) if input_model_path.exists() else None,
        "input_model": input_model,
        "harness_modeling_hint": _harness_modeling_hint(input_model),
        "uncovered_summary": out.get("uncovered", []),
    }


def _source_root_from_campaign(cfg: Any, fallback: Path) -> Path:
    if cfg is None:
        return fallback
    artifact = getattr(cfg, "artifact", None)
    for value in (
        getattr(artifact, "harness_source_path", None),
        getattr(artifact, "binary_path", None),
    ):
        if value is None:
            continue
        path = Path(value).resolve()
        for parent in [path.parent, *path.parents]:
            if parent.name == ".fuzz":
                return parent.parent
    return fallback


def _normal_input_model(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _combined_seed_suggestions(out: dict[str, Any], input_model: dict[str, Any]) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for raw in out.get("suggested_seeds", []):
        if isinstance(raw, dict):
            seeds.append(raw)
    for raw in input_model.get("seed_templates", []):
        if isinstance(raw, dict):
            seeds.append(raw)
    return _dedupe_dicts(seeds, key="bytes_b64")


def _combined_dict_additions(out: dict[str, Any], input_model: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for raw in out.get("dict_additions", []):
        if isinstance(raw, str):
            tokens.append(raw)
    for raw in input_model.get("tokens", []):
        if isinstance(raw, str):
            tokens.append(raw)
    seen: set[str] = set()
    deduped: list[str] = []
    for token in tokens:
        cleaned = token.strip().strip('"')
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped


def _dedupe_dicts(values: list[dict[str, Any]], *, key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for value in values:
        marker = str(value.get(key) or value)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(value)
    return out


def _harness_modeling_hint(input_model: dict[str, Any]) -> str:
    hint = input_model.get("harness_hint")
    if isinstance(hint, str) and hint.strip():
        return hint.strip()
    target_functions = input_model.get("target_functions", [])
    if not isinstance(target_functions, list) or not target_functions:
        return ""
    funcs = [
        str(row.get("func"))
        for row in target_functions
        if isinstance(row, dict) and row.get("func")
    ]
    tokens = [str(tok) for tok in input_model.get("tokens", []) if isinstance(tok, str)]
    parts = [f"Uncovered functions to model: {', '.join(funcs[:3])}."]
    if tokens:
        parts.append("Prefer seeds and harness fields that preserve: " + ", ".join(tokens[:5]) + ".")
    return " ".join(parts)
