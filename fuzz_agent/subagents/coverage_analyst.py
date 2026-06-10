"""coverage-analyst subagent: find uncovered code, suggest seeds & dict additions."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, cast

from ._llm import call_llm_json

_SYSTEM = """You analyze fuzz coverage. Output strict JSON only.
Schema: {
  "uncovered": [{"file": "...", "func": "...", "lines": "..."}],
  "suggested_seeds": [{"name": "...", "bytes_b64": "...", "reason": "..."}],
  "dict_additions": ["..."],
  "input_model": {
    "target_functions": [{"file": "...", "func": "...", "lines": "...", "signals": ["..."]}],
    "fields": [{"name": "...", "type": "...", "source": "...", "reason": "..."}],
    "tokens": ["..."],
    "seed_templates": [{"name": "...", "bytes_b64": "...", "reason": "..."}],
    "harness_hint": "...",
    "confidence": 0.0
  }
}
Be concise; max 5 entries per list. Prefer concrete input-structure hints that a
fuzz harness can implement, such as magic bytes, length-prefixed fields, type
tags, version bytes, checksums, varints, delimiters, and nested payload slices."""

_STRING_RE = re.compile(r'"((?:\\.|[^"\\]){1,64})"')
_CHAR_COMPARE_RE = re.compile(
    r"\b(?:data|buf|buffer|bytes|input|p)\s*\[\s*(?P<idx>\d+)\s*\]\s*==\s*"
    r"'(?P<char>(?:\\.|[^'\\]))'"
)
_SIZE_RE = re.compile(r"\b(?:size|len|length|n)\s*(?:>=|>)\s*(?P<num>\d+)")
_BYTE_COMPARE_RE = re.compile(
    r"\b(?:data|buf|buffer|bytes|input|p)\s*\[\s*(?P<idx>\d+)\s*\]\s*==\s*"
    r"(?P<num>0x[0-9a-fA-F]+|\d+)"
)
_FIELD_NAME_HINTS = (
    "magic", "header", "version", "type", "tag", "opcode", "length", "size",
    "payload", "checksum", "crc", "flags", "count", "varint",
)


def run(campaign_id: str, coverage_file: Path, source_root: Path) -> dict[str, Any]:
    uncovered = _read_uncovered(coverage_file)
    deterministic = _deterministic_analysis(uncovered, source_root)
    if coverage_file.suffix == ".json" and coverage_file.exists():
        cov = json.dumps({"uncovered": uncovered}, indent=2)
    else:
        summary = coverage_file
        if coverage_file.name == "coverage_uncovered.json":
            summary = coverage_file.with_name("coverage_summary.txt")
        cov = summary.read_text(errors="replace") if summary.exists() else ""
    if not cov.strip():
        deterministic["error"] = "no coverage data"
        return deterministic
    snippet = cov[:8000]
    user = (
        f"Campaign: {campaign_id}\nSource root: {source_root}\n"
        f"Coverage report (truncated):\n{snippet}\n\n"
        "Identify the most impactful uncovered branches and propose seeds that "
        "would reach them. Also infer a harness input model from uncovered "
        "function names and source-level branch constants. Return JSON only."
    )
    try:
        llm = cast(dict[str, Any], call_llm_json(_SYSTEM, user, max_tokens=2048))
        return _merge_analysis(deterministic, llm)
    except Exception as e:
        deterministic["error"] = str(e)
        return deterministic


def _read_uncovered(coverage_file: Path) -> list[dict[str, Any]]:
    if coverage_file.suffix != ".json" or not coverage_file.exists():
        return []
    try:
        payload = json.loads(coverage_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = payload.get("uncovered", [])
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _deterministic_analysis(
    uncovered: list[dict[str, Any]],
    source_root: Path,
) -> dict[str, Any]:
    target_functions: list[dict[str, Any]] = []
    fields: list[dict[str, str]] = []
    tokens: list[str] = []
    seed_templates: list[dict[str, str]] = []

    for row in uncovered[:10]:
        func = str(row.get("func") or "")
        file_value = str(row.get("file") or "")
        lines = str(row.get("lines") or "")
        source = _resolve_source(source_root, file_value)
        snippet = _source_snippet(source, lines, func)
        signals = _signals_for_function(func, snippet)
        target_functions.append({
            "file": file_value,
            "func": func,
            "lines": lines,
            "signals": signals[:8],
        })
        for token in _tokens_from_snippet(snippet):
            if token not in tokens:
                tokens.append(token)
        for field in _fields_from_signals(func, snippet):
            if field not in fields:
                fields.append(field)

    min_size = _largest_min_size_for_fields(fields)
    for token in tokens[:5]:
        blob = token.encode("utf-8", errors="ignore")
        if min_size and len(blob) < min_size:
            blob += b"\x00" * (min_size - len(blob))
        seed_templates.append({
            "name": _safe_name(f"model_{token}") or "model_seed",
            "bytes_b64": base64.b64encode(blob).decode("ascii"),
            "reason": f"exercise uncovered branch requiring token {token!r}",
        })

    harness_hint = _harness_hint(target_functions, fields, tokens)
    input_model = {
        "target_functions": target_functions[:5],
        "fields": fields[:8],
        "tokens": tokens[:12],
        "seed_templates": seed_templates[:5],
        "harness_hint": harness_hint,
        "confidence": _confidence(target_functions, fields, tokens),
    }
    return {
        "uncovered": uncovered[:5],
        "suggested_seeds": seed_templates[:5],
        "dict_additions": tokens[:12],
        "input_model": input_model,
    }


def _merge_analysis(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key in ("uncovered", "suggested_seeds", "dict_additions"):
        values = override.get(key)
        if isinstance(values, list) and values:
            merged[key] = _merge_lists(cast(list[Any], merged.get(key, [])), values)
    override_model = override.get("input_model")
    if isinstance(override_model, dict):
        base_model = cast(dict[str, Any], merged.get("input_model") or {})
        model = dict(base_model)
        for key in ("target_functions", "fields", "tokens", "seed_templates"):
            values = override_model.get(key)
            if isinstance(values, list) and values:
                model[key] = _merge_lists(cast(list[Any], model.get(key, [])), values)
        if isinstance(override_model.get("harness_hint"), str) and override_model["harness_hint"]:
            model["harness_hint"] = override_model["harness_hint"]
        confidence = override_model.get("confidence")
        if isinstance(confidence, (int, float)):
            model["confidence"] = max(float(model.get("confidence") or 0.0), float(confidence))
        merged["input_model"] = model
    return merged


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out[:12]


def _resolve_source(source_root: Path, file_value: str) -> Path | None:
    if not file_value:
        return None
    path = Path(file_value)
    if path.is_absolute() and path.exists():
        return path
    candidate = source_root / path
    if candidate.exists():
        return candidate
    matches = list(source_root.rglob(path.name)) if path.name else []
    return matches[0] if matches else None


def _source_snippet(source: Path | None, lines: str, func: str) -> str:
    if source is None or not source.exists():
        return ""
    try:
        all_lines = source.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start, end = _line_span(lines)
    if start <= 0:
        for idx, line in enumerate(all_lines, start=1):
            if func and re.search(rf"\b{re.escape(func)}\s*\(", line):
                start = idx
                end = idx + 20
                break
    start_idx = max(0, start - 8)
    end_idx = min(len(all_lines), max(end + 20, start + 40))
    return "\n".join(all_lines[start_idx:end_idx])


def _line_span(value: str) -> tuple[int, int]:
    match = re.match(r"(?P<start>\d+)(?:-(?P<end>\d+))?", value.strip())
    if match is None:
        return 0, 0
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    return start, end


def _signals_for_function(func: str, snippet: str) -> list[str]:
    signals: list[str] = []
    lower = f"{func}\n{snippet}".lower()
    for hint in _FIELD_NAME_HINTS:
        if hint in lower and hint not in signals:
            signals.append(hint)
    if _CHAR_COMPARE_RE.search(snippet):
        signals.append("byte_magic")
    if _SIZE_RE.search(snippet):
        signals.append("min_size")
    if ">>" in snippet or "<<" in snippet:
        signals.append("bit_fields")
    return signals


def _tokens_from_snippet(snippet: str) -> list[str]:
    tokens: list[str] = []
    for token in _char_sequence_tokens(snippet):
        if token not in tokens:
            tokens.append(token)
    for match in _STRING_RE.finditer(snippet):
        token = _decode_c_string(match.group(1))
        if _useful_token(token) and token not in tokens:
            tokens.append(token)
    for match in _BYTE_COMPARE_RE.finditer(snippet):
        value = int(match.group("num"), 0)
        if 32 <= value <= 126:
            token = chr(value)
            if token not in tokens:
                tokens.append(token)
    return tokens


def _char_sequence_tokens(snippet: str) -> list[str]:
    by_index: dict[int, str] = {}
    for match in _CHAR_COMPARE_RE.finditer(snippet):
        by_index[int(match.group("idx"))] = _decode_c_string(match.group("char"))
    if not by_index:
        return []
    tokens: list[str] = []
    current: list[str] = []
    expected: int | None = None
    for idx in sorted(by_index):
        if expected is None or idx == expected:
            current.append(by_index[idx])
        else:
            if len(current) >= 2:
                tokens.append("".join(current))
            current = [by_index[idx]]
        expected = idx + 1
    if len(current) >= 2:
        tokens.append("".join(current))
    return [token for token in tokens if _useful_token(token)]


def _fields_from_signals(func: str, snippet: str) -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []
    for match in _SIZE_RE.finditer(snippet):
        fields.append({
            "name": "min_size",
            "type": "integer",
            "source": match.group(0),
            "reason": "uncovered branch checks input length",
        })
    if _CHAR_COMPARE_RE.search(snippet):
        fields.append({
            "name": "magic",
            "type": "fixed_bytes",
            "source": func,
            "reason": "uncovered branch compares fixed byte positions",
        })
    lower = f"{func}\n{snippet}".lower()
    for name in ("version", "type", "tag", "flags", "checksum", "crc", "payload"):
        if name in lower:
            fields.append({
                "name": name,
                "type": "byte_or_slice" if name != "checksum" else "checksum",
                "source": func,
                "reason": f"uncovered code references {name}",
            })
    return fields


def _largest_min_size_for_fields(fields: list[dict[str, str]]) -> int | None:
    out: int | None = None
    for field in fields:
        if field.get("name") != "min_size":
            continue
        match = re.search(r"\d+", field.get("source", ""))
        if match:
            out = max(out or 0, int(match.group(0)))
    return out


def _harness_hint(
    target_functions: list[dict[str, Any]],
    fields: list[dict[str, str]],
    tokens: list[str],
) -> str:
    if not target_functions:
        return ""
    funcs = ", ".join(str(row.get("func") or "") for row in target_functions[:3])
    parts = [f"Uncovered functions suggest the harness should model input for: {funcs}."]
    if tokens:
        parts.append("Preserve or synthesize fixed tokens/magic bytes: " + ", ".join(repr(t) for t in tokens[:5]) + ".")
    names = [field["name"] for field in fields if field.get("name")]
    if names:
        parts.append("Split fuzz bytes into structured fields: " + ", ".join(dict.fromkeys(names)) + ".")
    parts.append(
        "When regenerating the harness, map early bytes to these fields before passing the remaining slice to the target."
    )
    return " ".join(parts)


def _confidence(
    target_functions: list[dict[str, Any]],
    fields: list[dict[str, str]],
    tokens: list[str],
) -> float:
    score = 0.0
    if target_functions:
        score += 0.2
    if fields:
        score += 0.3
    if tokens:
        score += 0.3
    if any(field.get("name") == "magic" for field in fields):
        score += 0.2
    return min(score, 1.0)


def _decode_c_string(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value


def _useful_token(value: str) -> bool:
    return 1 < len(value) <= 64 and any(ch.isalnum() for ch in value)


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")[:80]
