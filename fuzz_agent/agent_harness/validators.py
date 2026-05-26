"""Validation helpers for separating agent/harness failures from target findings."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..state.models import BuildArtifact, CrashRecord, EngineKind, HarnessSpec
from .observation import AgentStepScore, ValidationResult

_BUILD_FAILURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("missing_include", re.compile(r"fatal error: ['<](?P<symbol>[^'>]+)['>] file not found")),
    ("undefined_symbol", re.compile(r"undefined (?:reference|symbol).*?(?P<symbol>[A-Za-z_]\w*)")),
    ("signature_mismatch", re.compile(r"(?:no matching function|too (?:few|many) arguments|cannot convert)")),
    ("missing_type", re.compile(r"(?:unknown type name|does not name a type) ['`]?(?P<symbol>[A-Za-z_]\w*)")),
)


def validate_build_artifact(spec: HarnessSpec, artifact: BuildArtifact) -> list[ValidationResult]:
    """Check that a successful build returned usable, inspectable artifacts."""
    results = [
        ValidationResult(
            name="harness_source_exists",
            passed=spec.source_path.exists(),
            detail=str(spec.source_path),
        ),
        ValidationResult(
            name="build_log_exists",
            passed=artifact.build_log_path.exists(),
            detail=str(artifact.build_log_path),
        ),
        ValidationResult(
            name="artifact_exists",
            passed=artifact.binary_path.exists(),
            detail=str(artifact.binary_path),
        ),
    ]
    if artifact.harness_source_path is not None:
        results.append(
            ValidationResult(
                name="artifact_harness_source_exists",
                passed=artifact.harness_source_path.exists(),
                detail=str(artifact.harness_source_path),
            )
        )
    return results


def classify_build_failure(log_text: str) -> dict[str, str]:
    """Classify common compiler/linker failures from a build log tail."""
    for kind, pattern in _BUILD_FAILURE_PATTERNS:
        match = pattern.search(log_text)
        if match is None:
            continue
        symbol = match.groupdict().get("symbol") or ""
        return {
            "kind": kind,
            "symbol": symbol,
            "hint": _build_failure_hint(kind, symbol),
        }
    return {"kind": "unknown", "symbol": "", "hint": "inspect build log tail"}


def score_build_attempt(
    *,
    compiled: bool,
    source_path: Path | None,
    build_log_path: Path | None,
    artifact_path: Path | None,
    validations: list[ValidationResult],
) -> AgentStepScore:
    """Build a compact score from concrete filesystem and validation feedback."""
    failed = {v.name for v in validations if not v.passed}
    smoke = next((v for v in validations if v.name == "smoke_run"), None)
    target = next((v for v in validations if v.name == "target_reached"), None)
    return AgentStepScore(
        compiled=compiled,
        smoke_passed=smoke.passed if smoke is not None else None,
        target_reached=target.passed if target is not None else None,
        build_log_available=bool(build_log_path and build_log_path.exists())
        and "build_log_exists" not in failed,
        harness_source_available=bool(source_path and source_path.exists())
        and "harness_source_exists" not in failed,
        artifact_available=bool(artifact_path and artifact_path.exists())
        and "artifact_exists" not in failed,
    )


def _build_failure_hint(kind: str, symbol: str) -> str:
    if kind == "missing_include":
        return f"include or expose header for {symbol}" if symbol else "add missing include path"
    if kind == "undefined_symbol":
        return f"link target object or library that defines {symbol}" if symbol else "add missing link input"
    if kind == "signature_mismatch":
        return "adjust harness call to the target function signature"
    if kind == "missing_type":
        return f"include declaration for type {symbol}" if symbol else "include missing type declaration"
    return "inspect build log tail"


def validate_target_referenced_by_harness(spec: HarnessSpec) -> ValidationResult:
    """Check that the generated harness source appears to call the selected entry."""
    try:
        source = spec.source_path.read_text(errors="replace")
    except OSError as exc:
        return ValidationResult("target_reached", False, f"cannot read harness source: {exc}")
    if re.search(rf"\b{re.escape(spec.entry)}\s*\(", source):
        return ValidationResult(
            "target_reached",
            True,
            f"harness source references entry {spec.entry}",
        )
    return ValidationResult(
        "target_reached",
        False,
        f"harness source does not reference entry {spec.entry}",
    )


def validate_target_reached_by_artifact(
    spec: HarnessSpec,
    artifact: BuildArtifact,
) -> ValidationResult:
    """Check source reachability and, when possible, linked binary symbol evidence."""
    source_check = validate_target_referenced_by_harness(spec)
    if not source_check.passed:
        return source_check

    coverage_check = validate_target_reached_from_coverage_artifacts(
        spec.entry,
        _coverage_artifact_candidates(artifact),
    )
    if coverage_check is not None:
        return coverage_check

    runtime_check = _entry_runtime_coverage_evidence(spec.entry, artifact)
    if runtime_check:
        return ValidationResult(
            "target_reached",
            True,
            source_check.detail + "; runtime coverage output mentions target entry",
        )

    symbol_check = _entry_symbol_evidence(spec.entry, artifact.binary_path)
    if symbol_check is None:
        return ValidationResult(
            "target_reached",
            True,
            source_check.detail + "; binary symbol evidence unavailable",
        )
    if symbol_check:
        return ValidationResult(
            "target_reached",
            True,
            source_check.detail + "; linked artifact contains target symbol",
        )
    return ValidationResult(
        "target_reached",
        False,
        source_check.detail + "; linked artifact does not expose target symbol",
    )


def validate_target_reached_from_frames(entry: str, frames: list[str]) -> ValidationResult:
    """Check stack/symbol frames for the expected target entry."""
    for frame in frames:
        if entry in frame:
            return ValidationResult("target_reached", True, f"matched frame: {frame}")
    return ValidationResult("target_reached", False, f"entry {entry} not found in frames")


def validate_target_reached_from_coverage_artifacts(
    entry: str,
    paths: list[Path],
) -> ValidationResult | None:
    """Use persisted coverage files when they explicitly mention the selected entry."""
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        try:
            if path.suffix == ".json":
                if _entry_is_uncovered(entry, path):
                    return ValidationResult(
                        "target_reached",
                        False,
                        f"coverage artifact marks entry {entry} as uncovered: {path}",
                    )
                continue
            text = path.read_text(errors="replace")
        except (OSError, json.JSONDecodeError):
            continue
        if _coverage_text_marks_entry_covered(entry, text):
            return ValidationResult(
                "target_reached",
                True,
                f"coverage artifact mentions covered entry {entry}: {path}",
            )
    return None


def _entry_symbol_evidence(entry: str, binary_path: Path) -> bool | None:
    nm = shutil.which("nm")
    if nm is None or not binary_path.exists() or not binary_path.is_file():
        return None
    try:
        result = subprocess.run(
            [nm, "-C", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return bool(re.search(rf"\b{re.escape(entry)}\b", result.stdout))


def _coverage_artifact_candidates(artifact: BuildArtifact) -> list[Path]:
    dirs = [
        artifact.binary_path.parent,
        artifact.binary_path.parent.parent,
    ]
    names = ["coverage_summary.txt", "coverage_uncovered.json"]
    out: list[Path] = []
    for directory in dirs:
        for name in names:
            path = directory / name
            if path not in out:
                out.append(path)
    return out


def _entry_is_uncovered(entry: str, path: Path) -> bool:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return False
    for item in payload:
        if not isinstance(item, dict):
            continue
        func = item.get("func")
        if isinstance(func, str) and _entry_name_matches(entry, func):
            return True
    return False


def _coverage_text_marks_entry_covered(entry: str, text: str) -> bool:
    uncovered = False
    for line in text.splitlines():
        if line.strip().lower().startswith("uncovered functions"):
            uncovered = True
            continue
        if _entry_name_matches(entry, line):
            return not uncovered
    return False


def _entry_name_matches(entry: str, text: str) -> bool:
    return bool(re.search(rf"\b{re.escape(entry)}\b", text))


def _entry_runtime_coverage_evidence(entry: str, artifact: BuildArtifact) -> bool | None:
    if artifact.engine is not EngineKind.LIBFUZZER:
        return None
    binary_path = artifact.binary_path
    if not binary_path.exists() or not os.access(binary_path, os.X_OK):
        return None
    try:
        result = subprocess.run(
            [str(binary_path), "-runs=1", "-print_coverage=1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    if entry in output and ("COVERED" in output or "INITED" in output):
        return True
    return None


def validate_crash_not_from_harness(
    crash: CrashRecord,
    harness_source_path: Path | None,
    report: str | None = None,
) -> ValidationResult:
    """Flag crashes whose evidence points at the generated harness itself."""
    if harness_source_path is None:
        return ValidationResult("crash_not_from_harness", True, "no harness source path")

    markers = {
        str(harness_source_path),
        harness_source_path.name,
        harness_source_path.stem,
        "LLVMFuzzerTestOneInput",
        "fuzz_target",
    }
    first_frame = crash.top_frames[0] if crash.top_frames else ""
    evidence = "\n".join([first_frame, *(crash.top_frames[:5]), report or ""])
    rust_harness_panic = (
        ("panicked at" in evidence or "assertion failed" in evidence)
        and _frame_mentions_any(evidence, markers)
    )
    if _frame_mentions_any(first_frame, markers) or rust_harness_panic:
        return ValidationResult(
            "crash_not_from_harness",
            False,
            f"crash evidence appears to be harness-owned: {first_frame or 'no top frame'}",
        )
    return ValidationResult("crash_not_from_harness", True, "top frame is not harness-owned")


def _frame_mentions_any(frame: str, markers: set[str]) -> bool:
    return any(marker and marker in frame for marker in markers)
