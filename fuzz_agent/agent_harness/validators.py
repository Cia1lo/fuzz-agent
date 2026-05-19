"""Validation helpers for separating agent/harness failures from target findings."""
from __future__ import annotations

import re
from pathlib import Path

from ..state.models import BuildArtifact, CrashRecord, HarnessSpec
from .observation import AgentStepScore, ValidationResult


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


def validate_target_reached_from_frames(entry: str, frames: list[str]) -> ValidationResult:
    """Check stack/symbol frames for the expected target entry."""
    for frame in frames:
        if entry in frame:
            return ValidationResult("target_reached", True, f"matched frame: {frame}")
    return ValidationResult("target_reached", False, f"entry {entry} not found in frames")


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
