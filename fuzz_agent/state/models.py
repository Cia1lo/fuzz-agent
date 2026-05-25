"""Core data models — the shared vocabulary across all layers.

These types are the *contract* between Orchestrator, Tool Layer, Subagents,
and the Engine adapters. Implementation layers depend on these models, never
the other way around.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Language(str, Enum):
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    PYTHON = "python"
    JAVA = "java"
    UNKNOWN = "unknown"


class EngineKind(str, Enum):
    LIBFUZZER = "libfuzzer"
    CARGO_FUZZ = "cargo-fuzz"
    AFLPP = "aflpp"
    GO_NATIVE = "go_native"
    ATHERIS = "atheris"
    JAZZER = "jazzer"


class Sanitizer(str, Enum):
    ASAN = "asan"
    UBSAN = "ubsan"
    MSAN = "msan"
    TSAN = "tsan"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CrashStatus(str, Enum):
    UNCONFIRMED = "unconfirmed"
    CONFIRMED = "confirmed"
    FLAKY = "flaky"
    NON_REPRODUCIBLE = "non_reproducible"


# ---------- Target / Harness ----------

@dataclass
class TargetProfile:
    """Result of analyze_target — what we know about the fuzzee."""
    root: Path
    language: Language
    entry_points: list[str]                 # e.g. ["parse_json", "decode_frame"]
    build_system: str                       # cmake / cargo / go / make / ...
    dependencies: list[str] = field(default_factory=list)
    notes: str = ""                         # free-form LLM notes


@dataclass
class HarnessSpec:
    """A fuzz harness ready to be built."""
    target: TargetProfile
    entry: str                              # which entry point this harness drives
    engine: EngineKind
    source_path: Path                       # generated harness source
    dictionary_path: Optional[Path] = None
    sanitizers: list[Sanitizer] = field(default_factory=lambda: [Sanitizer.ASAN, Sanitizer.UBSAN])
    invariants: list[str] = field(default_factory=list)  # round-trip, differential, ...
    extra_sources: list[Path] = field(default_factory=list)
    compile_flags: list[str] = field(default_factory=list)
    link_flags: list[str] = field(default_factory=list)
    attempt: int = 1


@dataclass
class BuildArtifact:
    """Output of build_target."""
    binary_path: Path
    engine: EngineKind
    sanitizers: list[Sanitizer]
    build_log_path: Path
    harness_source_path: Optional[Path] = None


# ---------- Campaign ----------

class CampaignStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class CampaignConfig:
    artifact: BuildArtifact
    corpus_dir: Path
    crash_dir: Path
    dictionary_path: Optional[Path]
    time_budget_sec: int
    max_memory_mb: int = 2048
    extra_args: list[str] = field(default_factory=list)
    campaign_id: Optional[str] = None
    resumed_from: Optional[str] = None


@dataclass
class CampaignStats:
    """Lightweight snapshot — safe to feed back to the LLM frequently."""
    campaign_id: str
    status: CampaignStatus
    elapsed_sec: int
    execs_total: int
    execs_per_sec: float
    edges_covered: int
    edges_total: Optional[int]
    corpus_size: int
    unique_crashes: int
    last_new_coverage_sec_ago: Optional[int]
    last_event_ts: Optional[datetime] = None


# ---------- Crashes ----------

@dataclass
class VulnerabilityMatch:
    """A rule-based vulnerability classification for a crash."""
    rule_id: str
    title: str
    cwe: Optional[str]
    confidence: float
    evidence: list[str] = field(default_factory=list)
    source: str = "builtin"


@dataclass
class CrashRecord:
    crash_id: str                           # content-addressed (hash of minimized input)
    campaign_id: str
    input_path: Path
    minimized_path: Optional[Path]
    stack_hash: str                         # for dedup
    top_frames: list[str]                   # top N stack frames
    sanitizer_kind: Optional[str]           # heap-buffer-overflow, etc.
    discovered_at: datetime
    severity: Optional[Severity] = None
    exploitability_notes: str = ""
    status: CrashStatus = CrashStatus.UNCONFIRMED
    reproducible: Optional[bool] = None
    reproduce_log_path: Optional[Path] = None
    vulnerability_matches: list[VulnerabilityMatch] = field(default_factory=list)


# ---------- Events ----------

class EventKind(str, Enum):
    NEW_COVERAGE = "new_coverage"
    NEW_CRASH = "new_crash"
    PLATEAU = "plateau"
    OOM = "oom"
    TIMEOUT = "timeout"
    ENGINE_ERROR = "engine_error"
    HEARTBEAT = "heartbeat"


@dataclass
class FuzzEvent:
    kind: EventKind
    campaign_id: str
    ts: datetime
    payload: dict[str, Any]                 # kind-specific (see docs in events/stream.py)
