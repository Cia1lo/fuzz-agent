"""FuzzEngine abstraction — adapters wrap LibFuzzer / AFL++ / etc behind one interface.

Each adapter must:
  1. Build a harness into a runnable artifact (build).
  2. Launch a long-running fuzz process (start) and yield it as an event source.
  3. Expose minimization and triage primitives (minimize, reproduce).

The Orchestrator never spawns engine subprocesses directly — it goes through
this interface so the higher layers stay engine-agnostic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator, Optional

from ..state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStats,
    FuzzEvent,
    HarnessSpec,
)


class FuzzEngine(ABC):
    """One adapter per fuzz engine."""

    name: str  # "libfuzzer", "aflpp", ...

    # ---- build ----
    @abstractmethod
    def build(self, spec: HarnessSpec, out_dir: Path) -> BuildArtifact:
        """Compile a harness into a runnable fuzz binary."""

    # ---- run ----
    @abstractmethod
    def run(self, cfg: CampaignConfig) -> AsyncIterator[FuzzEvent]:
        """Start the campaign and yield FuzzEvents as they arrive.

        Implementations must:
          - Tail engine stdout/stderr line-buffered.
          - Translate engine-specific lines into typed FuzzEvents.
          - Emit HEARTBEAT periodically (>= every 10s) so the orchestrator
            can detect stalls.
          - Exit cleanly when time_budget_sec elapses or stop() is called.
        """

    @abstractmethod
    async def stop(self, campaign_id: str) -> None:
        """Stop a running campaign gracefully."""

    @abstractmethod
    def stats(self, campaign_id: str) -> CampaignStats:
        """Cheap snapshot — must be safe to call often."""

    # ---- triage primitives ----
    @abstractmethod
    def minimize(self, artifact: BuildArtifact, input_path: Path,
                 out_path: Path, timeout_sec: int = 60) -> Path:
        """Shrink an input while preserving its crash signature."""

    @abstractmethod
    def reproduce(self, artifact: BuildArtifact, input_path: Path,
                  timeout_sec: int = 30) -> Optional[str]:
        """Re-run a single input. Returns sanitizer report text on crash, else None."""
