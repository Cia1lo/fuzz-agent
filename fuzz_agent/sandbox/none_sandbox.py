"""Passthrough sandbox provider for local development."""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .base import Sandbox


class NoSandbox(Sandbox):
    """Sandbox implementation that leaves commands unchanged."""

    name = "none"

    def wrap(
        self,
        cmd: list[str],
        *,
        mounts: Sequence[tuple[Path, Path, str]] = (),
        memory_mb: int | None = None,
        cpu_seconds: int | None = None,
        network: bool = False,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        return cmd

    def available(self) -> bool:
        return True
