"""Sandbox interface for wrapping subprocess command lines."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class Sandbox(ABC):
    """Base class for subprocess sandbox providers."""

    name: str

    @abstractmethod
    def wrap(
        self,
        cmd: list[str],
        *,
        mounts: list[tuple[Path, Path, str]] = (),
        memory_mb: int | None = None,
        cpu_seconds: int | None = None,
        network: bool = False,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        """Return the command list with sandbox prefix applied."""

    @abstractmethod
    def available(self) -> bool:
        """Return whether the underlying sandbox tool is available on PATH."""
