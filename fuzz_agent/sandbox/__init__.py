"""Sandbox providers for wrapping fuzzing subprocesses."""
from __future__ import annotations

import os
import logging

from .base import Sandbox
from .docker import DockerSandbox
from .none_sandbox import NoSandbox
from .nsjail import NsjailSandbox


def select(name: str | None) -> Sandbox:
    """Return the configured sandbox provider."""
    selected = (name or os.environ.get("FUZZ_AGENT_SANDBOX") or "none").lower()
    if selected == "none":
        logging.getLogger(__name__).warning(
            "FUZZ_AGENT_SANDBOX=none runs fuzz targets without process isolation",
        )
        return NoSandbox()
    if selected == "docker":
        provider: Sandbox = DockerSandbox()
        if not provider.available():
            raise RuntimeError("FUZZ_AGENT_SANDBOX=docker selected but docker is not on PATH")
        return provider
    if selected == "nsjail":
        provider = NsjailSandbox()
        if not provider.available():
            raise RuntimeError("FUZZ_AGENT_SANDBOX=nsjail selected but nsjail is not on PATH")
        return provider
    raise ValueError(f"unknown sandbox provider: {selected}")


__all__ = [
    "Sandbox",
    "NoSandbox",
    "DockerSandbox",
    "NsjailSandbox",
    "select",
]
