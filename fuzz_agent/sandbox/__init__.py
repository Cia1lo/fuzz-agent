"""Sandbox providers for wrapping fuzzing subprocesses."""
from __future__ import annotations

import os

from .base import Sandbox
from .docker import DockerSandbox
from .none_sandbox import NoSandbox
from .nsjail import NsjailSandbox


def select(name: str | None) -> Sandbox:
    """Return the configured sandbox provider."""
    selected = (name or os.environ.get("FUZZ_AGENT_SANDBOX") or "none").lower()
    if selected == "none":
        return NoSandbox()
    if selected == "docker":
        return DockerSandbox()
    if selected == "nsjail":
        return NsjailSandbox()
    raise ValueError(f"unknown sandbox provider: {selected}")


__all__ = [
    "Sandbox",
    "NoSandbox",
    "DockerSandbox",
    "NsjailSandbox",
    "select",
]
