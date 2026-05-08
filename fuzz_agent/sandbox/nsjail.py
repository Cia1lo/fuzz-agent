"""nsjail-based sandbox provider."""
from __future__ import annotations

import shutil
from pathlib import Path

from .base import Sandbox


class NsjailSandbox(Sandbox):
    """Wrap commands with ``nsjail``."""

    name = "nsjail"

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
        wrapped = ["nsjail", "-Mo"]
        if cpu_seconds is not None:
            wrapped += ["--time_limit", str(cpu_seconds)]
        if memory_mb is not None:
            wrapped += ["--rlimit_as", f"{memory_mb}M"]
        for host_path, container_path, mode in mounts:
            if mode == "ro":
                wrapped += ["--bindmount_ro", f"{host_path}:{container_path}"]
            elif mode == "rw":
                wrapped += ["--bindmount", f"{host_path}:{container_path}"]
            else:
                raise ValueError(f"invalid mount mode: {mode}")
        if network:
            wrapped.append("--disable_clone_newnet")
        for key, value in (env or {}).items():
            wrapped += ["--env", f"{key}={value}"]
        return wrapped + ["--"] + cmd

    def available(self) -> bool:
        return shutil.which("nsjail") is not None
