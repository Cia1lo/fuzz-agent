"""Docker-based sandbox provider."""
from __future__ import annotations

import shutil
from pathlib import Path

from .base import Sandbox


class DockerSandbox(Sandbox):
    """Wrap commands with ``docker run``."""

    name = "docker"

    def __init__(self, image: str = "ubuntu:22.04", docker_bin: str = "docker") -> None:
        self.image = image
        self.docker_bin = docker_bin

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
        wrapped = [
            self.docker_bin,
            "run",
            "--rm",
            "-i",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev",
        ]
        if memory_mb is not None:
            wrapped += ["--memory", f"{memory_mb}m"]
        if cpu_seconds is not None:
            wrapped += ["--ulimit", f"cpu={cpu_seconds}"]
        if not network:
            wrapped += ["--network", "none"]
        for host_path, container_path, mode in mounts:
            if mode not in {"ro", "rw"}:
                raise ValueError(f"invalid mount mode: {mode}")
            wrapped += ["-v", f"{host_path}:{container_path}:{mode}"]
        for key, value in (env or {}).items():
            wrapped += ["-e", f"{key}={value}"]
        return wrapped + [self.image] + cmd

    def available(self) -> bool:
        return shutil.which(self.docker_bin) is not None
