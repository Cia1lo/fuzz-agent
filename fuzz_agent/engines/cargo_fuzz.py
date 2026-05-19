"""cargo-fuzz engine adapter for Rust fuzz targets."""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import subprocess
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional, TextIO, cast

from ..sandbox import NoSandbox, Sandbox
from ..state.models import (
    BuildArtifact,
    CampaignConfig,
    CampaignStats,
    CampaignStatus,
    EngineKind,
    EventKind,
    FuzzEvent,
    HarnessSpec,
    Language,
    Sanitizer,
)
from .base import FuzzEngine

_STATUS_RE = re.compile(
    r"#(?P<execs>\d+)\s+(?P<tag>\w+)\s+cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)\s+corp:\s*(?P<corp>\d+)"
)
_CRASH_HEADER_RE = re.compile(r"==\d+==ERROR: (?P<sanitizer>\w+Sanitizer): (?P<kind>[\w\-]+)")
_OOM_RE = re.compile(r"out-of-memory|libFuzzer: out-of-memory", re.IGNORECASE)
_TIMEOUT_RE = re.compile(r"libFuzzer: timeout", re.IGNORECASE)
_RUST_PANIC_RE = re.compile(r"\bpanicked at\b|thread '.*' panicked", re.IGNORECASE)
_HEARTBEAT_INTERVAL_SEC = 10


class CargoFuzzEngine(FuzzEngine):
    """Adapter around `cargo fuzz run` for Rust crates."""

    name = "cargo-fuzz"

    def __init__(self, sandbox: Sandbox | None = None) -> None:
        self._sandbox = sandbox or NoSandbox()
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._stats: dict[str, CampaignStats] = {}
        self._start_ts: dict[str, datetime] = {}
        self._last_coverage_ts: dict[str, datetime] = {}

    # ---------- build ----------
    def build(self, spec: HarnessSpec, out_dir: Path) -> BuildArtifact:
        if spec.target.language is not Language.RUST:
            raise RuntimeError(
                f"cargo-fuzz build only supports Rust targets, got {spec.target.language.value}"
            )
        if not spec.source_path.exists():
            raise FileNotFoundError(f"cargo-fuzz harness not found: {spec.source_path}")

        root = spec.target.root
        package_name, edition = _cargo_package(root)
        target_name = _target_name(spec.entry, spec.attempt)
        fuzz_target = root / "fuzz" / "fuzz_targets" / f"{target_name}.rs"
        log = out_dir / f"build_{spec.entry}_attempt_{spec.attempt}.log"

        out_dir.mkdir(parents=True, exist_ok=True)
        _ensure_fuzz_manifest(root, package_name, edition, target_name)
        fuzz_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(spec.source_path, fuzz_target)

        check_cmd = self._cargo_command(["fuzz", "--help"])
        build_cmd = self._cargo_command(["fuzz", "run", target_name, "--", "-runs=0"])
        with log.open("w", encoding="utf-8") as f:
            f.write("$ " + " ".join(shlex.quote(c) for c in check_cmd) + "\n")
            f.flush()
            r = subprocess.run(
                self._sandbox.wrap(
                    check_cmd,
                    mounts=self._mounts((root, root, "rw"), (out_dir, out_dir, "rw")),
                ),
                cwd=root,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
            if r.returncode != 0:
                raise RuntimeError(
                    "cargo-fuzz is not available; install it with "
                    "`cargo install cargo-fuzz`; see " + str(log)
                )

            f.write("$ " + " ".join(shlex.quote(c) for c in build_cmd) + "\n")
            f.flush()
            r = subprocess.run(
                self._sandbox.wrap(
                    build_cmd,
                    mounts=self._mounts((root, root, "rw"), (out_dir, out_dir, "rw")),
                ),
                cwd=root,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        if r.returncode != 0:
            raise RuntimeError(f"cargo-fuzz build failed; see {log}")

        return BuildArtifact(
            binary_path=fuzz_target,
            engine=EngineKind.CARGO_FUZZ,
            sanitizers=spec.sanitizers or [Sanitizer.ASAN],
            build_log_path=log,
            harness_source_path=fuzz_target,
        )

    # ---------- run ----------
    async def run(self, cfg: CampaignConfig) -> AsyncIterator[FuzzEvent]:
        cid = cfg.campaign_id or _target_name(cfg.artifact.binary_path.stem, 1)
        self._start_ts[cid] = datetime.now(timezone.utc)
        root = _crate_root_from_artifact(cfg.artifact)
        target_name = cfg.artifact.binary_path.stem
        libfuzzer_flags = [
            f"-max_total_time={cfg.time_budget_sec}",
            f"-rss_limit_mb={cfg.max_memory_mb}",
            f"-artifact_prefix={cfg.crash_dir}/",
            "-print_final_stats=1",
        ]
        if cfg.dictionary_path:
            libfuzzer_flags.append(f"-dict={cfg.dictionary_path}")
        libfuzzer_flags += list(cfg.extra_args)
        cmd = self._cargo_run_command(target_name, [cfg.corpus_dir], libfuzzer_flags)

        cfg.crash_dir.mkdir(parents=True, exist_ok=True)
        mounts = self._mounts(
            (root, root, "rw"),
            (cfg.corpus_dir, cfg.corpus_dir, "rw"),
            (cfg.crash_dir, cfg.crash_dir, "rw"),
        )
        if cfg.dictionary_path:
            mounts = self._mounts(
                *mounts,
                (cfg.dictionary_path.parent, cfg.dictionary_path.parent, "ro"),
            )
        wrapped = self._sandbox.wrap(cmd, mounts=mounts, memory_mb=cfg.max_memory_mb)

        run_log = cfg.crash_dir.parent / "run.log"
        run_log.parent.mkdir(parents=True, exist_ok=True)
        log_tail: list[str] = []
        proc = await asyncio.create_subprocess_exec(
            *wrapped,
            cwd=root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._procs[cid] = proc
        self._stats[cid] = self._empty_stats(cid)

        try:
            with run_log.open("a", encoding="utf-8") as log:
                log.write("$ " + _display_command(root, wrapped) + "\n")
                log.flush()
                async for ev in self._run_stdout_loop(cid, proc, log, log_tail):
                    yield ev
                rc = await proc.wait()
                self._stats[cid].status = (
                    CampaignStatus.STOPPED if rc == 0 else CampaignStatus.FAILED
                )
                self._refresh_elapsed(cid, datetime.now(timezone.utc))
                if rc != 0:
                    yield FuzzEvent(
                        kind=EventKind.ENGINE_ERROR,
                        campaign_id=cid,
                        ts=datetime.now(timezone.utc),
                        payload={
                            "returncode": rc,
                            "run_log": str(run_log),
                            "tail": "\n".join(log_tail[-40:]),
                        },
                    )
        finally:
            self._last_coverage_ts.pop(cid, None)
            self._procs.pop(cid, None)

    async def _run_stdout_loop(
        self,
        cid: str,
        proc: asyncio.subprocess.Process,
        log: TextIO,
        log_tail: list[str],
    ) -> AsyncIterator[FuzzEvent]:
        try:
            assert proc.stdout is not None
            while True:
                try:
                    line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=_HEARTBEAT_INTERVAL_SEC,
                    )
                except asyncio.TimeoutError:
                    yield self._heartbeat_event(cid)
                    continue

                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                log.write(text + "\n")
                log.flush()
                log_tail.append(text)
                if len(log_tail) > 200:
                    del log_tail[:100]
                ev = self._parse_line(cid, text)
                if ev is not None:
                    yield ev
        except asyncio.CancelledError:
            raise

    async def stop(self, campaign_id: str) -> None:
        proc = self._procs.get(campaign_id)
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()

    def stats(self, campaign_id: str) -> CampaignStats:
        return self._stats.get(campaign_id) or self._empty_stats(campaign_id)

    # ---------- parsing ----------
    def _parse_line(self, cid: str, line: str) -> Optional[FuzzEvent]:
        st = self._stats.setdefault(cid, self._empty_stats(cid))
        now = datetime.now(timezone.utc)
        self._refresh_elapsed(cid, now)

        m = _STATUS_RE.search(line)
        if m:
            execs = int(m.group("execs"))
            cov = int(m.group("cov"))
            corp = int(m.group("corp"))
            prev_cov = st.edges_covered
            st.execs_total = execs
            st.execs_per_sec = execs / max(st.elapsed_sec, 1)
            st.edges_covered = cov
            st.corpus_size = corp
            st.status = CampaignStatus.RUNNING
            st.last_event_ts = now
            if cov > prev_cov:
                self._last_coverage_ts[cid] = now
                st.last_new_coverage_sec_ago = 0
                return FuzzEvent(
                    kind=EventKind.NEW_COVERAGE,
                    campaign_id=cid,
                    ts=now,
                    payload={"edges": cov, "delta": cov - prev_cov, "execs": execs},
                )
            self._refresh_coverage_idle(cid, now)
            return None

        m = _CRASH_HEADER_RE.search(line)
        if m:
            st.unique_crashes += 1
            return FuzzEvent(
                kind=EventKind.NEW_CRASH,
                campaign_id=cid,
                ts=now,
                payload={
                    "sanitizer": m.group("sanitizer"),
                    "kind": m.group("kind"),
                    "raw": line[:500],
                },
            )

        if _RUST_PANIC_RE.search(line):
            st.unique_crashes += 1
            return FuzzEvent(
                kind=EventKind.NEW_CRASH,
                campaign_id=cid,
                ts=now,
                payload={"sanitizer": "rust", "kind": "panic", "raw": line[:500]},
            )
        if _OOM_RE.search(line):
            return FuzzEvent(kind=EventKind.OOM, campaign_id=cid, ts=now, payload={"raw": line[:500]})
        if _TIMEOUT_RE.search(line):
            return FuzzEvent(
                kind=EventKind.TIMEOUT,
                campaign_id=cid,
                ts=now,
                payload={"raw": line[:500]},
            )
        return None

    def _heartbeat_event(self, cid: str) -> FuzzEvent:
        now = datetime.now(timezone.utc)
        st = self._stats.setdefault(cid, self._empty_stats(cid))
        if st.status not in (CampaignStatus.STOPPED, CampaignStatus.FAILED):
            st.status = CampaignStatus.RUNNING
        st.last_event_ts = now
        self._refresh_elapsed(cid, now)
        self._refresh_coverage_idle(cid, now)
        return FuzzEvent(
            kind=EventKind.HEARTBEAT,
            campaign_id=cid,
            ts=now,
            payload={
                "elapsed_sec": st.elapsed_sec,
                "execs_total": st.execs_total,
                "edges_covered": st.edges_covered,
                "unique_crashes": st.unique_crashes,
            },
        )

    def _refresh_elapsed(self, cid: str, now: datetime) -> None:
        start = self._start_ts.get(cid, now)
        self._stats[cid].elapsed_sec = int((now - start).total_seconds())

    def _refresh_coverage_idle(self, cid: str, now: datetime) -> None:
        last_coverage = self._last_coverage_ts.get(cid)
        if last_coverage is None:
            return
        self._stats[cid].last_new_coverage_sec_ago = int(
            (now - last_coverage).total_seconds()
        )

    @staticmethod
    def _empty_stats(cid: str) -> CampaignStats:
        return CampaignStats(
            campaign_id=cid,
            status=CampaignStatus.PENDING,
            elapsed_sec=0,
            execs_total=0,
            execs_per_sec=0.0,
            edges_covered=0,
            edges_total=None,
            corpus_size=0,
            unique_crashes=0,
            last_new_coverage_sec_ago=None,
        )

    # ---------- triage ----------
    def minimize(
        self,
        artifact: BuildArtifact,
        input_path: Path,
        out_path: Path,
        timeout_sec: int = 60,
    ) -> Path:
        root = _crate_root_from_artifact(artifact)
        cmd = self._cargo_run_command(
            artifact.binary_path.stem,
            [input_path],
            ["-minimize_crash=1", f"-exact_artifact_path={out_path}"],
        )
        wrapped = self._sandbox.wrap(
            cmd,
            mounts=self._mounts(
                (root, root, "rw"),
                (input_path.parent, input_path.parent, "ro"),
                (out_path.parent, out_path.parent, "rw"),
            ),
            cpu_seconds=timeout_sec,
        )
        subprocess.run(wrapped, cwd=root, capture_output=True, timeout=timeout_sec)
        return out_path if out_path.exists() else input_path

    def reproduce(
        self,
        artifact: BuildArtifact,
        input_path: Path,
        timeout_sec: int = 30,
    ) -> Optional[str]:
        root = _crate_root_from_artifact(artifact)
        cmd = self._cargo_run_command(artifact.binary_path.stem, [input_path], ["-runs=1"])
        wrapped = self._sandbox.wrap(
            cmd,
            mounts=self._mounts(
                (root, root, "rw"),
                (input_path.parent, input_path.parent, "ro"),
            ),
            cpu_seconds=timeout_sec,
        )
        try:
            r = subprocess.run(wrapped, cwd=root, capture_output=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            return "timeout"
        out = (r.stdout + r.stderr).decode("utf-8", errors="replace")
        return out if r.returncode != 0 or _looks_like_crash(out) else None

    def _cargo_command(self, args: list[str]) -> list[str]:
        return [os.environ.get("FUZZ_AGENT_CARGO", "cargo"), *args]

    def _cargo_run_command(
        self,
        target_name: str,
        inputs: list[Path],
        libfuzzer_flags: list[str],
    ) -> list[str]:
        return self._cargo_command(
            ["fuzz", "run", target_name, *(str(p) for p in inputs), "--", *libfuzzer_flags]
        )

    @staticmethod
    def _mounts(*mounts: tuple[Path, Path, str]) -> list[tuple[Path, Path, str]]:
        merged: dict[tuple[Path, Path], str] = {}
        for host_path, container_path, mode in mounts:
            host = host_path.resolve()
            container = container_path.resolve()
            key = (host, container)
            merged[key] = "rw" if mode == "rw" or merged.get(key) == "rw" else "ro"
        return [(host, container, mode) for (host, container), mode in merged.items()]


def _cargo_package(root: Path) -> tuple[str, str]:
    manifest = root / "Cargo.toml"
    if not manifest.exists():
        raise RuntimeError(f"Cargo.toml not found at {manifest}")
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    package = cast(dict[str, Any] | None, data.get("package"))
    if not package:
        raise RuntimeError("cargo-fuzz integration needs a concrete Rust package manifest")
    name = package.get("name")
    if not isinstance(name, str) or not name:
        raise RuntimeError("Cargo.toml [package].name is missing")
    edition = package.get("edition")
    if not isinstance(edition, str) or not edition:
        edition = "2021"
    return name, edition


def _ensure_fuzz_manifest(root: Path, package_name: str, edition: str, target_name: str) -> None:
    fuzz_dir = root / "fuzz"
    target_dir = fuzz_dir / "fuzz_targets"
    target_dir.mkdir(parents=True, exist_ok=True)
    manifest = fuzz_dir / "Cargo.toml"
    bin_block = _bin_block(target_name)
    if not manifest.exists():
        manifest.write_text(
            "\n".join(
                [
                    "[package]",
                    f'name = "{package_name}-fuzz"',
                    'version = "0.0.0"',
                    "publish = false",
                    f'edition = "{edition}"',
                    "",
                    "[package.metadata]",
                    "cargo-fuzz = true",
                    "",
                    "[dependencies]",
                    'libfuzzer-sys = "0.4"',
                    f'{package_name} = {{ path = ".." }}',
                    "",
                    "[workspace]",
                    "",
                    bin_block.rstrip(),
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return

    text = manifest.read_text(encoding="utf-8")
    if f'name = "{target_name}"' not in text:
        manifest.write_text(text.rstrip() + "\n\n" + bin_block, encoding="utf-8")


def _bin_block(target_name: str) -> str:
    return "\n".join(
        [
            "[[bin]]",
            f'name = "{target_name}"',
            f'path = "fuzz_targets/{target_name}.rs"',
            "test = false",
            "doc = false",
            "bench = false",
            "",
        ]
    )


def _target_name(entry: str, attempt: int) -> str:
    base = re.sub(r"\W+", "_", entry).strip("_") or "target"
    if not re.match(r"^[A-Za-z_]", base):
        base = f"fuzz_{base}"
    return f"{base}_attempt_{attempt}"


def _crate_root_from_artifact(artifact: BuildArtifact) -> Path:
    target = artifact.binary_path
    if target.parent.name == "fuzz_targets" and target.parent.parent.name == "fuzz":
        return target.parent.parent.parent
    raise RuntimeError(
        "cargo-fuzz artifact must point to <crate>/fuzz/fuzz_targets/<target>.rs"
    )


def _looks_like_crash(output: str) -> bool:
    return bool(
        _CRASH_HEADER_RE.search(output)
        or _RUST_PANIC_RE.search(output)
        or _OOM_RE.search(output)
        or _TIMEOUT_RE.search(output)
    )


def _display_command(root: Path, cmd: list[str]) -> str:
    return "(cd " + shlex.quote(str(root)) + " && " + " ".join(shlex.quote(c) for c in cmd) + ")"
