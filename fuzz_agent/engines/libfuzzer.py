"""LibFuzzer engine adapter.

Compiles a harness with clang+sanitizers, runs the resulting binary, and
translates its stdout into typed FuzzEvents. This is the reference engine —
other adapters (AFL++, Atheris, Jazzer) follow the same shape.
"""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

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
    Sanitizer,
)
from .base import FuzzEngine
from .coverage import CoverageBuilder

# libFuzzer status line:  #1234 NEW    cov: 567 ft: 890 corp: 12/345b ...
_STATUS_RE = re.compile(
    r"#(?P<execs>\d+)\s+(?P<tag>\w+)\s+cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)\s+corp:\s*(?P<corp>\d+)"
)
_CRASH_HEADER_RE = re.compile(r"==\d+==ERROR: (?P<sanitizer>\w+Sanitizer): (?P<kind>[\w\-]+)")
_OOM_RE = re.compile(r"out-of-memory|libFuzzer: out-of-memory", re.IGNORECASE)
_TIMEOUT_RE = re.compile(r"libFuzzer: timeout", re.IGNORECASE)


class LibFuzzerEngine(FuzzEngine):
    name = "libfuzzer"

    def __init__(self, sandbox: Sandbox | None = None) -> None:
        self._sandbox = sandbox or NoSandbox()
        self._coverage: CoverageBuilder | None = None
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._stats: dict[str, CampaignStats] = {}
        self._start_ts: dict[str, datetime] = {}

    # ---------- build ----------
    def build(self, spec: HarnessSpec, out_dir: Path) -> BuildArtifact:
        out_dir.mkdir(parents=True, exist_ok=True)
        binary = out_dir / f"fuzz_{spec.entry}"
        log = out_dir / f"build_{spec.entry}.log"
        san = ",".join(s.value for s in spec.sanitizers) or "address"
        cc = os.environ.get("CC", "clang")
        cmd = [
            cc, "-g", "-O1", f"-fsanitize=fuzzer,{san}",
            str(spec.source_path), "-o", str(binary),
        ]
        cmd = self._sandbox.wrap(
            cmd,
            mounts=self._mounts(
                (spec.source_path.parent, spec.source_path.parent, "ro"),
                (out_dir, out_dir, "rw"),
            ),
        )
        with log.open("w") as f:
            f.write("$ " + " ".join(shlex.quote(c) for c in cmd) + "\n")
            f.flush()
            r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise RuntimeError(f"libFuzzer build failed; see {log}")
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=spec.sanitizers,
            build_log_path=log,
        )

    def build_with_coverage(self, spec: HarnessSpec, out_dir: Path) -> BuildArtifact:
        """Build a libFuzzer binary with LLVM coverage instrumentation."""
        if self._coverage is None:
            self._coverage = CoverageBuilder(self._sandbox)
        binary = self._coverage.build_coverage_binary(spec, out_dir)
        return BuildArtifact(
            binary_path=binary,
            engine=EngineKind.LIBFUZZER,
            sanitizers=spec.sanitizers,
            build_log_path=out_dir / f"build_{spec.entry}_coverage.log",
        )

    def collect_coverage(self, cfg: CampaignConfig, artifact: BuildArtifact) -> Path | None:
        """Run corpus inputs once, merge profraw files, and write a text summary."""
        try:
            if self._coverage is None:
                self._coverage = CoverageBuilder(self._sandbox)
            campaign_dir = cfg.crash_dir.parent
            campaign_dir.mkdir(parents=True, exist_ok=True)
            corpus_inputs = [p for p in cfg.corpus_dir.rglob("*") if p.is_file()]
            for idx, inp in enumerate(corpus_inputs):
                env = os.environ.copy()
                env["LLVM_PROFILE_FILE"] = str(campaign_dir / f"coverage_{idx}_%p.profraw")
                try:
                    subprocess.run(
                        [str(artifact.binary_path), str(inp)],
                        env=env, capture_output=True, timeout=30,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    continue
            profraw = sorted(campaign_dir.glob("*.profraw"))
            if not profraw:
                return None
            profdata = campaign_dir / "coverage.profdata"
            summary = campaign_dir / "coverage_summary.txt"
            self._coverage.merge_profraw(profraw, profdata)
            text = self._coverage.summarize(artifact.binary_path, profdata)
            try:
                uncovered = self._coverage.export_uncovered_funcs(artifact.binary_path, profdata)
            except Exception:
                uncovered = []
            if uncovered:
                lines = ["", "Uncovered functions:"]
                lines += [f"{f['file']}:{f['lines']} {f['func']}" for f in uncovered]
                text = text.rstrip() + "\n" + "\n".join(lines) + "\n"
            summary.write_text(text, encoding="utf-8")
            return summary
        except Exception:
            return None

    # ---------- run ----------
    async def run(self, cfg: CampaignConfig) -> AsyncIterator[FuzzEvent]:
        cid = uuid.uuid4().hex[:12]
        self._start_ts[cid] = datetime.now(timezone.utc)
        cmd = [
            str(cfg.artifact.binary_path),
            str(cfg.corpus_dir),
            f"-max_total_time={cfg.time_budget_sec}",
            f"-rss_limit_mb={cfg.max_memory_mb}",
            f"-artifact_prefix={cfg.crash_dir}/",
            "-print_final_stats=1",
        ]
        if cfg.dictionary_path:
            cmd.append(f"-dict={cfg.dictionary_path}")
        cmd += list(cfg.extra_args)
        cfg.crash_dir.mkdir(parents=True, exist_ok=True)
        mounts = self._mounts(
            (cfg.artifact.binary_path.parent, cfg.artifact.binary_path.parent, "ro"),
            (cfg.corpus_dir, cfg.corpus_dir, "rw"),
            (cfg.crash_dir, cfg.crash_dir, "rw"),
        )
        if cfg.dictionary_path:
            mounts = self._mounts(
                *mounts,
                (cfg.dictionary_path.parent, cfg.dictionary_path.parent, "ro"),
            )
        cmd = self._sandbox.wrap(cmd, mounts=mounts, memory_mb=cfg.max_memory_mb)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        self._procs[cid] = proc
        self._stats[cid] = self._empty_stats(cid)

        try:
            assert proc.stdout is not None
            heartbeat_task = asyncio.create_task(self._heartbeat(cid))
            try:
                async for line in proc.stdout:
                    text = line.decode("utf-8", errors="replace").rstrip()
                    ev = self._parse_line(cid, text)
                    if ev is not None:
                        yield ev
            finally:
                heartbeat_task.cancel()
            rc = await proc.wait()
            self._stats[cid].status = (
                CampaignStatus.STOPPED if rc == 0 else CampaignStatus.FAILED
            )
        finally:
            self._procs.pop(cid, None)

    async def _heartbeat(self, cid: str) -> None:
        # placeholder — orchestrator consumes the event stream directly
        try:
            while True:
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            return

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
        st.elapsed_sec = int((datetime.now(timezone.utc) - self._start_ts[cid]).total_seconds())

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
            st.last_event_ts = datetime.now(timezone.utc)
            if cov > prev_cov:
                st.last_new_coverage_sec_ago = 0
                return FuzzEvent(
                    kind=EventKind.NEW_COVERAGE, campaign_id=cid,
                    ts=datetime.now(timezone.utc),
                    payload={"edges": cov, "delta": cov - prev_cov, "execs": execs},
                )
            return None

        m = _CRASH_HEADER_RE.search(line)
        if m:
            st.unique_crashes += 1
            return FuzzEvent(
                kind=EventKind.NEW_CRASH, campaign_id=cid, ts=datetime.now(timezone.utc),
                payload={"sanitizer": m.group("sanitizer"), "kind": m.group("kind"),
                         "raw": line[:500]},
            )

        if _OOM_RE.search(line):
            return FuzzEvent(kind=EventKind.OOM, campaign_id=cid,
                             ts=datetime.now(timezone.utc), payload={"raw": line[:500]})
        if _TIMEOUT_RE.search(line):
            return FuzzEvent(kind=EventKind.TIMEOUT, campaign_id=cid,
                             ts=datetime.now(timezone.utc), payload={"raw": line[:500]})
        return None

    @staticmethod
    def _empty_stats(cid: str) -> CampaignStats:
        return CampaignStats(
            campaign_id=cid, status=CampaignStatus.PENDING, elapsed_sec=0,
            execs_total=0, execs_per_sec=0.0, edges_covered=0, edges_total=None,
            corpus_size=0, unique_crashes=0, last_new_coverage_sec_ago=None,
        )

    # ---------- triage ----------
    def minimize(self, artifact: BuildArtifact, input_path: Path,
                 out_path: Path, timeout_sec: int = 60) -> Path:
        cmd = [str(artifact.binary_path), "-minimize_crash=1",
               f"-exact_artifact_path={out_path}", str(input_path)]
        cmd = self._sandbox.wrap(
            cmd,
            mounts=self._mounts(
                (artifact.binary_path.parent, artifact.binary_path.parent, "ro"),
                (input_path.parent, input_path.parent, "ro"),
                (out_path.parent, out_path.parent, "rw"),
            ),
            cpu_seconds=timeout_sec,
        )
        subprocess.run(cmd, capture_output=True, timeout=timeout_sec)
        return out_path if out_path.exists() else input_path

    def reproduce(self, artifact: BuildArtifact, input_path: Path,
                  timeout_sec: int = 30) -> Optional[str]:
        cmd = self._sandbox.wrap(
            [str(artifact.binary_path), str(input_path)],
            mounts=self._mounts(
                (artifact.binary_path.parent, artifact.binary_path.parent, "ro"),
                (input_path.parent, input_path.parent, "ro"),
            ),
            cpu_seconds=timeout_sec,
        )
        try:
            r = subprocess.run(
                cmd,
                capture_output=True, timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            return "timeout"
        out = (r.stdout + r.stderr).decode("utf-8", errors="replace")
        return out if r.returncode != 0 else None

    @staticmethod
    def _mounts(*mounts: tuple[Path, Path, str]) -> list[tuple[Path, Path, str]]:
        merged: dict[tuple[Path, Path], str] = {}
        for host_path, container_path, mode in mounts:
            host = host_path.resolve()
            container = container_path.resolve()
            key = (host, container)
            merged[key] = "rw" if mode == "rw" or merged.get(key) == "rw" else "ro"
        return [(host, container, mode) for (host, container), mode in merged.items()]
