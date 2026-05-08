"""LLVM coverage helpers for libFuzzer campaigns."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..state.models import HarnessSpec


class CoverageBuilder:
    """Build and summarize LLVM source coverage for fuzz harnesses."""

    def __init__(self, sandbox=None) -> None:
        self._sandbox = sandbox

    def build_coverage_binary(self, spec: HarnessSpec, out_dir: Path) -> Path:
        """Compile a libFuzzer binary with LLVM coverage instrumentation."""
        out_dir.mkdir(parents=True, exist_ok=True)
        binary = out_dir / f"fuzz_{spec.entry}_coverage"
        log = out_dir / f"build_{spec.entry}_coverage.log"
        san = ",".join(s.value for s in spec.sanitizers) or "address"
        cc = os.environ.get("CC", "clang")
        cmd = [
            cc,
            "-g",
            "-O1",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            f"-fsanitize=fuzzer,{san}",
            str(spec.source_path),
            "-o",
            str(binary),
        ]
        cmd = self._wrap_build(cmd, spec.source_path.parent, out_dir)
        with log.open("w", encoding="utf-8") as f:
            f.write("$ " + " ".join(shlex.quote(c) for c in cmd) + "\n")
            f.flush()
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            raise RuntimeError(f"coverage build failed; see {log}")
        return binary

    def merge_profraw(self, profraw_files: list[Path], out: Path) -> Path:
        """Merge raw LLVM profile files into one indexed profile."""
        tool = self._llvm_tool("llvm-profdata")
        if not profraw_files:
            raise RuntimeError("no .profraw files found to merge")
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = [tool, "merge", "-sparse", *(str(p) for p in profraw_files), "-o", str(out)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "llvm-profdata merge failed")
        return out

    def summarize(self, binary: Path, profdata: Path) -> str:
        """Return the human-readable `llvm-cov report` output."""
        tool = self._llvm_tool("llvm-cov")
        cmd = [tool, "report", str(binary), f"-instr-profile={profdata}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "llvm-cov report failed")
        return result.stdout

    def export_uncovered_funcs(
        self, binary: Path, profdata: Path, n: int = 20
    ) -> list[dict]:
        """Return up to n functions whose exported line regions are uncovered."""
        tool = self._llvm_tool("llvm-cov")
        cmd = [
            tool,
            "export",
            str(binary),
            f"-instr-profile={profdata}",
            "-summary-only=false",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "llvm-cov export failed")
        payload = json.loads(result.stdout or "{}")
        funcs: list[dict[str, Any]] = []
        for unit in payload.get("data", []):
            for fn in unit.get("functions", []):
                regions = fn.get("regions") or []
                if fn.get("count", 0) != 0 or not self._regions_uncovered(regions):
                    continue
                start, end = self._line_span(regions)
                funcs.append(
                    {
                        "file": str((fn.get("filenames") or [""])[0]),
                        "func": str(fn.get("name", "")),
                        "lines": f"{start}-{end}",
                        "_span": max(end - start, 0),
                    }
                )
        funcs.sort(key=lambda item: item["_span"], reverse=True)
        return [{k: v for k, v in item.items() if k != "_span"} for item in funcs[:n]]

    def _wrap_build(self, cmd: list[str], source_dir: Path, out_dir: Path) -> list[str]:
        if self._sandbox is None or not hasattr(self._sandbox, "wrap"):
            return cmd
        mounts = [(source_dir, source_dir, "ro"), (out_dir, out_dir, "rw")]
        return self._sandbox.wrap(cmd, mounts=mounts)

    @staticmethod
    def _llvm_tool(name: str) -> str:
        tool = shutil.which(name)
        if not tool:
            raise RuntimeError(f"{name} not found; install LLVM tools and ensure PATH includes them")
        return tool

    @staticmethod
    def _regions_uncovered(regions: list[list[Any]]) -> bool:
        return all(len(region) < 5 or int(region[4]) == 0 for region in regions)

    @staticmethod
    def _line_span(regions: list[list[Any]]) -> tuple[int, int]:
        starts = [int(region[0]) for region in regions if len(region) >= 3]
        ends = [int(region[2]) for region in regions if len(region) >= 3]
        return (min(starts), max(ends)) if starts and ends else (0, 0)
