"""Source/build context packing for engine-specific harness generation."""
from __future__ import annotations

import json
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any, Iterator, cast

from ..state.models import EngineKind, Language, TargetProfile

_C_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
_RUST_EXTS = {".rs"}
_SKIP_DIRS = {".git", ".fuzz", "state", "build", "__pycache__"}
_SAMPLE_DIRS = ("tests", "test", "examples", "example", "fixtures", "testdata", "samples")


def pack_context(target: TargetProfile, entry: str, engine: EngineKind) -> dict[str, Any]:
    """Return bounded source/build context for one engine entry."""
    if engine is EngineKind.LIBFUZZER and target.language not in (Language.C, Language.CPP):
        raise RuntimeError(
            f"LibFuzzer harness generation only supports C/C++ targets, got {target.language.value}"
        )
    if engine is EngineKind.CARGO_FUZZ:
        if target.language is not Language.RUST:
            raise RuntimeError(
                f"cargo-fuzz harness generation only supports Rust targets, got {target.language.value}"
            )
        return _rust_context(target, entry)

    source, line_no = _find_entry_source(target.root, entry, _C_EXTS)
    compile_flags: list[str] = []
    link_flags: list[str] = []
    extra_sources: list[str] = []
    if source is not None:
        compile_flags, link_flags = _compile_commands_flags(target.root, source)
        if source.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx"}:
            extra_sources.append(str(source))
    return {
        "entry": entry,
        "source_file": str(source) if source else None,
        "line": line_no,
        "signature": _signature(source, line_no) if source else "",
        "snippet": _snippet(source, line_no) if source else "",
        "includes": _includes(source) if source else [],
        "compile_flags": compile_flags,
        "link_flags": link_flags,
        "extra_sources": extra_sources,
        "sample_inputs": [str(p) for p in _sample_inputs(target.root)],
        "build_system": target.build_system,
    }


def _rust_context(target: TargetProfile, entry: str) -> dict[str, Any]:
    source, line_no = _find_entry_source(target.root, entry, _RUST_EXTS)
    cargo = _cargo_context(target.root)
    return {
        "entry": entry,
        "source_file": str(source) if source else None,
        "line": line_no,
        "signature": _rust_signature(source, line_no) if source else "",
        "snippet": _snippet(source, line_no) if source else "",
        "uses": _rust_uses(source) if source else [],
        "compile_flags": [],
        "link_flags": [],
        "extra_sources": [],
        "sample_inputs": [str(p) for p in _sample_inputs(target.root)],
        "build_system": target.build_system,
        "package_name": cargo["package_name"],
        "crate_import": cargo["crate_import"],
        "edition": cargo["edition"],
        "dependencies": cargo["dependencies"],
    }


def _iter_source_files(root: Path, exts: set[str]) -> Iterator[Path]:
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in exts and path.stat().st_size < 512 * 1024:
            yield path


def _find_entry_source(root: Path, entry: str, exts: set[str]) -> tuple[Path | None, int | None]:
    call_re = re.compile(rf"\b{re.escape(entry)}\s*\(")
    for path in _iter_source_files(root, exts):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines, start=1):
            if call_re.search(line) and not line.strip().startswith("//"):
                return path, idx
    return None, None


def _cargo_context(root: Path) -> dict[str, Any]:
    manifest = root / "Cargo.toml"
    if not manifest.exists():
        raise RuntimeError(f"Cargo.toml not found at {manifest}")
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"failed to parse {manifest}: {exc}") from exc
    package = cast(dict[str, Any] | None, data.get("package"))
    if not package:
        raise RuntimeError("cargo-fuzz harness generation needs a concrete Rust package")
    package_name = package.get("name")
    if not isinstance(package_name, str) or not package_name:
        raise RuntimeError("Cargo.toml [package].name is missing")
    edition = package.get("edition")
    if not isinstance(edition, str) or not edition:
        edition = "2021"
    deps_raw = data.get("dependencies", {})
    dependencies = sorted(deps_raw) if isinstance(deps_raw, dict) else []
    return {
        "package_name": package_name,
        "crate_import": package_name.replace("-", "_"),
        "edition": edition,
        "dependencies": dependencies[:40],
    }


def _signature(source: Path, line_no: int | None) -> str:
    if line_no is None:
        return ""
    lines = source.read_text(errors="replace").splitlines()
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 4)
    chunk = " ".join(line.strip() for line in lines[start:end])
    match = re.search(r"([A-Za-z_][\w\s:*&<>~,]+\s+\**[A-Za-z_]\w*\s*\([^;{]*\))", chunk)
    return match.group(1).strip() if match else lines[line_no - 1].strip()


def _rust_signature(source: Path, line_no: int | None) -> str:
    if line_no is None:
        return ""
    lines = source.read_text(errors="replace").splitlines()
    start = max(0, line_no - 6)
    end = min(len(lines), line_no + 8)
    chunk = " ".join(line.strip() for line in lines[start:end])
    match = re.search(
        r"((?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_]\w*\s*\([^)]*\)"
        r"(?:\s*->\s*[^{]+)?)",
        chunk,
    )
    return match.group(1).strip() if match else lines[line_no - 1].strip()


def _snippet(source: Path, line_no: int | None, radius: int = 40) -> str:
    if line_no is None:
        return ""
    lines = source.read_text(errors="replace").splitlines()
    start = max(0, line_no - radius - 1)
    end = min(len(lines), line_no + radius)
    return "\n".join(f"{idx + 1}: {lines[idx]}" for idx in range(start, end))


def _includes(source: Path) -> list[str]:
    include_re = re.compile(r"^\s*#\s*include\s+[<\"].+[>\"]")
    try:
        return [line.strip() for line in source.read_text(errors="replace").splitlines()
                if include_re.match(line)][:40]
    except OSError:
        return []


def _rust_uses(source: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in source.read_text(errors="replace").splitlines()
            if line.strip().startswith("use ")
        ][:40]
    except OSError:
        return []


def _compile_commands_flags(root: Path, source: Path) -> tuple[list[str], list[str]]:
    cc = root / "compile_commands.json"
    if not cc.exists():
        return [], _makefile_link_hints(root)
    try:
        rows = json.loads(cc.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], _makefile_link_hints(root)
    source_resolved = source.resolve()
    for row in rows:
        file_path = Path(row.get("file", ""))
        if not file_path.is_absolute():
            file_path = Path(row.get("directory", root)) / file_path
        if file_path.resolve() != source_resolved:
            continue
        argv = row.get("arguments") or shlex.split(row.get("command", ""))
        compile_flags: list[str] = []
        link_flags: list[str] = []
        skip_next = False
        for idx, arg in enumerate(argv[1:], start=1):
            if skip_next:
                skip_next = False
                continue
            if arg in {"-o", "-c"}:
                skip_next = arg == "-o"
                continue
            if arg == str(source) or arg == str(source_resolved):
                continue
            if arg.startswith(("-I", "-D", "-std=", "-isystem", "-f", "-m")):
                compile_flags.append(arg)
                if arg == "-isystem" and idx + 1 < len(argv):
                    compile_flags.append(argv[idx + 1])
                    skip_next = True
            elif arg.startswith(("-L", "-l", "-Wl,")):
                link_flags.append(arg)
        return compile_flags, link_flags
    return [], _makefile_link_hints(root)


def _makefile_link_hints(root: Path) -> list[str]:
    hints: list[str] = []
    for name in ("Makefile", "makefile"):
        path = root / name
        if not path.exists():
            continue
        text = path.read_text(errors="replace")
        for token in shlex.split(text.replace("\n", " ")):
            if token.startswith(("-L", "-l", "-Wl,")) and token not in hints:
                hints.append(token)
            if len(hints) >= 20:
                return hints
    return hints


def _sample_inputs(root: Path, limit: int = 10) -> list[Path]:
    out: list[Path] = []
    for dirname in _SAMPLE_DIRS:
        base = root / dirname
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.stat().st_size <= 64 * 1024:
                out.append(path)
                if len(out) >= limit:
                    return out
    return out
