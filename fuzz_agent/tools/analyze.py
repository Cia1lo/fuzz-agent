"""analyze_target — identify language, build system, candidate entry points."""
from __future__ import annotations

import re
from pathlib import Path

from ..state.models import Language, TargetProfile

_LANG_HINTS = {
    Language.RUST: ("Cargo.toml",),
    Language.GO: ("go.mod",),
    Language.PYTHON: ("pyproject.toml", "setup.py"),
    Language.JAVA: ("pom.xml", "build.gradle", "build.gradle.kts"),
    Language.CPP: ("CMakeLists.txt",),
    Language.C: ("Makefile",),
}

_BUILD = {
    Language.RUST: "cargo",
    Language.GO: "go",
    Language.PYTHON: "pip",
    Language.JAVA: "maven",
    Language.CPP: "cmake",
    Language.C: "make",
}

_ENTRY_RE = {
    Language.C: re.compile(
        r"^\s*[\w\s\*]+\s+"
        r"(parse_\w+|decode_\w+|deserialize_\w+|load_\w+|read_\w+)\s*\(",
        re.MULTILINE,
    ),
    Language.CPP: re.compile(
        r"^\s*[\w\s\*:<>~,&\*]+\s+"
        r"((?:Parse|parse|Decode|decode|Deserialize|deserialize|Load|load|Read|read)\w*)\s*\(",
        re.MULTILINE,
    ),
    Language.GO: re.compile(r"^func\s+(Parse\w*|Decode\w*|Unmarshal\w*)\s*\(", re.MULTILINE),
    Language.RUST: re.compile(r"^\s*pub\s+fn\s+(parse_\w+|decode_\w+|from_bytes\w*)\s*\(",
                               re.MULTILINE),
    Language.PYTHON: re.compile(r"^def\s+(parse_\w+|decode_\w+|loads?)\s*\(", re.MULTILINE),
}

_C_LIKE = {Language.C, Language.CPP}
_SKIP_DIRS = {".git", ".fuzz", "state", "build", "cmake-build-debug", "cmake-build-release"}
_BYTE_SIGNATURE_RE = re.compile(
    r"^\s*[\w\s\*:<>~,&\*]+\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
    r"(?P<params>[^)]*(?:uint8_t|unsigned\s+char|char\s*\*|std::string|string_view|span)[^)]*)"
    r"\)\s*(?:const\s*)?(?:[{;]|$)",
    re.MULTILINE,
)
_IGNORED_ENTRY_NAMES = {"main", "LLVMFuzzerTestOneInput", "fuzz_target"}


def analyze_target_impl(path: Path) -> TargetProfile:
    path = path.resolve()
    lang = Language.UNKNOWN
    for L, files in _LANG_HINTS.items():
        if any((path / f).exists() for f in files):
            lang = L
            break
    entries: list[str] = []
    pat = _ENTRY_RE.get(lang)
    if pat is not None:
        for f in path.rglob("*"):
            if _skip_path(f) or not f.is_file() or f.stat().st_size > 256 * 1024:
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for entry in _entry_candidates(lang, pat, text):
                entries.append(entry)
                if len(entries) >= 20:
                    break
            if len(entries) >= 20:
                break
    return TargetProfile(
        root=path, language=lang,
        entry_points=sorted(set(entries)),
        build_system=_BUILD.get(lang, "unknown"),
        notes=f"Auto-detected language={lang.value} via project files",
    )


def _skip_path(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _entry_candidates(lang: Language, pat: re.Pattern[str], text: str) -> list[str]:
    out: list[str] = []
    for match in pat.finditer(text):
        _append_entry(out, match.group(1))
    if lang in _C_LIKE:
        for match in _BYTE_SIGNATURE_RE.finditer(text):
            _append_entry(out, match.group("name"))
    return out


def _append_entry(entries: list[str], name: str) -> None:
    if name in _IGNORED_ENTRY_NAMES or name in entries:
        return
    entries.append(name)
