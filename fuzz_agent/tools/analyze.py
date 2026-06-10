"""analyze_target — identify language, build system, candidate entry points."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

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
        r"(parse_\w+|decode_\w+|deserialize_\w+|load_\w+|read_\w+|unpack_\w+)\s*\(",
        re.IGNORECASE | re.MULTILINE,
    ),
    Language.CPP: re.compile(
        r"^\s*[\w\s\*:<>~,&\*]+\s+"
        r"((?:Parse|parse|Decode|decode|Deserialize|deserialize|Load|load|Read|read|"
        r"Unpack|unpack)\w*)\s*\(",
        re.IGNORECASE | re.MULTILINE,
    ),
    Language.GO: re.compile(
        r"^func\s+(?:\([^)]*\)\s*)?(Parse\w*|Decode\w*|Unmarshal\w*|Read\w*)\s*\(",
        re.MULTILINE,
    ),
    Language.RUST: re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+"
        r"(parse_\w+|decode_\w+|from_bytes\w*|read_\w+|load_\w+)\s*\(",
        re.MULTILINE,
    ),
    Language.PYTHON: re.compile(
        r"^\s*def\s+(parse_\w+|decode_\w+|loads?|read_\w+|load_\w+)\s*\(",
        re.MULTILINE,
    ),
    Language.JAVA: re.compile(
        r"^\s*(?:public|protected|private|static|\s)+[\w<>\[\]]+\s+"
        r"(parse\w+|decode\w+|deserialize\w+|read\w+|load\w+)\s*\(",
        re.IGNORECASE | re.MULTILINE,
    ),
}

_C_LIKE = {Language.C, Language.CPP}
_SKIP_DIRS = {".git", ".fuzz", "state", "build", "cmake-build-debug", "cmake-build-release"}
_SOURCE_EXTS = {
    Language.C: {".c", ".h"},
    Language.CPP: {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"},
    Language.RUST: {".rs"},
    Language.GO: {".go"},
    Language.PYTHON: {".py"},
    Language.JAVA: {".java"},
}
_BYTE_SIGNATURE_RE = re.compile(
    r"^\s*[\w\s\*:<>~,&\*]+\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
    r"(?P<params>[^)]*(?:uint8_t|unsigned\s+char|char\s*\*|std::string|string_view|span)[^)]*)"
    r"\)\s*(?:const\s*)?(?:[{;]|$)",
    re.MULTILINE,
)
_C_LIKE_FUNCTION_RE = re.compile(
    r"^\s*(?:template\s*<[^>]+>\s*)?"
    r"(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+|friend\s+)*"
    r"(?P<ret>[A-Za-z_~][\w:<>,~*&\s]+?)\s+"
    r"(?P<name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)?)\s*"
    r"\((?P<params>[^;{}()]*)\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?(?:->\s*[^;{]+)?\s*\{",
    re.MULTILINE,
)
_IGNORED_ENTRY_NAMES = {"main", "LLVMFuzzerTestOneInput", "fuzz_target"}
_ENTRY_NAME_HINTS = (
    "parse", "decode", "deserialize", "unmarshal", "unpack", "read", "load",
    "process", "handle", "consume", "validate", "from_bytes",
)
_BYTE_PARAM_HINTS = (
    "uint8_t", "unsigned char", "char *", "char*", "std::string", "string_view",
    "span", "bytes", "&[u8]", "Vec<u8>", "byte[]", "[]byte",
)
_INPUT_NAME_HINTS = (
    "data", "bytes", "buffer", "buf", "input", "packet", "frame", "message", "blob",
)


def analyze_target_impl(path: Path) -> TargetProfile:
    path = path.resolve()
    lang, build_system = _detect_language(path)
    if lang is Language.UNKNOWN:
        lang = _infer_language_from_sources(path)
        build_system = "unknown"
    entries: list[str] = _discover_entries(path, lang)
    notes = (
        f"Auto-detected language={lang.value}; build_system={build_system}; "
        f"entry_points={len(entries)}"
    )
    return TargetProfile(
        root=path, language=lang,
        entry_points=entries,
        build_system=build_system,
        notes=notes,
    )


def _detect_language(path: Path) -> tuple[Language, str]:
    for L, files in _LANG_HINTS.items():
        if any((path / f).exists() for f in files):
            if L is Language.C and _has_cpp_sources(path):
                return Language.CPP, _BUILD[L]
            return L, _BUILD[L]
    return Language.UNKNOWN, "unknown"


def _infer_language_from_sources(path: Path) -> Language:
    counts = {
        lang: sum(1 for f in path.rglob("*") if not _skip_path(f) and f.suffix.lower() in exts)
        for lang, exts in _SOURCE_EXTS.items()
    }
    counts.pop(Language.UNKNOWN, None)
    lang, count = max(counts.items(), key=lambda item: item[1])
    return lang if count else Language.UNKNOWN


def _has_cpp_sources(path: Path) -> bool:
    cpp_exts = {".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"}
    return any(
        f.is_file() and not _skip_path(f) and f.suffix.lower() in cpp_exts
        for f in path.rglob("*")
    )


def _discover_entries(path: Path, lang: Language) -> list[str]:
    candidates: dict[str, tuple[int, int]] = {}
    order = 0
    pat = _ENTRY_RE.get(lang)
    if pat is not None:
        for f in _iter_source_files(path, lang):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for entry, score in _entry_candidates(lang, pat, text):
                _add_candidate(candidates, entry, score + _path_score(f), order)
                order += 1
    ranked = sorted(candidates.items(), key=lambda item: (-item[1][0], item[1][1], item[0]))
    return [name for name, _ in ranked[:20]]


def _iter_source_files(path: Path, lang: Language) -> Iterable[Path]:
    exts = _SOURCE_EXTS.get(lang)
    if not exts:
        return []
    return (
        f for f in path.rglob("*")
        if not _skip_path(f)
        and f.is_file()
        and f.suffix.lower() in exts
        and f.stat().st_size <= 512 * 1024
    )


def _skip_path(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _entry_candidates(lang: Language, pat: re.Pattern[str], text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for match in pat.finditer(text):
        name = _normalize_entry_name(match.group(1))
        _append_entry(out, name, _entry_score(lang, name, match.group(0)))
    if lang in _C_LIKE:
        for match in _BYTE_SIGNATURE_RE.finditer(text):
            name = _normalize_entry_name(match.group("name"))
            _append_entry(out, name, _entry_score(lang, name, match.group("params")))
        for match in _C_LIKE_FUNCTION_RE.finditer(text):
            name = _normalize_entry_name(match.group("name"))
            score = _entry_score(lang, name, match.group("params"))
            if score >= 35:
                _append_entry(out, name, score)
    return out


def _append_entry(entries: list[tuple[str, int]], name: str, score: int) -> None:
    if name in _IGNORED_ENTRY_NAMES or any(existing == name for existing, _ in entries):
        return
    entries.append((name, score))


def _add_candidate(candidates: dict[str, tuple[int, int]], name: str, score: int, order: int) -> None:
    existing = candidates.get(name)
    if existing is None or score > existing[0]:
        candidates[name] = (score, existing[1] if existing else order)


def _normalize_entry_name(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def _entry_score(lang: Language, name: str, signature: str) -> int:
    del lang
    lower_name = name.lower()
    lower_sig = signature.lower()
    score = 0
    if any(hint in lower_name for hint in _ENTRY_NAME_HINTS):
        score += 30
    if any(hint in lower_name for hint in _INPUT_NAME_HINTS):
        score += 20
    if any(hint.lower() in lower_sig for hint in _BYTE_PARAM_HINTS):
        score += 40
    if any(hint in lower_sig for hint in _INPUT_NAME_HINTS):
        score += 10
    if re.search(r"\b(size|len|length|n)\b", lower_sig):
        score += 8
    if lower_name.startswith("_") or lower_name in _IGNORED_ENTRY_NAMES:
        score -= 100
    return score


def _path_score(path: Path) -> int:
    parts = {part.lower() for part in path.parts}
    score = 0
    if parts & {"src", "lib", "source"}:
        score += 5
    if parts & {"test", "tests", "fixtures", "examples", "demo"}:
        score -= 15
    return score
