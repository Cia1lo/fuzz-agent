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
    Language.C: re.compile(r"^\s*[\w\s\*]+\s+(parse_\w+|decode_\w+|deserialize_\w+)\s*\(",
                            re.MULTILINE),
    Language.CPP: re.compile(r"^\s*[\w\s\*:]+\s+(Parse\w*|Decode\w*|Deserialize\w*)\s*\(",
                              re.MULTILINE),
    Language.GO: re.compile(r"^func\s+(Parse\w*|Decode\w*|Unmarshal\w*)\s*\(", re.MULTILINE),
    Language.RUST: re.compile(r"^\s*pub\s+fn\s+(parse_\w+|decode_\w+|from_bytes\w*)\s*\(",
                               re.MULTILINE),
    Language.PYTHON: re.compile(r"^def\s+(parse_\w+|decode_\w+|loads?)\s*\(", re.MULTILINE),
}


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
            if not f.is_file() or f.stat().st_size > 256 * 1024:
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for m in pat.finditer(text):
                entries.append(m.group(1))
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
