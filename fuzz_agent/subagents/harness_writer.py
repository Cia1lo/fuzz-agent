"""harness-writer subagent: generate a fuzz harness for one entry point."""
from __future__ import annotations

from pathlib import Path

from ..state.models import EngineKind, HarnessSpec, Sanitizer, TargetProfile
from ._llm import call_claude_json

_EXT = {
    EngineKind.LIBFUZZER: "cc",
    EngineKind.AFLPP: "c",
    EngineKind.ATHERIS: "py",
    EngineKind.JAZZER: "java",
    EngineKind.GO_NATIVE: "go",
}

_SYSTEM = """You write fuzz harnesses. Output strict JSON only.
Schema: {"source": "<full harness source code>", "dictionary": ["tok1", "tok2", ...]}
Rules:
- The harness must drive ONE entry point with bytes from the fuzzer.
- Include any requested invariants (round-trip, differential) as asserts.
- Keep the harness minimal — no I/O beyond what's required."""


def run(target: TargetProfile, entry: str,
        engine: EngineKind, invariants: list[str]) -> HarnessSpec:
    user = (
        f"Target language: {target.language.value}\n"
        f"Target root: {target.root}\n"
        f"Entry point: {entry}\n"
        f"Engine: {engine.value}\n"
        f"Invariants to enforce: {invariants or ['none']}\n\n"
        "Generate the harness. Return JSON with `source` and optional `dictionary`."
    )
    out = call_claude_json(_SYSTEM, user, max_tokens=4096)
    ext = _EXT.get(engine, "txt")
    harness_dir = target.root / ".fuzz" / "harness"
    harness_dir.mkdir(parents=True, exist_ok=True)
    src = harness_dir / f"{entry}.{ext}"
    src.write_text(out["source"], encoding="utf-8")
    dict_path = None
    if out.get("dictionary"):
        dict_path = harness_dir / f"{entry}.dict"
        dict_path.write_text(
            "\n".join(f'"{t}"' for t in out["dictionary"]), encoding="utf-8"
        )
    return HarnessSpec(
        target=target, entry=entry, engine=engine,
        source_path=src, dictionary_path=dict_path,
        sanitizers=[Sanitizer.ASAN, Sanitizer.UBSAN],
        invariants=invariants,
    )
