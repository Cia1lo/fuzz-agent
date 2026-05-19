import asyncio
import sys

from fuzz_agent.engines.cargo_fuzz import CargoFuzzEngine
from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    EngineKind,
    EventKind,
    HarnessSpec,
    Language,
    TargetProfile,
)


def _fake_cargo(path, *, rc: int = 0, output: str = ""):
    path.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "log = pathlib.Path(os.environ['FAKE_CARGO_LOG'])\n"
        "with log.open('a', encoding='utf-8') as f:\n"
        "    f.write('cwd=' + os.getcwd() + ' argv=' + ' '.join(sys.argv[1:]) + '\\n')\n"
        f"print({output!r}, flush=True)\n"
        "if sys.argv[1:3] == ['fuzz', '--help']:\n"
        "    raise SystemExit(0)\n"
        f"raise SystemExit({rc})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _rust_profile(root):
    (root / "Cargo.toml").write_text(
        '[package]\nname = "demo-crate"\nedition = "2021"\n',
        encoding="utf-8",
    )
    return TargetProfile(
        root=root,
        language=Language.RUST,
        entry_points=["parse_thing"],
        build_system="cargo",
    )


def test_build_creates_cargo_fuzz_target_and_builds(tmp_path, monkeypatch):
    fake_log = tmp_path / "cargo.log"
    fake = _fake_cargo(tmp_path / "cargo", output="#1 NEW cov: 7 ft: 9 corp: 1/1b")
    monkeypatch.setenv("FUZZ_AGENT_CARGO", str(fake))
    monkeypatch.setenv("FAKE_CARGO_LOG", str(fake_log))

    root = tmp_path / "crate"
    root.mkdir()
    profile = _rust_profile(root)
    harness = root / ".fuzz" / "harness" / "parse_thing" / "attempt_1.rs"
    harness.parent.mkdir(parents=True)
    harness.write_text(
        "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n"
        "fuzz_target!(|data: &[u8]| { let _ = demo_crate::parse_thing(data); });\n",
        encoding="utf-8",
    )
    spec = HarnessSpec(
        target=profile,
        entry="parse_thing",
        engine=EngineKind.CARGO_FUZZ,
        source_path=harness,
    )

    artifact = CargoFuzzEngine().build(spec, root / ".fuzz" / "build")

    assert artifact.engine is EngineKind.CARGO_FUZZ
    assert artifact.binary_path == root / "fuzz" / "fuzz_targets" / "parse_thing_attempt_1.rs"
    assert "demo_crate::parse_thing" in artifact.binary_path.read_text(encoding="utf-8")
    manifest = (root / "fuzz" / "Cargo.toml").read_text(encoding="utf-8")
    assert "cargo-fuzz = true" in manifest
    assert 'libfuzzer-sys = "0.4"' in manifest
    assert 'name = "parse_thing_attempt_1"' in manifest
    assert "fuzz run parse_thing_attempt_1 -- -runs=0" in fake_log.read_text(encoding="utf-8")


def test_run_uses_campaign_id_and_writes_run_log(tmp_path, monkeypatch):
    fake_log = tmp_path / "cargo.log"
    fake = _fake_cargo(tmp_path / "cargo", output="#1 NEW cov: 11 ft: 2 corp: 1/1b")
    monkeypatch.setenv("FUZZ_AGENT_CARGO", str(fake))
    monkeypatch.setenv("FAKE_CARGO_LOG", str(fake_log))

    root = tmp_path / "crate"
    target = root / "fuzz" / "fuzz_targets" / "parse_thing_attempt_1.rs"
    target.parent.mkdir(parents=True)
    target.write_text("#![no_main]\n", encoding="utf-8")
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=target,
            engine=EngineKind.CARGO_FUZZ,
            sanitizers=[],
            build_log_path=root / ".fuzz" / "build" / "build.log",
            harness_source_path=target,
        ),
        corpus_dir=tmp_path / "campaign" / "corpus",
        crash_dir=tmp_path / "campaign" / "crashes",
        dictionary_path=None,
        time_budget_sec=5,
        campaign_id="store-cid",
    )

    async def scenario():
        engine = CargoFuzzEngine()
        return [event async for event in engine.run(cfg)]

    events = asyncio.run(scenario())

    assert events
    assert events[0].campaign_id == "store-cid"
    assert events[0].kind is EventKind.NEW_COVERAGE
    assert "fuzz run parse_thing_attempt_1" in (cfg.crash_dir.parent / "run.log").read_text(
        encoding="utf-8"
    )


def test_reproduce_returns_cargo_fuzz_crash_output(tmp_path, monkeypatch):
    fake_log = tmp_path / "cargo.log"
    fake = _fake_cargo(
        tmp_path / "cargo",
        rc=1,
        output="thread '<unnamed>' panicked at src/lib.rs:10:5",
    )
    monkeypatch.setenv("FUZZ_AGENT_CARGO", str(fake))
    monkeypatch.setenv("FAKE_CARGO_LOG", str(fake_log))

    root = tmp_path / "crate"
    target = root / "fuzz" / "fuzz_targets" / "parse_thing_attempt_1.rs"
    target.parent.mkdir(parents=True)
    target.write_text("#![no_main]\n", encoding="utf-8")
    crash = tmp_path / "crash"
    crash.write_bytes(b"boom")
    artifact = BuildArtifact(
        binary_path=target,
        engine=EngineKind.CARGO_FUZZ,
        sanitizers=[],
        build_log_path=root / ".fuzz" / "build" / "build.log",
        harness_source_path=target,
    )

    report = CargoFuzzEngine().reproduce(artifact, crash)

    assert report is not None
    assert "panicked at" in report
    assert "fuzz run parse_thing_attempt_1" in fake_log.read_text(encoding="utf-8")
