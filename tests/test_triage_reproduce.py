from fuzz_agent.agent_harness import AgentObservation
from fuzz_agent.state.models import BuildArtifact, CampaignConfig, CrashStatus, EngineKind
from fuzz_agent.tools import _runtime
from fuzz_agent.tools._runtime import Runtime
from fuzz_agent.tools.triage import triage_crashes_impl


class FakeEngine:
    def reproduce(self, artifact, input_path, timeout_sec=30):
        return "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x1 in ParseThing"


class FlakyEngine:
    def __init__(self):
        self.calls = 0

    def reproduce(self, artifact, input_path, timeout_sec=30):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("tool crashed")
        return None


def test_triage_reproduces_and_writes_missing_log(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    rt._engines[EngineKind.LIBFUZZER] = FakeEngine()
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
            harness_source_path=tmp_path / "harness.cc",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    cfg.corpus_dir = paths["corpus_dir"]
    cfg.crash_dir = paths["crash_dir"]
    cfg.campaign_id = cid
    rt.store.update_meta(cid, cfg)
    crash = paths["crash_dir"] / "crash-input"
    crash.write_bytes(b"boom")

    [record] = triage_crashes_impl(cid, 10)

    assert record.status is CrashStatus.CONFIRMED
    assert record.reproducible is True
    assert record.reproduce_log_path.exists()
    assert "heap-buffer-overflow" in record.reproduce_log_path.read_text(encoding="utf-8")
    assert record.vulnerability_matches
    assert record.vulnerability_matches[0].cwe in {"CWE-119", "CWE-125", "CWE-787"}
    trace = rt.store.list_agent_trace(cid)
    assert trace[-1]["phase"] == "crash_reproduce"
    assert trace[-1]["observation"]["kind"] == "crash_reproduce"
    assert trace[-1]["score"]["crash_reproducible"] is True


def test_triage_marks_flaky_after_reproduce_errors(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    engine = FlakyEngine()
    rt._engines[EngineKind.LIBFUZZER] = engine
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
            harness_source_path=tmp_path / "harness.cc",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    cfg.corpus_dir = paths["corpus_dir"]
    cfg.crash_dir = paths["crash_dir"]
    cfg.campaign_id = cid
    rt.store.update_meta(cid, cfg)
    crash = paths["crash_dir"] / "crash-input"
    crash.write_bytes(b"boom")

    [record] = triage_crashes_impl(cid, 10)

    assert record.status is CrashStatus.FLAKY
    assert record.reproducible is None
    assert engine.calls == 3
    trace = rt.store.list_agent_trace(cid)
    attempts = trace[-1]["observation"]["raw"]["reproduce_attempts"]
    observation = AgentObservation.from_dict(trace[-1]["observation"])
    assert observation.kind == "crash_reproduce_failure"
    assert attempts[0]["status"] == "error"
    assert attempts[-1]["status"] == "non_reproducible"
