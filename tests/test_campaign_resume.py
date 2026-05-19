from fuzz_agent.state.models import BuildArtifact, CampaignConfig, EngineKind
from fuzz_agent.tools import _runtime
from fuzz_agent.tools._runtime import Runtime
from fuzz_agent.tools.campaign import resume_campaign_impl


def test_resume_campaign_creates_new_campaign_seeded_from_old_corpus(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    artifact = BuildArtifact(
        binary_path=tmp_path / "fuzz",
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=tmp_path / "build.log",
    )
    cfg = CampaignConfig(
        artifact=artifact,
        corpus_dir=tmp_path / "old-corpus",
        crash_dir=tmp_path / "old-crashes",
        dictionary_path=None,
        time_budget_sec=30,
    )
    cid = rt.store.new_campaign(cfg)
    old_paths = rt.store.paths(cid)
    (old_paths["corpus_dir"] / "seed").write_bytes(b"seed")
    cfg.corpus_dir = old_paths["corpus_dir"]
    cfg.crash_dir = old_paths["crash_dir"]
    cfg.campaign_id = cid
    rt.store.update_meta(cid, cfg)

    def fake_submit(coro):
        coro.close()
        return object()

    monkeypatch.setattr(rt, "submit", fake_submit)

    new_cid = resume_campaign_impl(cid, 12)
    new_cfg = rt.store.campaign_config(new_cid)

    assert new_cid != cid
    assert new_cfg.resumed_from == cid
    assert new_cfg.time_budget_sec == 12
    assert (rt.store.paths(new_cid)["corpus_dir"] / "seed").read_bytes() == b"seed"
