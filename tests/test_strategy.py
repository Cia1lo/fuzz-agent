import base64

from fuzz_agent.state.models import BuildArtifact, CampaignConfig, EngineKind
from fuzz_agent.tools import _runtime
from fuzz_agent.tools._runtime import Runtime
from fuzz_agent.tools.strategy import mutate_strategy_impl


def test_mutate_strategy_dedupes_seeds_and_dictionary_tokens(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=tmp_path / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=tmp_path / "build.log",
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    (paths["corpus_dir"] / "existing").write_bytes(b"same")
    (paths["base"] / "extra.dict").write_text('"TOK"\n', encoding="utf-8")

    def fake_analyst(campaign_id, coverage_file, source_root):
        return {
            "suggested_seeds": [
                {"name": "dup", "bytes_b64": base64.b64encode(b"same").decode()},
                {"name": "new", "bytes_b64": base64.b64encode(b"new").decode()},
            ],
            "dict_additions": ["TOK", "NEW"],
            "uncovered": [],
        }

    monkeypatch.setattr("fuzz_agent.tools.strategy.coverage_analyst", fake_analyst)

    result = mutate_strategy_impl(cid, "hint")

    assert result["added_seeds"] == ["strategy_new"]
    assert result["dict_additions"] == ["NEW"]
    assert result["dictionary_path"] == str(paths["base"] / "extra.dict")
    assert (paths["base"] / "extra.dict").read_text(encoding="utf-8").splitlines() == [
        '"TOK"', '"NEW"'
    ]
