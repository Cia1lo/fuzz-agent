import base64
import importlib
import json

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


def test_mutate_strategy_derives_input_model_from_uncovered_function(
    tmp_path,
    monkeypatch,
):
    rt = Runtime(root=tmp_path / "state-root")
    monkeypatch.setattr(_runtime, "_singleton", rt)
    target = tmp_path / "target"
    target.mkdir()
    (target / "parser.cc").write_text(
        "#include <cstddef>\n"
        "int ParseThing(const unsigned char *data, size_t size) {\n"
        "  if (size >= 5 && data[0] == 'M' && data[1] == 'A' && data[2] == 'G' && data[3] == 'I') {\n"
        "    return data[4];\n"
        "  }\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    harness = target / ".fuzz" / "harness" / "ParseThing" / "attempt_1.cc"
    harness.parent.mkdir(parents=True)
    harness.write_text("harness", encoding="utf-8")
    cfg = CampaignConfig(
        artifact=BuildArtifact(
            binary_path=target / ".fuzz" / "build" / "fuzz",
            engine=EngineKind.LIBFUZZER,
            sanitizers=[],
            build_log_path=target / ".fuzz" / "build" / "build.log",
            harness_source_path=harness,
        ),
        corpus_dir=tmp_path / "corpus",
        crash_dir=tmp_path / "crashes",
        dictionary_path=None,
        time_budget_sec=10,
    )
    cid = rt.store.new_campaign(cfg)
    paths = rt.store.paths(cid)
    paths["coverage_uncovered"].write_text(
        json.dumps([{"file": "parser.cc", "func": "ParseThing", "lines": "3-5"}]),
        encoding="utf-8",
    )
    coverage_module = importlib.import_module("fuzz_agent.subagents.coverage_analyst")
    monkeypatch.setattr(
        coverage_module,
        "call_llm_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no llm")),
    )

    result = mutate_strategy_impl(cid, "plateau")

    assert result["dict_additions"] == ["MAGI"]
    assert result["added_seeds"] == ["strategy_model_MAGI"]
    assert "magic" in {field["name"] for field in result["input_model"]["fields"]}
    assert result["harness_modeling_hint"]
    model_path = paths["base"] / "input_model.json"
    assert result["input_model_path"] == str(model_path)
    assert json.loads(model_path.read_text(encoding="utf-8"))["tokens"] == ["MAGI"]
