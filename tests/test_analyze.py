from fuzz_agent.state.models import Language
from fuzz_agent.tools import analyze_target


def test_analyze_rust_target_detects_entry_point(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"demo\"\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "pub fn parse_thing(b: &[u8]) -> Result<(), ()> { let _ = b; Ok(()) }\n",
        encoding="utf-8",
    )

    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.RUST
    assert "parse_thing" in profile.entry_points


def test_analyze_python_target_detects_entry_point(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = \"demo\"\n", encoding="utf-8")
    (tmp_path / "parser.py").write_text(
        "def parse_json(data):\n    return data\n",
        encoding="utf-8",
    )

    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.PYTHON
    assert "parse_json" in profile.entry_points


def test_analyze_empty_dir_unknown_with_no_entries(tmp_path):
    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.UNKNOWN
    assert profile.entry_points == []
