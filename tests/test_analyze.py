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


def test_analyze_cpp_detects_lowercase_and_byte_signature_entries(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text("project(demo)\n", encoding="utf-8")
    (tmp_path / "parser.cc").write_text(
        "int parse_frame(const uint8_t *data, size_t size) { return 0; }\n"
        "int HandleBytes(const unsigned char *data, size_t size) { return 0; }\n",
        encoding="utf-8",
    )
    build = tmp_path / "build"
    build.mkdir()
    (build / "generated.cc").write_text(
        "int DecodeGenerated(const unsigned char *data, size_t size) { return 0; }\n",
        encoding="utf-8",
    )

    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.CPP
    assert "parse_frame" in profile.entry_points
    assert "HandleBytes" in profile.entry_points
    assert "DecodeGenerated" not in profile.entry_points


def test_analyze_infers_language_from_sources_and_ranks_byte_entry(tmp_path):
    (tmp_path / "parser.cc").write_text(
        "int InitConfig() { return 0; }\n"
        "int ProcessPacket(const char *data, unsigned long len) { return len > 0 && data[0]; }\n"
        "int helper_no_input(int mode) { return mode; }\n",
        encoding="utf-8",
    )

    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.CPP
    assert profile.entry_points[0] == "ProcessPacket"
    assert "helper_no_input" not in profile.entry_points


def test_analyze_cpp_detects_generic_handle_buffer_entry(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text("project(demo)\n", encoding="utf-8")
    (tmp_path / "codec.cc").write_text(
        "bool HandleBuffer(std::string_view input) {\n"
        "  return input.size() > 4;\n"
        "}\n",
        encoding="utf-8",
    )

    profile = analyze_target(str(tmp_path))

    assert "HandleBuffer" in profile.entry_points


def test_analyze_empty_dir_unknown_with_no_entries(tmp_path):
    profile = analyze_target(str(tmp_path))

    assert profile.language is Language.UNKNOWN
    assert profile.entry_points == []
