import json

from fuzz_agent.state.models import EngineKind, Language, TargetProfile
from fuzz_agent.subagents.harness_context import pack_context


def test_pack_context_finds_cpp_signature_flags_and_samples(tmp_path):
    src = tmp_path / "parser.cc"
    src.write_text(
        '#include "parser.h"\n'
        "#include <string>\n\n"
        "int ParseThing(const unsigned char *data, size_t size) {\n"
        "  return size > 0 ? data[0] : 0;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([
            {
                "directory": str(tmp_path),
                "file": str(src),
                "arguments": [
                    "clang++", "-Iinclude", "-DDEBUG", "-std=c++17",
                    "-c", str(src), "-o", "parser.o",
                ],
            }
        ]),
        encoding="utf-8",
    )
    samples = tmp_path / "testdata"
    samples.mkdir()
    (samples / "seed").write_bytes(b"abc")
    target = TargetProfile(
        root=tmp_path,
        language=Language.CPP,
        entry_points=["ParseThing"],
        build_system="cmake",
    )

    context = pack_context(target, "ParseThing", EngineKind.LIBFUZZER)

    assert context["source_file"] == str(src)
    assert "ParseThing" in context["signature"]
    assert '#include "parser.h"' in context["includes"]
    assert "-Iinclude" in context["compile_flags"]
    assert str(src) in context["extra_sources"]
    assert str(samples / "seed") in context["sample_inputs"]


def test_pack_context_prefers_cpp_definition_over_header_declaration(tmp_path):
    header = tmp_path / "parser.h"
    header.write_text(
        "#pragma once\n"
        "#include <cstddef>\n"
        "#include <cstdint>\n"
        "int ParseThing(const uint8_t* data, size_t size);\n",
        encoding="utf-8",
    )
    src = tmp_path / "parser.cc"
    src.write_text(
        '#include "parser.h"\n\n'
        "int ParseThing(const uint8_t* data, size_t size) {\n"
        "  return size > 0 ? data[0] : 0;\n"
        "}\n",
        encoding="utf-8",
    )
    target = TargetProfile(
        root=tmp_path,
        language=Language.CPP,
        entry_points=["ParseThing"],
        build_system="cmake",
    )

    context = pack_context(target, "ParseThing", EngineKind.LIBFUZZER)

    assert context["source_file"] == str(src)
    assert str(src) in context["extra_sources"]
    assert str(header) not in context["extra_sources"]
    assert f"-I{tmp_path}" in context["compile_flags"]


def test_pack_context_for_cargo_fuzz_includes_rust_crate_context(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo-crate"\nedition = "2021"\n\n[dependencies]\nserde = "1"\n',
        encoding="utf-8",
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "use serde::Deserialize;\n"
        "pub fn parse_thing(data: &[u8]) -> Result<(), ()> {\n"
        "    let _ = data;\n"
        "    Ok(())\n"
        "}\n",
        encoding="utf-8",
    )
    target = TargetProfile(
        root=tmp_path,
        language=Language.RUST,
        entry_points=["parse_thing"],
        build_system="cargo",
    )

    context = pack_context(target, "parse_thing", EngineKind.CARGO_FUZZ)

    assert context["package_name"] == "demo-crate"
    assert context["crate_import"] == "demo_crate"
    assert context["signature"].startswith("pub fn parse_thing")
    assert "serde" in context["dependencies"]
    assert context["uses"] == ["use serde::Deserialize;"]
