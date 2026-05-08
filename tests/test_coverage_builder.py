import json
import subprocess
from pathlib import Path

from fuzz_agent.engines.coverage import CoverageBuilder


def _mock_llvm_tools(monkeypatch):
    monkeypatch.setattr("fuzz_agent.engines.coverage.shutil.which", lambda name: f"/usr/bin/{name}")


def test_merge_profraw_passes_correct_argv(monkeypatch, tmp_path):
    _mock_llvm_tools(monkeypatch)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("fuzz_agent.engines.coverage.subprocess.run", fake_run)
    profraw = [tmp_path / "a.profraw", tmp_path / "b.profraw"]
    out = tmp_path / "coverage.profdata"

    assert CoverageBuilder().merge_profraw(profraw, out) == out

    assert calls[0][0] == [
        "/usr/bin/llvm-profdata",
        "merge",
        "-sparse",
        str(profraw[0]),
        str(profraw[1]),
        "-o",
        str(out),
    ]


def test_summarize_returns_stdout(monkeypatch, tmp_path):
    _mock_llvm_tools(monkeypatch)
    report = "Filename Regions Missed Regions Cover\nTOTAL 10 2 80.00%\n"

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=report, stderr="")

    monkeypatch.setattr("fuzz_agent.engines.coverage.subprocess.run", fake_run)

    assert CoverageBuilder().summarize(tmp_path / "fuzz", tmp_path / "coverage.profdata") == report


def test_export_uncovered_funcs_returns_only_zero_count_functions(monkeypatch, tmp_path):
    _mock_llvm_tools(monkeypatch)
    payload = {
        "data": [
            {
                "functions": [
                    {
                        "name": "foo",
                        "filenames": ["/x.c"],
                        "regions": [[10, 1, 15, 1, 0, 0, 0, 0]],
                        "count": 0,
                    },
                    {
                        "name": "bar",
                        "filenames": ["/x.c"],
                        "regions": [[20, 1, 25, 1, 5, 0, 0, 0]],
                        "count": 5,
                    },
                ]
            }
        ]
    }

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("fuzz_agent.engines.coverage.subprocess.run", fake_run)

    assert CoverageBuilder().export_uncovered_funcs(
        Path("/bin/fuzz"), tmp_path / "coverage.profdata"
    ) == [{"file": "/x.c", "func": "foo", "lines": "10-15"}]
