import asyncio
from datetime import datetime, timezone

from click.testing import CliRunner

from fuzz_agent.chat import ChatSession, ChatTurn, ConversationAgent
from fuzz_agent.chat.memory import recent_history
from fuzz_agent.cli import main
from fuzz_agent.events.stream import EventBus
from fuzz_agent.state.models import (
    BuildArtifact,
    CampaignConfig,
    CrashRecord,
    CrashStatus,
    EngineKind,
)
from fuzz_agent.state.store import CampaignStore
from fuzz_agent.tools import _runtime
from fuzz_agent.tools._runtime import Runtime


def test_chat_analyze_target_sets_session_target(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"demo\"\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "pub fn parse_thing(b: &[u8]) -> Result<(), ()> { let _ = b; Ok(()) }\n",
        encoding="utf-8",
    )
    session = ChatSession()
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, f"analyze {tmp_path}"))

    assert "语言: rust" in reply
    assert "parse_thing" in reply
    assert session.target_path == str(tmp_path.resolve())
    assert session.working_memory["last_intent"] == "analyze"
    assert session.working_memory["last_command"].startswith("analyze")
    assert "语言: rust" in session.working_memory["last_reply"]


def test_chat_session_memory_roundtrip():
    session = ChatSession(
        session_id="memory-test",
        active_campaign_id="cid123",
        target_path="/tmp/target",
        summary="older turns summary",
        working_memory={"last_intent": "status"},
        history=[ChatTurn(role="user", content="status")],
    )

    restored = ChatSession.from_dict(session.to_dict())

    assert restored.summary == "older turns summary"
    assert restored.working_memory == {"last_intent": "status"}
    assert restored.history[0].content == "status"


def test_recent_history_uses_character_budget():
    session = ChatSession(history=[
        ChatTurn(role="user", content=f"turn {idx}")
        for idx in range(10)
    ])

    history = recent_history(session, char_budget=50)

    assert "turn 9" in history
    assert "turn 0" not in history
    assert len(history) <= 50


def test_chat_status_uses_explicit_campaign_id(tmp_path, monkeypatch, make_stats):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    rt.store.record_stats(make_stats("abc123", unique_crashes=2))
    session = ChatSession()
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "status abc123"))

    assert "campaign `abc123`" in reply
    assert "unique crashes: 2" in reply
    assert session.active_campaign_id == "abc123"


def test_chat_prompt_includes_campaign_snapshot(tmp_path, make_stats):
    rt = Runtime(root=tmp_path)
    cid = _new_test_campaign(rt)
    rt.store.record_stats(make_stats(cid, unique_crashes=2, edges_covered=7))
    session = ChatSession(active_campaign_id=cid)

    from fuzz_agent.chat.agent import _chat_prompt

    prompt = _chat_prompt(session, "what happened?", rt.store)

    assert f"campaign_id: {cid}" in prompt
    assert "edges_covered: 7" in prompt
    assert "unique_crashes: 2" in prompt


def test_chat_status_without_campaign_does_not_treat_command_as_id(tmp_path):
    rt = Runtime(root=tmp_path)
    session = ChatSession()
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "status"))

    assert "没有可用 campaign" in reply


def test_chat_slash_help_uses_command_parser(tmp_path):
    rt = Runtime(root=tmp_path)
    session = ChatSession()
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "/help"))

    assert "可用对话命令" in reply


def test_chat_greeting_works_without_llm(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rt = Runtime(root=tmp_path)
    session = ChatSession()
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "你好"))

    assert "你好" in reply
    assert "fuzz-agent" in reply


def test_chat_run_parses_chinese_freeform_without_spaces(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    target = tmp_path / "demo_targets" / "real_target_crash"
    target.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    captured_goals = []

    async def fake_run(self, goal):
        captured_goals.append(goal)
        return {
            "campaign_id": "cid123",
            "stats": {
                "status": "finished",
                "elapsed_sec": goal.time_budget_sec,
                "unique_crashes": 0,
            },
            "paths": {"agent_trace": "trace.jsonl"},
        }

    monkeypatch.setattr("fuzz_agent.chat.agent.Orchestrator.run", fake_run)
    session = ChatSession()
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "对demo_targets/real_target_crash进行fuzz测试一分钟"))

    assert "Campaign `cid123` 的最终状态是 `finished`" in reply
    assert "运行约 60s" in reply
    assert "本次 fuzz 已完成，暂未发现 crash。" in reply
    assert len(captured_goals) == 1
    assert captured_goals[0].target_path == target.resolve()
    assert captured_goals[0].time_budget_sec == 60
    assert captured_goals[0].engine == EngineKind.LIBFUZZER
    assert session.target_path == str(target.resolve())
    assert session.active_campaign_id == "cid123"


def test_chat_run_reuses_target_for_chinese_duration(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    captured_goals = []

    async def fake_run(self, goal):
        captured_goals.append(goal)
        return {
            "campaign_id": "cid456",
            "stats": {
                "status": "finished",
                "elapsed_sec": goal.time_budget_sec,
                "unique_crashes": 0,
            },
            "paths": {"agent_trace": "trace.jsonl"},
        }

    monkeypatch.setattr("fuzz_agent.chat.agent.Orchestrator.run", fake_run)
    session = ChatSession(target_path=str(tmp_path))
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "跑半分钟"))

    assert "Campaign `cid456` 的最终状态是 `finished`" in reply
    assert "运行约 30s" in reply
    assert "本次 fuzz 已完成，暂未发现 crash。" in reply
    assert len(captured_goals) == 1
    assert captured_goals[0].target_path == tmp_path.resolve()
    assert captured_goals[0].time_budget_sec == 30


def test_chat_run_summary_includes_crash_details(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    crash_input = tmp_path / "state" / "campaigns" / "cid789" / "crashes" / "crash-abc"
    crash_input.parent.mkdir(parents=True)
    crash_input.write_bytes(b"BUG!")
    reproduce_log = crash_input.with_suffix(".log")
    reproduce_log.write_text(
        "\n".join([
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
            "WRITE of size 1 at 0x1 thread T0",
            "    #0 0xaaa in ParseThing(unsigned char const*, unsigned long) parser.cc:10",
            "0x1 is located 0 bytes after 4-byte region [0x0,0x4)",
            "allocated by thread T0 here:",
            "    #0 0xbbb in malloc+0x70 libclang_rt.asan.dylib",
            "    #1 0xccc in ParseThing(unsigned char const*, unsigned long) parser.cc:5",
            "SUMMARY: AddressSanitizer: heap-buffer-overflow parser.cc:10",
        ]),
        encoding="utf-8",
    )

    async def fake_run(self, goal):
        return {
            "campaign_id": "cid789",
            "stats": {
                "status": "failed",
                "elapsed_sec": 0,
                "unique_crashes": 1,
            },
            "crashes": [
                {
                    "crash_id": "abc",
                    "status": "confirmed",
                    "sanitizer_kind": "SEGV",
                    "input_path": str(crash_input),
                    "minimized_path": None,
                    "reproduce_log_path": str(reproduce_log),
                    "top_frames": ["ParseThing parser.cc:10"],
                    "vulnerability_matches": [
                        {"title": "Null pointer dereference", "cwe": "CWE-476"},
                    ],
                },
            ],
            "paths": {
                "agent_trace": str(tmp_path / "trace.jsonl"),
                "crash_dir": str(crash_input.parent),
            },
        }

    monkeypatch.setattr("fuzz_agent.chat.agent.Orchestrator.run", fake_run)
    session = ChatSession(target_path=str(tmp_path))
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "run 1s"))

    assert "发现 1 个 crash" in reply
    assert "结果解读" in reply
    assert "`abc`" in reply
    assert "输入预览是 `BUG!`" in reply
    assert "复现日志在" in reply
    assert "ParseThing parser.cc:10" in reply
    assert "写入 1 字节" in reply
    assert "0 bytes after 4-byte region" in reply
    assert "ParseThing(unsigned char const*, unsigned long) parser.cc:5" in reply
    assert "Null pointer dereference (CWE-476)" in reply
    assert "保存内容" not in reply
    assert "SUMMARY: AddressSanitizer" not in reply


def test_chat_run_summary_omits_large_artifact_contents(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    run_log = tmp_path / "run.log"
    run_log.write_text("A" * 9000, encoding="utf-8")

    async def fake_run(self, goal):
        return {
            "campaign_id": "cid-large",
            "stats": {
                "status": "finished",
                "elapsed_sec": 1,
                "unique_crashes": 0,
            },
            "paths": {"run_log": str(run_log)},
        }

    monkeypatch.setattr("fuzz_agent.chat.agent.Orchestrator.run", fake_run)
    session = ChatSession(target_path=str(tmp_path))
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "run 1s"))

    assert "run log" in reply
    assert "完整运行记录" in reply
    assert "AAAAA" not in reply


def test_chat_llm_intent_can_parse_freeform_analyze(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"demo\"\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "pub fn parse_thing(b: &[u8]) -> Result<(), ()> { let _ = b; Ok(()) }\n",
        encoding="utf-8",
    )

    def fake_call_llm_json(*_args, **_kwargs):
        return {
            "intent": "analyze",
            "path": str(tmp_path),
            "campaign_id": None,
            "duration_sec": None,
            "engine": None,
            "top_n": None,
            "reply": None,
        }

    monkeypatch.setattr("fuzz_agent.chat.agent.call_llm_json", fake_call_llm_json)
    session = ChatSession()
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "帮我看一下这个项目"))

    assert "语言: rust" in reply
    assert "parse_thing" in reply


def test_chat_trace_summarizes_agent_trace(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    cid = _new_test_campaign(rt)
    rt.store.record_agent_trace(cid, {
        "phase": "harness_attempt",
        "observation": {"diagnostics": "missing include <stdint.h>"},
        "decision": {"action": "regenerate_harness", "reason": "build failed"},
    })
    session = ChatSession(active_campaign_id=cid)
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "trace"))

    assert "决策解读" in reply
    assert "Harness 未通过验证，准备重新生成" in reply
    assert "阶段: Harness 生成/验证" in reply
    assert "missing include" in reply


def test_chat_trace_explains_crash_reproduce_without_raw_log(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    monkeypatch.setattr(_runtime, "_singleton", rt)
    cid = _new_test_campaign(rt)
    rt.store.record_agent_trace(cid, {
        "phase": "crash_reproduce",
        "observation": {
            "diagnostics": "\n".join([
                "INFO: Running with entropic power schedule (0xFF, 100).",
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
                "WRITE of size 1 at 0x1 thread T0",
                "    #0 0xaaa in ParseThing(unsigned char const*, unsigned long) parser.cc:10",
            ]),
            "artifacts": {"crash_id": "abc"},
        },
        "decision": {
            "action": "record_crash",
            "reason": "persist reproducibility and harness ownership evidence",
        },
        "result": {"crash_id": "abc", "status": "confirmed", "reproducible": True},
        "score": {"harness_fault_detected": False},
    })
    session = ChatSession(active_campaign_id=cid)
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "trace"))

    assert "Crash 复现证据已记录" in reply
    assert "复现结果: 已复现" in reply
    assert "Harness 归因: 当前证据没有指向 harness 自身错误" in reply
    assert "日志信号: 堆缓冲区越界" in reply
    assert "写入 1 字节" in reply
    assert "INFO: Running with entropic power schedule" not in reply


def test_chat_triage_includes_crash_artifacts(tmp_path, monkeypatch):
    crash_input = tmp_path / "crashes" / "crash-abc"
    crash_input.parent.mkdir()
    crash_input.write_bytes(b"BUG!")
    reproduce_log = crash_input.with_suffix(".log")
    reproduce_log.write_text(
        "\n".join([
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
            "WRITE of size 1 at 0x1 thread T0",
            "    #0 0xaaa in ParseThing(unsigned char const*, unsigned long) parser.cc:10",
            "0x1 is located 0 bytes after 4-byte region [0x0,0x4)",
            "allocated by thread T0 here:",
            "    #0 0xbbb in malloc+0x70 libclang_rt.asan.dylib",
            "    #1 0xccc in ParseThing(unsigned char const*, unsigned long) parser.cc:5",
        ]),
        encoding="utf-8",
    )
    crash = CrashRecord(
        crash_id="abc",
        campaign_id="cid789",
        input_path=crash_input,
        minimized_path=None,
        stack_hash="abc",
        top_frames=["ParseThing parser.cc:10"],
        sanitizer_kind="SEGV",
        discovered_at=datetime.now(timezone.utc),
        status=CrashStatus.CONFIRMED,
        reproducible=True,
        reproduce_log_path=reproduce_log,
    )
    monkeypatch.setattr("fuzz_agent.chat.agent.tools.triage_crashes", lambda *_args, **_kwargs: [crash])
    session = ChatSession(active_campaign_id="cid789")
    agent = ConversationAgent(CampaignStore(tmp_path), EventBus())

    reply = asyncio.run(agent.respond(session, "triage"))

    assert "campaign `cid789` crash 分诊结果" in reply
    assert "结果解读" in reply
    assert "输入预览是 `BUG!`" in reply
    assert "复现日志在" in reply
    assert "ParseThing parser.cc:10" in reply
    assert "写入 1 字节" in reply
    assert "0 bytes after 4-byte region" in reply
    assert "status=confirmed" not in reply


def test_chat_stop_calls_tool_for_active_campaign(tmp_path, monkeypatch):
    rt = Runtime(root=tmp_path)
    called: list[str] = []
    monkeypatch.setattr("fuzz_agent.chat.agent.tools.stop_campaign", called.append)
    session = ChatSession(active_campaign_id="abc123")
    agent = ConversationAgent(rt.store, rt.bus)

    reply = asyncio.run(agent.respond(session, "stop"))

    assert called == ["abc123"]
    assert "已请求停止" in reply


def test_cli_chat_help_smoke():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["chat"], input="help\nquit\n")

    assert result.exit_code == 0
    assert "Fuzz Agent chat" in result.output
    assert "可用对话命令" in result.output


def _new_test_campaign(rt: Runtime) -> str:
    artifact = BuildArtifact(
        binary_path=rt.root / "fuzz",
        engine=EngineKind.LIBFUZZER,
        sanitizers=[],
        build_log_path=rt.root / "build.log",
    )
    cfg = CampaignConfig(
        artifact=artifact,
        corpus_dir=rt.root / "corpus",
        crash_dir=rt.root / "crashes",
        dictionary_path=None,
        time_budget_sec=30,
    )
    return rt.store.new_campaign(cfg)
