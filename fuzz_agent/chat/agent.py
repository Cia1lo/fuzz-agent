"""Minimal conversational facade over the existing fuzz-agent tools."""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .. import tools
from ..events.stream import EventBus
from ..orchestrator import CampaignGoal, Orchestrator
from ..state.models import CampaignStats, CrashRecord, EngineKind, TargetProfile
from ..state.store import CampaignStore
from ..subagents._llm import call_llm, call_llm_json
from .memory import (
    build_chat_memory_prompt,
    build_intent_prompt,
    note_error,
    note_intent,
    note_reply,
    refresh_session_summary,
)
from .session import ChatSession

_INTENTS = {
    "analyze",
    "run",
    "status",
    "stop",
    "resume",
    "trace",
    "triage",
    "help",
    "chat",
    "unknown",
}

_PATH_CANDIDATE_RE = re.compile(
    r"(?:~|\.{1,2})?(?:/[A-Za-z0-9_.@+=:-]+)+|"
    r"[A-Za-z0-9_.@+=:-]+(?:/[A-Za-z0-9_.@+=:-]+)+"
)

_CHINESE_DIGITS = {
    "零": 0,
    "〇": 0,
    "一": 1,
    "二": 2,
    "两": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
}

_RUN_PHRASES = (
    "运行",
    "启动",
    "开始",
    "执行",
    "跑",
    "跑一下",
    "跑一遍",
    "跑起来",
    "模糊测试",
    "fuzz测试",
    "fuzz 测试",
    "fuzz一下",
    "fuzz 一下",
    "fuzz一遍",
    "fuzz 一遍",
    "进行fuzz",
    "进行 fuzz",
    "做fuzz",
    "做 fuzz",
    "fuzz test",
)

_ANALYZE_PHRASES = (
    "分析",
    "检查",
    "识别",
    "扫描",
)

_INTENT_SYSTEM = """You classify a user's message for a fuzzing CLI assistant.
Return strict JSON only:
{
  "intent": "analyze|run|status|stop|resume|trace|triage|help|chat|unknown",
  "path": null|string,
  "campaign_id": null|string,
  "duration_sec": null|integer,
  "engine": null|"libfuzzer"|"cargo-fuzz",
  "top_n": null|integer,
  "reply": null|string
}
Use "chat" for greetings or general questions that should not call a tool.
Use "unknown" when a command is ambiguous or missing required information.
Do not invent paths or campaign ids.
Examples:
User: 对demo_targets/real_target_crash进行fuzz测试一分钟
{"intent":"run","path":"demo_targets/real_target_crash","duration_sec":60,"engine":"libfuzzer","campaign_id":null,"top_n":null,"reply":null}
User: 帮我分析一下 ./demo_targets/real_target_crash
{"intent":"analyze","path":"./demo_targets/real_target_crash","duration_sec":null,"engine":null,"campaign_id":null,"top_n":null,"reply":null}
User: 查看刚才的状态
{"intent":"status","path":null,"duration_sec":null,"engine":null,"campaign_id":null,"top_n":null,"reply":null}"""

_CHAT_SYSTEM = """You are a concise assistant inside fuzz-agent, a fuzzing orchestrator.
Answer normal conversation naturally, but keep users oriented toward available actions:
analyze a target, run fuzzing, check status, stop/resume campaigns, inspect trace, and triage crashes.
Do not claim that you executed a tool unless the user asked for a supported action."""

_INLINE_ARTIFACT_FILE_LIMIT_BYTES = 8 * 1024
_INLINE_BINARY_ARTIFACT_LIMIT_BYTES = 512
_INLINE_ARTIFACT_TOTAL_LIMIT_BYTES = 32 * 1024


@dataclass(frozen=True)
class ChatIntent:
    intent: str
    path: str | None = None
    campaign_id: str | None = None
    duration_sec: int | None = None
    engine: EngineKind | None = None
    top_n: int | None = None
    reply: str | None = None


@dataclass(frozen=True)
class CrashExplanation:
    problem: str = ""
    sanitizer: str = ""
    access: str = ""
    location: str = ""
    boundary: str = ""
    allocation: str = ""


class ConversationAgent:
    """Chat layer that maps user messages onto existing tools."""

    def __init__(self, store: CampaignStore, bus: EventBus) -> None:
        self.store = store
        self.bus = bus

    async def respond(self, session: ChatSession, message: str) -> str:
        text = message.strip()
        if not text:
            return "请输入要执行的操作，例如 `analyze ./target` 或 `status <campaign_id>`。"
        session.add_turn("user", text)
        try:
            reply = await self._dispatch(session, text)
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            note_error(session, error)
            reply = f"执行失败：{error}"
        session.add_turn("assistant", reply)
        note_reply(session, reply)
        refresh_session_summary(session)
        return reply

    async def _dispatch(self, session: ChatSession, text: str) -> str:
        intent = self._parse_intent(session, text)
        note_intent(session, intent=intent.intent, command=text)
        if intent.intent == "help":
            return _help_text()
        if intent.intent == "status":
            return self._status(session, text, intent)
        if intent.intent == "stop":
            return self._stop(session, text, intent)
        if intent.intent == "trace":
            return self._trace(session, text, intent)
        if intent.intent == "triage":
            return self._triage(session, text, intent)
        if intent.intent == "resume":
            return self._resume(session, text, intent)
        if intent.intent == "analyze":
            return self._analyze(session, text, intent)
        if intent.intent == "run":
            return await self._run(session, text, intent)
        if intent.intent == "chat":
            return self._chat(session, text, intent)
        return _unknown_text()

    def _parse_intent(self, session: ChatSession, text: str) -> ChatIntent:
        rule_intent = _rule_intent(text)
        if rule_intent.intent != "unknown":
            return rule_intent
        if _llm_enabled():
            llm_intent = _llm_intent(session, text, self.store)
            if llm_intent.intent != "unknown":
                return llm_intent
        return ChatIntent(intent="chat") if _looks_like_chat(text) else rule_intent

    def _analyze(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        path = _path_from_intent(intent, text, session)
        if path is None:
            return "请提供要分析的目录，例如 `analyze ./demo_targets/real_target_crash`。"
        profile = tools.analyze_target(str(path))
        session.target_path = str(profile.root)
        return _format_profile(profile)

    async def _run(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        path = _path_from_intent(intent, text, session)
        if path is None:
            return "请提供要 fuzz 的目录，例如 `run ./target 30m`。"
        duration = intent.duration_sec or _extract_duration(text) or 30 * 60
        engine = intent.engine or _extract_engine(text) or EngineKind.LIBFUZZER
        goal = CampaignGoal(
            target_path=path.resolve(),
            time_budget_sec=duration,
            engine=engine,
        )
        orch = Orchestrator(self.store, self.bus)
        summary = await orch.run(goal)
        cid = str(summary.get("campaign_id") or "")
        if cid:
            session.active_campaign_id = cid
        session.target_path = str(path.resolve())
        return _format_campaign_summary(summary)

    def _status(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        cid = self._resolve_campaign_id(session, text, intent)
        if cid is None:
            return "没有可用 campaign。请先运行 `run <path> 30m`，或提供 campaign_id。"
        stats = tools.query_status(cid)
        session.active_campaign_id = stats.campaign_id
        return _format_stats(stats)

    def _stop(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        cid = self._resolve_campaign_id(session, text, intent)
        if cid is None:
            return "没有可停止的 campaign。请提供 campaign_id。"
        tools.stop_campaign(cid)
        session.active_campaign_id = cid
        return f"已请求停止 campaign `{cid}`。"

    def _resume(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        cid = self._resolve_campaign_id(session, text, intent)
        if cid is None:
            return "请提供要恢复的 campaign_id，例如 `resume abc123 10m`。"
        new_cid = tools.resume_campaign(cid, intent.duration_sec or _extract_duration(text))
        session.active_campaign_id = new_cid
        return f"已从 `{cid}` 恢复为新 campaign `{new_cid}`。"

    def _trace(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        cid = self._resolve_campaign_id(session, text, intent)
        if cid is None:
            return "请提供 campaign_id，或先在当前对话中运行一个 campaign。"
        trace = tools.read_agent_trace(cid)
        session.active_campaign_id = cid
        return _format_trace(cid, trace)

    def _triage(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        cid = self._resolve_campaign_id(session, text, intent)
        if cid is None:
            return "请提供要分诊的 campaign_id。"
        crashes = tools.triage_crashes(cid, top_n=intent.top_n or _extract_top_n(text))
        session.active_campaign_id = cid
        return _format_crashes(cid, crashes)

    def _chat(self, session: ChatSession, text: str, intent: ChatIntent) -> str:
        if intent.reply:
            return intent.reply
        if _llm_enabled():
            try:
                reply = call_llm(
                    _CHAT_SYSTEM,
                    _chat_prompt(session, text, self.store),
                    max_tokens=512,
                )
                if reply.strip():
                    return reply.strip()
            except Exception:  # noqa: BLE001
                pass
        return _fallback_chat_text(text)

    def _resolve_campaign_id(
        self,
        session: ChatSession,
        text: str,
        intent: ChatIntent,
    ) -> str | None:
        if intent.campaign_id:
            return intent.campaign_id
        explicit = _extract_campaign_id(text)
        if explicit is not None:
            return explicit
        if session.active_campaign_id:
            return session.active_campaign_id
        campaigns = self.store.list_campaigns()
        if campaigns:
            cid = campaigns[0].get("cid")
            if isinstance(cid, str):
                return cid
        return None


def _rule_intent(text: str) -> ChatIntent:
    command_text = _strip_slash_command(text)
    lower = command_text.lower()
    if _is_help(lower):
        return ChatIntent(intent="help")
    if _has_any(lower, ("status", "stats")) or _contains_any(command_text, ("状态", "进度")):
        return ChatIntent(intent="status")
    if _has_any(lower, ("stop", "halt", "cancel")) or _contains_any(
        command_text,
        ("停止", "终止", "取消"),
    ):
        return ChatIntent(intent="stop")
    if _has_any(lower, ("trace", "why", "explain")) or _contains_any(
        command_text,
        ("为什么", "解释", "决策", "轨迹"),
    ):
        return ChatIntent(intent="trace")
    if _has_any(lower, ("triage",)) or _contains_any(
        command_text,
        ("分诊", "crash分析", "崩溃分析"),
    ):
        return ChatIntent(intent="triage")
    if _has_any(lower, ("resume", "continue")) or "恢复" in command_text or "继续" in command_text:
        return ChatIntent(intent="resume")
    if _has_any(lower, ("analyze", "inspect")) or _contains_any(
        command_text,
        _ANALYZE_PHRASES,
    ):
        return ChatIntent(intent="analyze")
    if _has_any(lower, ("run", "start")) or _contains_any(lower, _RUN_PHRASES):
        return ChatIntent(intent="run")
    if _contains_any(command_text, ("测试一下", "测试一遍", "进行测试", "开始测试")):
        return ChatIntent(intent="run")
    if _looks_like_chat(command_text):
        return ChatIntent(intent="chat")
    return ChatIntent(intent="unknown")


def _strip_slash_command(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("/"):
        return stripped[1:].lstrip()
    return text


def _llm_enabled() -> bool:
    disabled = os.environ.get("FUZZ_AGENT_CHAT_LLM", "").strip().lower()
    return bool(os.environ.get("OPENAI_API_KEY")) and disabled not in {"0", "false", "off", "no"}


def _llm_intent(
    session: ChatSession,
    text: str,
    store: CampaignStore | None = None,
) -> ChatIntent:
    try:
        raw = call_llm_json(_INTENT_SYSTEM, _intent_prompt(session, text, store), max_tokens=512)
    except Exception:  # noqa: BLE001
        return ChatIntent(intent="unknown")
    return _parse_llm_intent(raw)


def _parse_llm_intent(raw: Any) -> ChatIntent:
    if not isinstance(raw, dict):
        return ChatIntent(intent="unknown")
    intent = raw.get("intent")
    if not isinstance(intent, str) or intent not in _INTENTS:
        return ChatIntent(intent="unknown")
    return ChatIntent(
        intent=intent,
        path=_optional_str(raw.get("path")),
        campaign_id=_optional_str(raw.get("campaign_id")),
        duration_sec=_optional_positive_int(raw.get("duration_sec")),
        engine=_optional_engine(raw.get("engine")),
        top_n=_optional_positive_int(raw.get("top_n")),
        reply=_optional_str(raw.get("reply")),
    )


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _optional_positive_int(value: Any) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _optional_engine(value: Any) -> EngineKind | None:
    if not isinstance(value, str):
        return None
    try:
        return EngineKind(value)
    except ValueError:
        return None


def _intent_prompt(
    session: ChatSession,
    text: str,
    store: CampaignStore | None = None,
) -> str:
    return build_intent_prompt(session, text, store=store)


def _chat_prompt(
    session: ChatSession,
    text: str,
    store: CampaignStore | None = None,
) -> str:
    return build_chat_memory_prompt(session, text, store=store)


def _path_from_intent(intent: ChatIntent, text: str, session: ChatSession) -> Path | None:
    if intent.path:
        path = Path(intent.path).expanduser()
        if path.exists() and path.is_dir():
            return path.resolve()
    return _extract_path(text, session)


def _is_help(lower: str) -> bool:
    return lower in {"help", "?", "h"} or "帮助" in lower


def _has_any(lower: str, needles: tuple[str, ...]) -> bool:
    return any(re.search(rf"\b{re.escape(needle)}\b", lower) for needle in needles)


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _tokens(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _clean_token(token: str) -> str:
    return token.strip().strip("`'\".,;:()[]{}，。；：（）【】")


def _extract_path(text: str, session: ChatSession) -> Path | None:
    for token in _tokens(text):
        path = _existing_dir_from_candidate(token)
        if path is not None:
            return path
    for candidate in _path_candidates(text):
        path = _existing_dir_from_candidate(candidate)
        if path is not None:
            return path
    lower = text.lower()
    if any(word in lower for word in ("this dir", "current dir", "cwd")) or any(
        word in text for word in ("当前目录", "这个目录", "这里")
    ):
        return Path.cwd().resolve()
    if session.target_path:
        path = Path(session.target_path).expanduser()
        if path.exists() and path.is_dir():
            return path.resolve()
    return None


def _existing_dir_from_candidate(candidate: str) -> Path | None:
    cleaned = _clean_token(candidate)
    if not cleaned or _is_noise_token(cleaned):
        return None
    path = Path(cleaned).expanduser()
    if path.exists() and path.is_dir():
        return path.resolve()
    return None


def _path_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for match in _PATH_CANDIDATE_RE.finditer(text):
        candidate = _clean_token(match.group(0))
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _looks_like_chat(text: str) -> bool:
    compact = text.strip().lower()
    greetings = {
        "hi",
        "hello",
        "hey",
        "你好",
        "您好",
        "嗨",
        "哈喽",
    }
    if compact in greetings:
        return True
    return any(
        phrase in text
        for phrase in (
            "你是谁",
            "你能做什么",
            "介绍一下",
            "怎么用",
            "如何使用",
            "谢谢",
            "thanks",
        )
    )


def _is_noise_token(token: str) -> bool:
    lower = token.lower()
    return (
        lower
        in {
            "analyze",
            "inspect",
            "run",
            "fuzz",
            "start",
            "status",
            "stop",
            "resume",
            "continue",
            "trace",
            "triage",
            "for",
            "with",
            "engine",
            "分析",
            "检查",
            "运行",
            "启动",
            "开始",
            "执行",
            "测试",
            "模糊测试",
            "状态",
            "进度",
            "停止",
            "终止",
            "取消",
            "恢复",
            "继续",
            "解释",
            "分诊",
        }
        or _duration_token(lower) is not None
        or lower in {kind.value for kind in EngineKind}
        or lower == "cargo_fuzz"
    )


def _extract_duration(text: str) -> int | None:
    for token in _tokens(text):
        seconds = _duration_token(_clean_token(token).lower())
        if seconds is not None:
            return seconds
    match = re.search(r"(\d+)\s*(秒钟?|分钟|分|小时|天)", text)
    if match:
        unit_seconds = _duration_unit_seconds(match.group(2))
        if unit_seconds is not None:
            return int(match.group(1)) * unit_seconds
    match = re.search(r"半\s*(秒钟?|分钟|分|小时|天)", text)
    if match:
        unit_seconds = _duration_unit_seconds(match.group(1))
        if unit_seconds is not None:
            return max(1, unit_seconds // 2)
    match = re.search(r"([零〇一二两三四五六七八九十百]+)\s*(秒钟?|分钟|分|小时|天)", text)
    if match:
        n = _parse_chinese_int(match.group(1))
        unit_seconds = _duration_unit_seconds(match.group(2))
        if n is not None and unit_seconds is not None:
            return n * unit_seconds
    if "一会儿" in text or "一会" in text:
        return 5 * 60
    return None


def _duration_unit_seconds(unit: str) -> int | None:
    if unit in {"秒", "秒钟"}:
        return 1
    if unit in {"分钟", "分"}:
        return 60
    if unit == "小时":
        return 3600
    if unit == "天":
        return 86400
    return None


def _parse_chinese_int(text: str) -> int | None:
    if not text:
        return None
    if text in _CHINESE_DIGITS:
        return _CHINESE_DIGITS[text]
    if "百" in text:
        head, _, tail = text.partition("百")
        hundreds = _CHINESE_DIGITS.get(head, 1 if not head else -1)
        if hundreds < 0:
            return None
        tail_value = _parse_chinese_int(tail) if tail else 0
        if tail_value is None:
            return None
        return hundreds * 100 + tail_value
    if "十" in text:
        head, _, tail = text.partition("十")
        tens = _CHINESE_DIGITS.get(head, 1 if not head else -1)
        ones = _CHINESE_DIGITS.get(tail, 0 if not tail else -1)
        if tens < 0 or ones < 0:
            return None
        return tens * 10 + ones
    return None


def _duration_token(token: str) -> int | None:
    match = re.fullmatch(
        r"(\d+)(s|sec|secs|second|seconds|m|min|mins|minute|minutes|"
        r"h|hr|hrs|hour|hours|d|day|days)",
        token,
    )
    if not match:
        return None
    n = int(match.group(1))
    unit = match.group(2)
    if unit in {"s", "sec", "secs", "second", "seconds"}:
        return n
    if unit in {"m", "min", "mins", "minute", "minutes"}:
        return n * 60
    if unit in {"h", "hr", "hrs", "hour", "hours"}:
        return n * 3600
    return n * 86400


def _extract_engine(text: str) -> EngineKind | None:
    lower = text.lower()
    if "cargo_fuzz" in lower:
        return EngineKind.CARGO_FUZZ
    for kind in EngineKind:
        if kind.value in lower:
            return kind
    return None


def _extract_campaign_id(text: str) -> str | None:
    match = re.search(r"(?:campaign(?:_id)?|cid)\s*[:=]?\s*([A-Za-z0-9_-]{6,})", text)
    if match:
        return match.group(1)
    for token in reversed(_tokens(text)):
        cleaned = _clean_token(token)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{5,}", cleaned):
            path = Path(cleaned).expanduser()
            if (
                not path.exists()
                and _duration_token(cleaned.lower()) is None
                and not _is_noise_token(cleaned)
            ):
                return cleaned
    return None


def _extract_top_n(text: str) -> int:
    match = re.search(r"(?:top|前)\s*(\d+)", text, re.IGNORECASE)
    if not match:
        return 10
    return max(1, min(100, int(match.group(1))))


def _format_profile(profile: TargetProfile) -> str:
    entries = ", ".join(profile.entry_points) if profile.entry_points else "未发现"
    return (
        f"目标: `{profile.root}`\n"
        f"语言: {profile.language.value}\n"
        f"构建系统: {profile.build_system}\n"
        f"候选入口: {entries}\n"
        f"备注: {profile.notes}"
    )


def _format_campaign_summary(summary: dict[str, Any]) -> str:
    cid = summary.get("campaign_id")
    stats = summary.get("stats") or {}
    paths = summary.get("paths") or {}
    crashes = _summary_crashes(summary)
    unique_crashes = _int_value(stats.get("unique_crashes"))
    has_crashes = bool(crashes) or unique_crashes > 0
    status = str(stats.get("status") or "unknown")
    lines = [
        _campaign_result_sentence(str(cid), status, has_crashes, len(crashes) or unique_crashes),
    ]
    overview = _campaign_overview_sentence(str(cid), stats)
    if overview:
        lines.extend(["", overview])
    if crashes:
        lines.extend(["", *_format_crash_summary(crashes, paths)])
    elif unique_crashes > 0:
        crash_dir = str(paths.get("crash_dir") or "")
        detail = "系统记录到了 crash 计数，但这次 summary 没带回具体分诊记录。"
        if crash_dir:
            detail += f" crash 文件目录在 `{crash_dir}`。"
        lines.extend(["", detail])
    artifact_text = _artifact_sentence(paths, has_crashes=has_crashes)
    if artifact_text:
        lines.extend(["", artifact_text])
    lines.extend(["", *_next_step_lines(str(cid), status, has_crashes)])
    return "\n".join(lines)


def _format_stats(stats: CampaignStats) -> str:
    return (
        f"campaign `{stats.campaign_id}`\n"
        f"状态: {stats.status.value}\n"
        f"运行时间: {stats.elapsed_sec}s\n"
        f"执行次数: {stats.execs_total}\n"
        f"速度: {stats.execs_per_sec:.2f}/s\n"
        f"覆盖边: {stats.edges_covered}"
        + (f"/{stats.edges_total}" if stats.edges_total is not None else "")
        + f"\ncorpus: {stats.corpus_size}\nunique crashes: {stats.unique_crashes}"
    )


def _format_trace(cid: str, trace: list[dict[str, Any]]) -> str:
    if not trace:
        return f"campaign `{cid}` 暂无 agent trace。"
    lines = [f"campaign `{cid}` 最近 {min(5, len(trace))} 条 agent trace:"]
    for i, row in enumerate(trace[-5:], start=max(1, len(trace) - 4)):
        decision = _dict_field(row, "decision")
        observation = _dict_field(row, "observation")
        action = decision.get("action", "")
        reason = decision.get("reason", "")
        phase = row.get("phase", "")
        diagnostics = _shorten(str(observation.get("diagnostics", "")), 180)
        lines.append(f"{i}. {phase}: {action} - {reason}")
        if diagnostics:
            lines.append(f"   诊断: {diagnostics}")
    return "\n".join(lines)


def _dict_field(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    return {}


def _format_crashes(cid: str, crashes: list[CrashRecord]) -> str:
    if not crashes:
        return f"campaign `{cid}` 没有可展示的 crash。"
    lines = [
        "结果",
        f"campaign `{cid}` crash 分诊结果如下，共 {len(crashes)} 个结果。",
        "",
        "Crash 证据",
    ]
    for idx, crash in enumerate(crashes[:5], start=1):
        frames = "; ".join(crash.top_frames[:3])
        lines.append(
            f"{idx}. `{crash.crash_id}` status={crash.status.value} "
            f"kind={crash.sanitizer_kind or 'unknown'} frames={frames}"
        )
        lines.extend(_format_crash_record_details(crash))
    if len(crashes) > 5:
        lines.append(f"- 还有 {len(crashes) - 5} 个 crash 未展示")
    lines.extend(["", "下一步", f"- 打开 campaign 页面 `/campaigns/{cid}` 查看 run log、harness 和 artifact。"])
    return "\n".join(lines)


def _format_crash_record_details(crash: CrashRecord) -> list[str]:
    lines: list[str] = []
    lines.append(f"  input: `{crash.input_path}`")
    preview = _input_preview(crash.input_path)
    if preview:
        lines.append(f"  input preview: `{preview}`")
    if crash.minimized_path:
        lines.append(f"  minimized: `{crash.minimized_path}`")
    if crash.reproduce_log_path:
        lines.append(f"  reproduce log: `{crash.reproduce_log_path}`")
    if crash.vulnerability_matches:
        match = crash.vulnerability_matches[0]
        suffix = f" ({match.cwe})" if match.cwe else ""
        lines.append(f"  match: {match.title}{suffix}")
    if crash.exploitability_notes:
        lines.append(f"  notes: {_shorten(crash.exploitability_notes, 180)}")
    return lines


def _summary_crashes(summary: dict[str, Any]) -> list[dict[str, Any]]:
    crashes = summary.get("crashes")
    if not isinstance(crashes, list):
        return []
    return [crash for crash in crashes if isinstance(crash, dict)]


def _campaign_result_sentence(
    cid: str,
    status: str,
    has_crashes: bool,
    crash_count: int,
) -> str:
    if has_crashes:
        suffix = "。这里的 `failed` 通常表示目标程序因 crash 退出，不代表 harness 构建失败。" if status == "failed" else "。"
        return f"本次 fuzz 已结束，并发现 {crash_count} 个 crash{suffix}"
    if status == "failed":
        return (
            "本次 fuzz 未正常完成，且没有记录到 crash。"
            "这更可能是引擎错误、运行环境问题、超时或构建产物异常。"
        )
    if status in {"stopped", "finished"}:
        return "本次 fuzz 已完成，暂未发现 crash。"
    return f"Campaign `{cid}` 当前状态为 `{status}`，暂未发现 crash。"


def _campaign_overview_sentence(cid: str, stats: dict[str, Any]) -> str:
    status = str(stats.get("status") or "unknown")
    elapsed = _int_value(stats.get("elapsed_sec"))
    unique_crashes = _int_value(stats.get("unique_crashes"))
    details = [
        f"运行约 {elapsed}s",
        f"记录到 {unique_crashes} 个 unique crash",
    ]
    if stats.get("execs_total") is not None:
        details.append(f"执行了 {stats.get('execs_total')} 次")
    if stats.get("execs_per_sec") is not None:
        details.append(f"速度约 {stats.get('execs_per_sec')}/s")
    if stats.get("edges_covered") is not None:
        details.append(f"覆盖到 {stats.get('edges_covered')} 条边")
    if stats.get("corpus_size") is not None:
        details.append(f"corpus 中有 {stats.get('corpus_size')} 个输入")
    return f"Campaign `{cid}` 的最终状态是 `{status}`；" + "，".join(details) + "。"


def _format_crash_summary(crashes: list[dict[str, Any]], paths: dict[str, Any]) -> list[str]:
    lines = [
        "结果解读",
        f"Crash 详情里带回了 {len(crashes)} 条记录。下面是面向判断的摘要，不需要先读原始日志。",
    ]
    for idx, crash in enumerate(crashes[:5], start=1):
        crash_id = str(crash.get("crash_id") or "unknown")
        status = str(crash.get("status") or "unknown")
        kind = str(crash.get("sanitizer_kind") or "unknown")
        explanation = _crash_explanation(crash)
        title = explanation.problem or kind
        lines.append(
            f"{idx}. Crash `{crash_id}` 当前是 `{status}`，主要问题是 {title}。"
        )
        lines.extend(_format_crash_explanation(crash, explanation))
        matches = _vulnerability_matches(crash)
        if matches and matches[0] != title:
            lines.append(f"   漏洞分类: {matches[0]}。")
        if kind == "unknown" and explanation.sanitizer:
            lines.append(f"   sanitizer: {explanation.sanitizer}。")
    if len(crashes) > 5:
        lines.append(f"还有 {len(crashes) - 5} 个 crash 没有在这条回复里展开。")
    crash_dir = str(paths.get("crash_dir") or "")
    if crash_dir:
        lines.append(f"完整 crash 输入和复现日志保存在 `{crash_dir}`。")
    return lines


def _format_crash_explanation(
    crash: dict[str, Any],
    explanation: CrashExplanation,
) -> list[str]:
    lines: list[str] = []
    if explanation.location:
        lines.append(f"   代码位置: {explanation.location}。")
    if explanation.access:
        lines.append(f"   触发行为: {explanation.access}。")
    if explanation.boundary:
        lines.append(f"   边界说明: {explanation.boundary}。")
    if explanation.allocation:
        lines.append(f"   相关分配: {explanation.allocation}。")

    input_path = _path_or_none(crash.get("input_path"))
    if input_path is not None:
        preview = _input_preview(input_path)
        size = _file_size(input_path)
        size_text = f"{size} bytes，" if size is not None else ""
        if preview:
            lines.append(f"   触发输入: {size_text}输入预览是 `{preview}`。")
        else:
            lines.append(f"   触发输入保存在 `{input_path}`。")

    minimized_path = _path_or_none(crash.get("minimized_path"))
    if minimized_path is not None:
        lines.append(f"   最小化后的输入在 `{minimized_path}`。")

    status = str(crash.get("status") or "unknown")
    reproduce_log = _path_or_none(crash.get("reproduce_log_path"))
    if status == "confirmed":
        lines.append("   可信度: 已复现，属于 confirmed crash。")
    elif status != "unknown":
        lines.append(f"   可信度: 当前状态是 `{status}`，需要结合复现结果判断。")
    if reproduce_log is not None:
        lines.append(f"   复现日志在 `{reproduce_log}`；这里已提取关键结论，不展开原始日志。")
    return lines


def _crash_explanation(crash: dict[str, Any]) -> CrashExplanation:
    log = _read_text_for_summary(crash.get("reproduce_log_path"))
    matches = _vulnerability_matches(crash)
    problem = matches[0] if matches else ""
    sanitizer = ""
    if log:
        sanitizer, sanitizer_problem = _asan_problem(log)
        problem = problem or sanitizer_problem
    if not problem:
        problem = str(crash.get("sanitizer_kind") or "unknown")
    return CrashExplanation(
        problem=problem,
        sanitizer=sanitizer,
        access=_asan_access(log),
        location=_first_frame(crash) or _top_log_frame(log),
        boundary=_asan_boundary(log),
        allocation=_asan_allocation_frame(log),
    )


def _asan_problem(log: str) -> tuple[str, str]:
    match = re.search(r"ERROR:\s+([^:]+):\s+([^\s]+)", log)
    if not match:
        return "", ""
    sanitizer = match.group(1).strip()
    kind = match.group(2).strip()
    return sanitizer, _friendly_sanitizer_kind(kind)


def _friendly_sanitizer_kind(kind: str) -> str:
    labels = {
        "heap-buffer-overflow": "堆缓冲区越界",
        "stack-buffer-overflow": "栈缓冲区越界",
        "global-buffer-overflow": "全局缓冲区越界",
        "use-after-free": "释放后使用",
        "double-free": "重复释放",
        "bad-free": "非法释放",
        "null-dereference": "空指针解引用",
        "integer-overflow": "整数溢出",
        "signed-integer-overflow": "有符号整数溢出",
    }
    label = labels.get(kind)
    return f"{label} ({kind})" if label else kind


def _asan_access(log: str) -> str:
    match = re.search(r"\b(READ|WRITE) of size (\d+)", log)
    if not match:
        return ""
    op = "读取" if match.group(1) == "READ" else "写入"
    return f"{op} {match.group(2)} 字节"


def _asan_boundary(log: str) -> str:
    match = re.search(r"\bis located ([^\n]+)", log)
    if not match:
        return ""
    return _shorten(match.group(1).strip(), 180)


def _asan_allocation_frame(log: str) -> str:
    _, marker, tail = log.partition("allocated by thread")
    if not marker:
        return ""
    for line in tail.splitlines()[:12]:
        frame = _frame_from_log_line(line)
        if not frame:
            continue
        lower = frame.lower()
        if "malloc" in lower or "operator new" in lower or "libclang_rt" in lower:
            continue
        return frame
    return ""


def _top_log_frame(log: str) -> str:
    for line in log.splitlines():
        frame = _frame_from_log_line(line)
        if frame:
            return frame
    return ""


def _frame_from_log_line(line: str) -> str:
    match = re.search(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+)$", line)
    if not match:
        return ""
    return _shorten(match.group(1).strip(), 220)


def _read_text_for_summary(value: Any, limit: int = 128 * 1024) -> str:
    path = _path_or_none(value)
    if path is None or not path.is_file():
        return ""
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _artifact_sentence(paths: dict[str, Any], *, has_crashes: bool) -> str:
    labels = (
        ("run log", "run_log"),
        ("agent trace", "agent_trace"),
        ("coverage summary", "coverage_summary"),
    )
    parts: list[str] = []
    for label, key in labels:
        path = _path_or_none(paths.get(key))
        if path is not None and path.is_file():
            parts.append(f"{label} 在 `{path}`")
    crash_dir = _path_or_none(paths.get("crash_dir"))
    if has_crashes and crash_dir is not None and crash_dir.is_dir():
        parts.append(f"crash 目录在 `{crash_dir}`")
    if not parts:
        return ""
    return "关键证据文件已经保存：" + "；".join(parts) + "。"


def _inline_artifact_sections(
    paths: dict[str, Any],
    crashes: list[dict[str, Any]],
) -> list[str]:
    candidates = _inline_artifact_candidates(paths, crashes)
    if not candidates:
        return []
    lines = [(
        "下面直接展示较小的本地 artifact；超过 "
        f"{_INLINE_ARTIFACT_FILE_LIMIT_BYTES} bytes 的文本文件会省略，"
        f"二进制文件超过 {_INLINE_BINARY_ARTIFACT_LIMIT_BYTES} bytes 会省略。"
    )]
    remaining = _INLINE_ARTIFACT_TOTAL_LIMIT_BYTES
    seen: set[Path] = set()
    for label, path, binary in candidates:
        resolved = path.expanduser()
        try:
            key = resolved.resolve()
        except OSError:
            key = resolved
        if key in seen:
            continue
        seen.add(key)
        section, used = _inline_file_section(
            label,
            resolved,
            binary=binary,
            remaining_bytes=remaining,
        )
        if section:
            lines.extend(["", *section])
        remaining = max(0, remaining - used)
    return lines if len(lines) > 1 else []


def _inline_artifact_candidates(
    paths: dict[str, Any],
    crashes: list[dict[str, Any]],
) -> list[tuple[str, Path, bool]]:
    candidates: list[tuple[str, Path, bool]] = []
    for crash in crashes[:5]:
        crash_id = str(crash.get("crash_id") or "unknown")
        _append_path_candidate(candidates, f"crash input `{crash_id}`", crash.get("input_path"), binary=True)
        _append_path_candidate(
            candidates,
            f"minimized crash input `{crash_id}`",
            crash.get("minimized_path"),
            binary=True,
        )
        _append_path_candidate(candidates, f"reproduce log `{crash_id}`", crash.get("reproduce_log_path"))

    _append_path_candidate(candidates, "run log", paths.get("run_log"))
    _append_path_candidate(candidates, "coverage summary", paths.get("coverage_summary"))
    _append_path_candidate(candidates, "coverage uncovered JSON", paths.get("coverage_uncovered"))
    _append_path_candidate(candidates, "agent trace JSONL", paths.get("agent_trace"))
    _append_path_candidate(candidates, "events JSONL", paths.get("events_log"))
    _append_path_candidate(candidates, "campaign meta JSON", paths.get("meta"))

    for label, value in _artifact_paths_from_meta(paths.get("meta")):
        _append_path_candidate(candidates, label, value)
    base = _path_or_none(paths.get("base"))
    if base is not None:
        for name, label in (
            ("input_model.json", "input model JSON"),
            ("extra.dict", "coverage dictionary"),
        ):
            path = base / name
            if path.exists():
                candidates.append((label, path, False))
    return candidates


def _append_path_candidate(
    candidates: list[tuple[str, Path, bool]],
    label: str,
    value: Any,
    *,
    binary: bool = False,
) -> None:
    path = _path_or_none(value)
    if path is None or not path.exists():
        return
    candidates.append((label, path, binary))


def _artifact_paths_from_meta(meta_value: Any) -> list[tuple[str, Path]]:
    meta_path = _path_or_none(meta_value)
    if meta_path is None or not meta_path.is_file():
        return []
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    artifact = payload.get("artifact") if isinstance(payload, dict) else None
    if not isinstance(artifact, dict):
        return []
    out: list[tuple[str, Path]] = []
    build_log = _path_or_none(artifact.get("build_log_path"))
    if build_log is not None:
        out.append(("build log", build_log))
    harness = _path_or_none(artifact.get("harness_source_path"))
    if harness is not None:
        out.append(("harness source", harness))
    return out


def _path_or_none(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value:
        return Path(value)
    return None


def _inline_file_section(
    label: str,
    path: Path,
    *,
    binary: bool,
    remaining_bytes: int,
) -> tuple[list[str], int]:
    if not path.exists():
        return ([f"{label} `{path}` 未找到，无法内联。"], 0)
    if not path.is_file():
        return ([], 0)
    try:
        size = path.stat().st_size
    except OSError as exc:
        return ([f"{label} `{path}` 无法读取大小：{exc}。"], 0)
    limit = (
        _INLINE_BINARY_ARTIFACT_LIMIT_BYTES
        if binary
        else _INLINE_ARTIFACT_FILE_LIMIT_BYTES
    )
    if size > limit:
        return ([f"{label} `{path}` 大小为 {size} bytes，超过 {limit} bytes，已省略。"], 0)
    if size > remaining_bytes:
        return ([f"{label} `{path}` 因本条回复 artifact 展示预算不足，已省略。"], 0)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return ([f"{label} `{path}` 读取失败：{exc}。"], 0)
    if binary or _looks_binary(data):
        return (_binary_file_section(label, path, data), size)
    text = data.decode("utf-8", errors="replace")
    return (_text_file_section(label, path, text), size)


def _text_file_section(label: str, path: Path, text: str) -> list[str]:
    return [
        f"{label} `{path}`：",
        *_fenced_lines("text", text if text else "<empty>"),
    ]


def _binary_file_section(label: str, path: Path, data: bytes) -> list[str]:
    encoded = base64.b64encode(data).decode("ascii")
    return [
        f"{label} `{path}`（{len(data)} bytes，按二进制展示）：",
        *_fenced_lines("hex", data.hex(" ") if data else "<empty>"),
        f"base64: `{encoded}`",
    ]


def _fenced_lines(language: str, text: str) -> list[str]:
    fence = "```"
    while fence in text:
        fence += "`"
    return [f"{fence}{language}", text.rstrip("\n"), fence]


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _next_step_lines(cid: str, status: str, has_crashes: bool) -> list[str]:
    if has_crashes:
        return [
            f"下一步可以输入 `triage {cid}` 刷新分诊结果，确认是否还有重复或新分类。",
            f"完整原始日志、harness 和 artifact 可在 `/campaigns/{cid}` 查看。",
        ]
    if status == "failed":
        return [
            "下一步优先查看 agent trace 和错误事件，确认是引擎错误、环境问题还是目标程序异常退出。",
            f"完整原始日志和 artifact 可在 `/campaigns/{cid}` 查看。",
        ]
    return [
        "下一步可以延长运行时间继续探索，或查看 coverage 结果寻找未覆盖路径。",
        f"完整运行记录和 artifact 可在 `/campaigns/{cid}` 查看。",
    ]


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return 0
    return 0


def _input_preview(path: Path, limit: int = 32) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    if not data:
        return "<empty>"
    text = data.decode("utf-8", errors="replace")
    if all(ch.isprintable() and ch not in "\r\n\t" for ch in text):
        return text
    return data.hex()


def _first_frame(crash: dict[str, Any]) -> str:
    frames = crash.get("top_frames")
    if isinstance(frames, list) and frames:
        return str(frames[0])
    return ""


def _vulnerability_matches(crash: dict[str, Any]) -> list[str]:
    raw = crash.get("vulnerability_matches")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        title = item.get("title")
        cwe = item.get("cwe")
        if isinstance(title, str) and title:
            out.append(f"{title}" + (f" ({cwe})" if isinstance(cwe, str) and cwe else ""))
    return out


def _shorten(text: str, limit: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _help_text() -> str:
    return (
        "可用对话命令：\n"
        "- `analyze <path>`：分析目标目录\n"
        "- `run <path> 30m [libfuzzer|cargo-fuzz]`：运行一次完整 fuzz campaign\n"
        "- `status [campaign_id]`：查看状态\n"
        "- `stop [campaign_id]`：停止运行中的 campaign\n"
        "- `resume <campaign_id> [10m]`：从已有 corpus 恢复\n"
        "- `trace [campaign_id]`：解释最近 agent 决策轨迹\n"
        "- `triage [campaign_id]`：分诊 crash\n"
        "- 也支持常见自然语言，例如 `对demo_targets/real_target_crash进行fuzz测试一分钟`\n"
        "- 设置 `OPENAI_API_KEY` 后，可以用更自由的自然语言表达\n"
        "- `quit`：退出 CLI 对话"
    )


def _fallback_chat_text(text: str) -> str:
    if text.strip().lower() in {"hi", "hello", "hey"} or text.strip() in {"你好", "您好", "嗨", "哈喽"}:
        return (
            "你好。我是 fuzz-agent 的对话入口，可以帮你分析目标、启动 fuzz、查看状态、"
            "解释 agent trace 和分诊 crash。输入 `help` 可以查看命令。"
        )
    if "你能做什么" in text or "怎么用" in text or "如何使用" in text:
        return _help_text()
    return (
        "我可以闲聊一些基础问题，但完整自然语言理解需要设置 `OPENAI_API_KEY`。"
        "目前也可以直接用 `help` 里的命令驱动 fuzz-agent。"
    )


def _unknown_text() -> str:
    return (
        "我还不能可靠理解这条指令。可用命令：`analyze <path>`、`run <path> 30m`、"
        "`status [campaign_id]`、`stop [campaign_id]`、`resume <campaign_id>`、"
        "`trace [campaign_id]`、`triage [campaign_id]`。设置 `OPENAI_API_KEY` 后可以启用自然语言解析。"
    )
