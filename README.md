# fuzz-agent

## 项目简介

`fuzz-agent` 是一个面向 harness engineering 的 fuzz 编排器。它通过
OpenAI-compatible LLM 生成和修复 fuzz harness，但关键判断依赖可验证的工程反馈：
目标分析、构建日志、fuzz 引擎事件、coverage、crash artifact、reproduce 结果和
持久化 campaign 状态。

当前主线能力是 C/C++ + LibFuzzer；Rust + `cargo-fuzz` 已接入；Python + Atheris 有
adapter，但整体仍偏早期。AFL++、Jazzer、Go native fuzz 目前主要是枚举和规划层面的
占位。

项目目标不是替代 fuzz engine，而是把目标分析、harness 生成、构建验证、运行监督、
coverage 反馈、crash 复现分诊和产物持久化串成可恢复的工程闭环。



## 架构

```text
CLI / Web UI / Chat
        |
        v
Orchestrator
  analyze -> agent harness -> build -> launch -> supervise -> triage
        |
        +--------------------+
        |                    |
        v                    v
Tool facade              EventBus
  analyze/build          heartbeat/new_coverage/new_crash/plateau
  campaign/triage
  observe/strategy
        |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
Engine adapters       Subagents             CampaignStore
  LibFuzzer             harness_writer        SQLite + JSONL/files
  cargo-fuzz            coverage_analyst      campaigns/crashes/stats
  Atheris               crash_triage          agent trace/chat sessions
                        exploit_assessor
                        vulnerability_matcher
```

核心分层原则：

- `state.models` 定义跨层共享数据契约。
- `tools` 是 orchestrator 唯一直接调用的工具门面。
- `engines` 屏蔽 LibFuzzer、cargo-fuzz、Atheris 的构建、运行和复现差异。
- `subagents` 负责 LLM 或规则驱动的窄任务，例如 harness 生成、coverage 分析和
  crash triage。
- `CampaignStore` 负责 SQLite 和文件系统持久化。
- `EventBus` 负责进程内 campaign 事件发布/订阅，并支撑 plateau 检测和 Web SSE。

`agent_harness` 是外层 harness engineering 闭环：它会围绕一个入口函数反复执行
`generate_harness -> build -> validate artifact -> smoke_run -> target_reached ->
policy decision`，并把每次 attempt 写入结构化 trace。`harness_writer` 生成的是内层
fuzz harness，即把 fuzz bytes 接到目标函数的适配代码。

## 项目环境

本项目以 `uv` 管理本地 Python 环境和依赖锁定。建议所有本地启动、Web UI、Chat 和开发验证
都通过 `uv run` 执行，避免绕过 `uv.lock`。

基础要求：

- Python `>=3.11`
- `uv`
- 按实际 fuzz engine 安装对应外部工具

同步基础依赖：

```bash
uv sync
```

同步 Web UI 依赖：

```bash
uv sync --extra web
```

同步开发和 Web UI 全量依赖：

```bash
uv sync --all-extras
```

确认 CLI 可用：

```bash
uv run fuzz-agent --help
```

LLM 配置使用 OpenAI-compatible 接口：

```bash
export OPENAI_API_KEY=...
# 可选：兼容 OpenAI API 的其他服务
export OPENAI_BASE_URL=https://example.com/v1
export FUZZ_AGENT_MODEL=gpt-4o-mini
```

外部工具按需要安装：

- C/C++ LibFuzzer：`clang`
- Rust cargo-fuzz：`cargo` 和 `cargo install cargo-fuzz`
- coverage：`llvm-profdata`、`llvm-cov`
- crash symbolization：`llvm-symbolizer`，缺失时会降级
- sandbox：可选 `docker` 或 `nsjail`

## 快速开始

C/C++ LibFuzzer：

```bash
uv run fuzz-agent analyze ./my-cpp-target
uv run fuzz-agent run ./my-cpp-target --engine libfuzzer --time 30m
```

Rust cargo-fuzz：

```bash
uv run fuzz-agent analyze ./my-rust-crate
uv run fuzz-agent run ./my-rust-crate --engine cargo-fuzz --time 30m
```

查看状态、分诊和恢复：

```bash
uv run fuzz-agent status <campaign_id>
uv run fuzz-agent triage <campaign_id>
uv run fuzz-agent resume <campaign_id> --time 30m
```

常用 run 选项：

```bash
uv run fuzz-agent run ./target --engine libfuzzer --time 30m --max-crashes 50 --plateau 300
uv run fuzz-agent run ./target --engine libfuzzer --time 30m --no-triage
```

启动 Web UI：

```bash
uv run fuzz-agent serve --host 127.0.0.1 --port 8000
```

启动 CLI Chat：

```bash
uv run fuzz-agent chat
```

Chat 支持规则优先命令：

```text
analyze <path>
run <path> 30m [libfuzzer|cargo-fuzz|atheris]
status [campaign_id]
stop [campaign_id]
resume <campaign_id> [10m]
trace [campaign_id]
triage [campaign_id]
```

设置 `OPENAI_API_KEY` 后，Chat 会尝试使用 LLM 解析更自由的自然语言意图。可用
`FUZZ_AGENT_CHAT_LLM=off` 关闭该路径。

## Web UI

Web UI 默认只允许 loopback client。确实需要远程访问时显式开启：

```bash
export FUZZ_AGENT_WEB_ALLOW_REMOTE=1
```

主要页面：

- `/` 和 `/campaigns`：campaign 列表和创建入口。
- `/campaigns/{cid}`：campaign artifact 只读详情页。
- `/chat`：对话式 workbench，包含 session 列表、command hints、campaign context panel
  和 streaming response。

主要 API：

- `GET /api/campaigns`
- `POST /api/campaigns`
- `GET /api/campaigns/{cid}`
- `GET /api/campaigns/{cid}/stats`
- `GET /api/campaigns/{cid}/crashes`
- `GET /api/campaigns/{cid}/crashes/{crash_id}`
- `GET /api/campaigns/{cid}/agent-trace`
- `GET /api/campaigns/{cid}/logs/run`
- `GET /api/campaigns/{cid}/logs/build`
- `GET /api/campaigns/{cid}/harness`
- `GET /api/campaigns/{cid}/coverage/summary`
- `GET /api/campaigns/{cid}/coverage/uncovered`
- `GET /api/campaigns/{cid}/events`
- `POST /api/campaigns/{cid}/stop`
- `GET /api/chat/sessions`
- `GET /api/chat/sessions/{session_id}`
- `POST /api/chat`
- `POST /api/chat/stream`

## Engine 语义

### LibFuzzer

LibFuzzer build 会使用 `clang`，并带上 `-fsanitize=fuzzer,<sanitizers>`。当前 C/C++
路径依赖 `HarnessSpec.extra_sources` 指向目标源码，生成产物通常在：

```text
<target>/.fuzz/harness/<entry>/attempt_N.*
<target>/.fuzz/build/build_<entry>_attempt_N.log
<target>/.fuzz/build/fuzz_<entry>_attempt_N
```

coverage helper 会额外构建 coverage binary，使用 `llvm-profdata merge` 和
`llvm-cov report/export` 生成 coverage summary 与未覆盖函数信息。

### cargo-fuzz

`cargo-fuzz` engine 会把 LLM 生成的 Rust harness 安装到目标 crate 下：

```text
<crate>/fuzz/fuzz_targets/<entry>_attempt_N.rs
<crate>/fuzz/Cargo.toml
```

build 阶段会执行：

```bash
cargo fuzz run <target> -- -runs=0
```

run 阶段会使用当前 campaign 的持久化 corpus/crash 目录。`FUZZ_AGENT_CARGO` 可用于指定
cargo 可执行文件路径。

### Atheris

Atheris adapter 当前主要覆盖 Python harness 的基础路径：build 阶段做 `import atheris`
可用性检查，artifact 指向 Python harness，run/reproduce/minimize 已有基础实现。自动 harness
生成和 coverage 闭环还没有达到 LibFuzzer 路径的成熟度。

## Campaign 生命周期

一次完整 run 会经历：

```text
analyze -> generate harness -> build -> validate -> smoke run -> start campaign
        -> supervise events -> triage crashes -> finalize
```

`Orchestrator` 监督这些事件：

- `NEW_CRASH`：自动触发 crash triage。
- `NEW_COVERAGE`：更新 plateau 检测状态。
- `PLATEAU`：调用 coverage strategy，把建议 seed 和 dictionary token 写回 campaign。
- `OOM` / `ENGINE_ERROR`：记录事件；自动恢复仍需继续完善。

停止条件包括时间预算耗尽、campaign 状态变为 stopped/failed、unique crashes 达到上限。

## 产物标注

`fuzz-agent` 的运行产物默认保存在本地工作目录和目标项目的 `.fuzz/` 目录中。核心产物按用途
标注如下：

| 标注 | 路径 | 说明 |
| --- | --- | --- |
| 状态数据库 | `state/state.db` | SQLite 状态库，保存 campaign、stats、events、crashes 和 chat session。 |
| campaign 元数据 | `state/campaigns/<campaign_id>/meta.json` | 单次 campaign 的配置、artifact 引用和生命周期信息。 |
| 事件日志 | `state/campaigns/<campaign_id>/events.jsonl` | heartbeat、new coverage、new crash、plateau、OOM、engine error 等事件。 |
| 引擎运行日志 | `state/campaigns/<campaign_id>/run.log` | fuzz engine 标准输出和错误输出的持久化记录。 |
| corpus | `state/campaigns/<campaign_id>/corpus/` | 当前 campaign 使用和增长的输入语料。 |
| crash artifact | `state/campaigns/<campaign_id>/crashes/` | fuzz engine 发现的 crash 输入和相关复现材料。 |
| coverage summary | `state/campaigns/<campaign_id>/coverage_summary.txt` | LibFuzzer coverage 的文本摘要。 |
| uncovered functions | `state/campaigns/<campaign_id>/coverage_uncovered.json` | 未覆盖函数和策略变异输入。 |
| input model | `state/campaigns/<campaign_id>/input_model.json` | coverage plateau 后推断出的 magic、字段、token 和 seed 模板。 |
| agent trace | `state/campaigns/<campaign_id>/agent_trace.jsonl` | harness 生成、构建、验证、策略决策和重试 trace。 |
| pre-campaign trace | `state/agent_sessions/<session_id>/agent_trace.jsonl` | campaign 创建前全部构建失败时保留的 agent trace。 |
| generated harness | `<target>/.fuzz/harness/<entry>/attempt_N.*` | LLM 或 fallback 生成的 harness 源码与 dictionary。 |
| build artifact | `<target>/.fuzz/build/fuzz_<entry>_attempt_N` | LibFuzzer 等 engine 构建出的 fuzz binary。 |
| build log | `<target>/.fuzz/build/build_<entry>_attempt_N.log` | harness 构建日志，用于修复和审计。 |

默认状态目录在当前工作目录：

```text
state/state.db
state/campaigns/<campaign_id>/meta.json
state/campaigns/<campaign_id>/events.jsonl
state/campaigns/<campaign_id>/run.log
state/campaigns/<campaign_id>/corpus/
state/campaigns/<campaign_id>/crashes/
state/campaigns/<campaign_id>/coverage_summary.txt
state/campaigns/<campaign_id>/coverage_uncovered.json
state/campaigns/<campaign_id>/agent_trace.jsonl
```

如果构建阶段在创建 campaign 前全部失败，会写入 pre-campaign session：

```text
state/agent_sessions/<session_id>/agent_trace.jsonl
```

Chat session 会持久化到 SQLite 的 `chat_sessions` 表。

## 漏洞匹配

`triage` 会在 crash reproduce 之后自动填充 `vulnerability_matches`。内置规则会根据
sanitizer kind、crash log 和 top frames 匹配常见 CWE，例如：

- `heap-use-after-free` -> `CWE-416`
- `double-free` -> `CWE-415`
- `heap/stack/global-buffer-overflow` 写越界 -> `CWE-787`
- `heap/stack/global-buffer-overflow` 读越界 -> `CWE-125`
- `integer-overflow` -> `CWE-190`
- `null dereference` -> `CWE-476`
- timeout/OOM -> DoS 相关 CWE

也可以通过 `FUZZ_AGENT_VULN_RULES` 加载项目专属规则，用于匹配具体 CVE 或内部漏洞编号：

```bash
export FUZZ_AGENT_VULN_RULES=/path/to/vuln_rules.json
```

规则格式：

```json
{
  "rules": [
    {
      "rule_id": "CVE-2099-0001",
      "title": "Demo parser known overflow",
      "cwe": "CWE-787",
      "confidence": 0.99,
      "sanitizer_kind": "heap-buffer-overflow",
      "frame_regex": "parse_thing",
      "log_regex": "magic-token"
    }
  ]
}
```

同一条规则里的 `sanitizer_kind`、`frame_regex`、`log_regex` 会按 AND 关系匹配；至少需要
提供其中一个条件。

## Sandbox 与 HITL

通过 `FUZZ_AGENT_SANDBOX` 选择 sandbox provider：

```bash
export FUZZ_AGENT_SANDBOX=none
export FUZZ_AGENT_SANDBOX=docker
export FUZZ_AGENT_SANDBOX=nsjail
```

`none` 是开发默认值，会发出 warning；`docker` 或 `nsjail` 不可用时会直接失败，避免误以为
已隔离运行。

HITL provider 用于高风险结果或动作确认：

```bash
export FUZZ_AGENT_HITL=allow
export FUZZ_AGENT_HITL=deny
export FUZZ_AGENT_HITL=cli
```

默认 provider 是 always-allow 风格，适合本地开发；`deny` 会拒绝需要确认的动作；
`cli` 会在命令行交互确认。

## 开发验证

```bash
uv run ruff check fuzz_agent tests
uv run mypy fuzz_agent
uv run pytest -q
```

当前测试覆盖重点：

- 数据模型序列化和 `CampaignStore` 持久化。
- target analyze 启发式。
- LibFuzzer status/crash/OOM/timeout 解析。
- cargo-fuzz build/run/reproduce adapter 行为。
- agent harness session retry、validation、trace。
- orchestrator 对失败 harness trace、finalize、plateau policy 的处理。
- campaign resume、strategy mutation、observe tools。
- crash reproduce、vulnerability matcher、harness fault 分类。
- EventBus 和 plateau 事件。
- Web API、artifact endpoint、local-only middleware、chat session 持久化。
- Chat rule/LLM intent 解析。
