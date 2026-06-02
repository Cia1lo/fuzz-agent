# fuzz-agent

`fuzz-agent` 是一个面向 harness engineering 的 fuzz 编排器。它通过
OpenAI-compatible LLM 生成和修复 fuzz harness，但关键判断依赖可验证的工程反馈：
目标分析、构建日志、fuzz 引擎事件、coverage、crash artifact、reproduce 结果和
持久化 campaign 状态。

当前主线能力是 C/C++ + LibFuzzer；Rust + `cargo-fuzz` 已接入；Python + Atheris 有
adapter，但整体仍偏早期。AFL++、Jazzer、Go native fuzz 目前主要是枚举和规划层面的
占位。

## 当前进度

| 能力 | 状态 |
| --- | --- |
| C/C++ target 分析与 LibFuzzer harness 生成 | 已实现 |
| LibFuzzer build/run/reproduce/minimize | 已实现 |
| Rust target 分析与 cargo-fuzz harness 生成 | 已实现 |
| cargo-fuzz build/run/reproduce/minimize | 已实现 |
| Python Atheris adapter | 实验性：import check、run、reproduce/minimize 基础路径 |
| Agent harness 生成/构建/验证/重试 trace | 已实现 |
| Campaign background run、resume、stop、status | 已实现 |
| EventBus heartbeat/new coverage/new crash/plateau 事件 | 已实现 |
| LibFuzzer coverage summary/uncovered function 输出 | 已实现 |
| Coverage plateau 后的 seed/dictionary 策略变异 | 已实现 |
| Crash reproduce、去重、confirmed/non-reproducible/flaky 状态 | 已实现 |
| 漏洞类型/CWE 匹配和自定义规则 | 已实现 |
| CLI 与规则优先 Chat facade | 已实现 |
| Web UI campaign/artifact/chat 工作台 | 已实现 |
| Web SSE events 和 chat streaming | 已实现 |
| Web 默认 local-only 访问保护 | 已实现 |
| Docker/nsjail sandbox provider | 已实现基础包装 |
| AFL++、Jazzer、Go native fuzz | 暂未真正接入 |

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

## 安装

```bash
pip install -e .
```

开发和 Web UI 依赖：

```bash
pip install -e ".[dev,web]"
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
fuzz-agent analyze ./my-cpp-target
fuzz-agent run ./my-cpp-target --engine libfuzzer --time 30m
```

Rust cargo-fuzz：

```bash
fuzz-agent analyze ./my-rust-crate
fuzz-agent run ./my-rust-crate --engine cargo-fuzz --time 30m
```

查看状态、分诊和恢复：

```bash
fuzz-agent status <campaign_id>
fuzz-agent triage <campaign_id>
fuzz-agent resume <campaign_id> --time 30m
```

常用 run 选项：

```bash
fuzz-agent run ./target --engine libfuzzer --time 30m --max-crashes 50 --plateau 300
fuzz-agent run ./target --engine libfuzzer --time 30m --no-triage
```

启动 Web UI：

```bash
fuzz-agent serve --host 127.0.0.1 --port 8000
```

启动 CLI Chat：

```bash
fuzz-agent chat
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

## 产物位置

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
ruff check fuzz_agent tests
mypy fuzz_agent
pytest -q
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

## 当前限制

- LibFuzzer 只支持 C/C++，且构建依赖 `HarnessSpec.extra_sources` 和本地 `clang`。
- target analyze 和入口点发现是正则启发式，不是完整语义分析。
- cargo-fuzz 需要目标路径是具体 Rust package；纯 workspace root 需要先选择实际 crate。
- cargo-fuzz coverage 尚未完善，结构化 coverage 主要是 LibFuzzer 路径。
- Atheris adapter 存在，但不是当前最成熟路径；使用前需要补齐实际 Python harness 生成和
  验证细节。
- AFL++、Jazzer、Go native fuzz 尚未真正接入。
- 默认 `FUZZ_AGENT_SANDBOX=none` 无隔离，只适合本地可信目标。
- LLM 输出经过 JSON 解析和部分 payload 验证，但真正文件写入仍应通过工具层控制。
- Web 默认 local-only；不要在未配置认证/隔离前直接暴露到公网。
