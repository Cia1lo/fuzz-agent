# fuzz-agent 项目说明

本文档基于当前目录代码整理，用于帮助后续维护者或自动化 agent 快速理解项目架构、功能边界、技术栈和常用工作流。

## 项目定位

`fuzz-agent` 是一个面向 harness engineering 的 fuzz 编排器。它通过 OpenAI-compatible LLM 生成和修复 fuzz harness，但关键判断依赖可验证的工程反馈：目标分析、构建日志、fuzz 引擎事件、coverage、crash artifact、reproduce 结果和持久化 campaign 状态。

当前主线能力是 C/C++ + LibFuzzer；Rust + `cargo-fuzz` 已接入；Python + Atheris 有 adapter，但整体能力相对早期。AFL++、Jazzer、Go native fuzz 目前主要是枚举和规划层面的占位。

## 总体架构

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

- `state.models` 定义跨层共享数据契约，其他层围绕这些 dataclass 和 enum 协作。
- `tools` 是 orchestrator 唯一直接调用的工具门面；具体实现分散在 `tools/*.py`。
- `engines` 屏蔽 LibFuzzer、cargo-fuzz、Atheris 等引擎差异。
- `subagents` 负责 LLM 或规则驱动的窄任务，例如生成 harness、分析 coverage、评估 crash。
- `CampaignStore` 负责 SQLite 和文件系统持久化。
- `EventBus` 负责进程内 campaign 事件发布/订阅，并支撑 plateau 检测和 Web SSE。

## 关键目录

| 路径 | 作用 |
| --- | --- |
| `fuzz_agent/cli.py` | Click CLI 入口，提供 `serve/analyze/run/triage/resume/status/chat`。 |
| `fuzz_agent/orchestrator.py` | 主控制循环，串联分析、harness 准备、campaign 运行、事件监督和最终分诊。 |
| `fuzz_agent/state/` | 核心数据模型和持久化存储。 |
| `fuzz_agent/tools/` | 可调用工具层，封装分析、构建、campaign 控制、观测、分诊和策略变异。 |
| `fuzz_agent/engines/` | fuzz 引擎 adapter：LibFuzzer、cargo-fuzz、Atheris、LLVM coverage helper。 |
| `fuzz_agent/agent_harness/` | 外层 agent harness engineering 闭环：观察、策略、验证、trace。 |
| `fuzz_agent/subagents/` | LLM/规则子任务：harness 生成、coverage 分析、crash triage、漏洞匹配等。 |
| `fuzz_agent/events/` | `EventBus` 与 `PlateauDetector`。 |
| `fuzz_agent/sandbox/` | `none/docker/nsjail` sandbox provider。 |
| `fuzz_agent/web/` | FastAPI + Jinja2 Web UI、artifact API、SSE events、聊天页面。 |
| `fuzz_agent/chat/` | 对话式命令 facade，规则优先，可选 LLM intent 解析。 |
| `tests/` | 单元测试与 fake target 场景。 |
| `demo_targets/` | 手工演示用 C/C++ fake targets。 |

## 核心数据模型

主要定义在 `fuzz_agent/state/models.py`：

- `TargetProfile`：目标项目分析结果，包括 root、language、entry_points、build_system、dependencies、notes。
- `HarnessSpec`：待构建 harness，包括目标、入口、engine、source_path、dictionary、sanitizers、extra_sources、compile/link flags、attempt。
- `BuildArtifact`：构建产物，包括 binary_path、engine、sanitizers、build_log_path、harness_source_path。
- `CampaignConfig`：一次 fuzz campaign 的运行配置，包括 artifact、corpus/crash 目录、dictionary、时间预算、内存和 resume 信息。
- `CampaignStats`：轻量状态快照，包括运行时间、执行次数、覆盖边、corpus size、unique crashes 等。
- `CrashRecord`：crash 去重和分诊结果，包括 input、minimized input、top frames、sanitizer kind、reproduce 状态、漏洞匹配。
- `FuzzEvent`：引擎事件，包括 `new_coverage/new_crash/plateau/oom/timeout/engine_error/heartbeat`。

这些模型是跨层协作的契约。新增功能时优先扩展模型和工具接口，再让 orchestrator 使用。

## 主要功能

### 目标分析

入口：`tools.analyze_target()`，实现：`tools/analyze.py`。

当前通过项目文件判断语言和构建系统：

- Rust：`Cargo.toml`
- Go：`go.mod`
- Python：`pyproject.toml` / `setup.py`
- Java：`pom.xml` / Gradle
- C++：`CMakeLists.txt`
- C：`Makefile`

入口点候选通过正则扫描常见 parse/decode/deserialize 函数。该逻辑是启发式的，不是完整代码索引。

### Harness 生成

入口：`tools.generate_harness()`，实现：`subagents/harness_writer.py` 和 `subagents/harness_context.py`。

流程：

1. `harness_context.pack_context()` 收集入口函数源码位置、签名、邻近源码、include/use、compile flags、link hints、sample inputs。
2. `harness_writer` 调用 OpenAI-compatible LLM，要求返回严格 JSON：`source` 和可选 `dictionary`。
3. 输出写入目标项目下：

```text
<target>/.fuzz/harness/<entry>/attempt_N.<ext>
<target>/.fuzz/harness/<entry>/attempt_N.dict
```

LibFuzzer harness 输出 `LLVMFuzzerTestOneInput`；cargo-fuzz harness 输出 `libfuzzer_sys::fuzz_target!` fuzz target。

### Agent Harness 闭环

入口：`AgentHarnessSession`，目录：`fuzz_agent/agent_harness/`。

它是“外层 agent harness engineering”循环，负责把一个 harness 生成到可用状态：

```text
generate_harness -> build -> validate artifact -> smoke_run -> target_reached -> policy decision
```

重要组件：

- `observation.py`：结构化观察和评分，如编译是否成功、smoke 是否通过、目标是否被引用。
- `validators.py`：构建产物验证、目标引用验证、harness-owned crash 判断。
- `policy.py`：默认 deterministic policy；也有 LLM-backed policy，但输出必须经过 schema 验证。
- `trace.py`：记录每次尝试的 observation、decision、action、result、score。

成功启动 campaign 后，trace 会写入：

```text
state/campaigns/<campaign_id>/agent_trace.jsonl
```

如果构建阶段在创建 campaign 前全部失败，会写入 pre-campaign session：

```text
state/agent_sessions/<session_id>/agent_trace.jsonl
```

### 构建

入口：`tools.build_target()`，实现：`tools/build.py`。

构建逻辑委托到对应 engine：

- LibFuzzer：`LibFuzzerEngine.build()` 使用 `clang`，参数包含 `-fsanitize=fuzzer,<sanitizers>`，需要 `HarnessSpec.extra_sources` 指向目标源码。
- cargo-fuzz：`CargoFuzzEngine.build()` 将生成的 Rust harness 复制到 `<crate>/fuzz/fuzz_targets/<target>.rs`，维护 `<crate>/fuzz/Cargo.toml`，再执行 `cargo fuzz run <target> -- -runs=0`。
- Atheris：`AtherisEngine.build()` 当前主要做 `import atheris` 可用性检查，artifact 指向 Python harness。

构建产物通常位于：

```text
<target>/.fuzz/build/build_<entry>_attempt_N.log
<target>/.fuzz/build/fuzz_<entry>_attempt_N
```

### Campaign 运行与监督

入口：`tools.start_fuzz_campaign()` 和 `Orchestrator.run()`。

`tools/campaign.py` 创建 campaign、复制初始 corpus、提交后台 asyncio 任务，并把引擎事件写入 store 和 bus。

运行状态目录：

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

`Orchestrator._supervise()` 订阅 EventBus，处理：

- `NEW_CRASH`：自动触发 crash triage。
- `NEW_COVERAGE`：更新 plateau 检测状态。
- `PLATEAU`：生成 coverage observation，调用 coverage strategy policy 和 `mutate_strategy()`，必要时重启 campaign。
- `OOM/ENGINE_ERROR`：当前主要记录，自动恢复还未完善。

停止条件包括时间预算耗尽、状态 stopped/failed、unique crashes 达到上限。

### Coverage 与策略变异

LibFuzzer 的 coverage helper 在 `engines/coverage.py`：

- 使用 `-fprofile-instr-generate` 和 `-fcoverage-mapping` 构建 coverage binary。
- 使用 `llvm-profdata merge` 合并 `.profraw`。
- 使用 `llvm-cov report/export` 输出覆盖摘要和未覆盖函数。

`tools/strategy.py` 调用 `coverage_analyst`，基于 uncovered coverage 建议 seed 和 dictionary token，并写回当前 campaign corpus 和 `extra.dict`。目前这是 coverage plateau 处理的主要自动策略。

### Crash 分诊与漏洞匹配

入口：`tools.triage_crashes()`，实现：`tools/triage.py`。

流程：

1. `crash_triage` 扫描 crash 目录，读取 crash log，提取 top frames 和 sanitizer kind。
2. 用 stack frames 或输入 bytes 生成 stack hash 去重。
3. 调用 engine `reproduce()` 复现单个 crash。
4. 标记 `confirmed/non_reproducible/flaky`。
5. `vulnerability_matcher` 根据 sanitizer kind、log、frame 做 CWE/CVE 风格规则匹配。
6. finalization 阶段还会调用 `exploit_assessor` 评估 severity，并通过 HITL 控制高危结果输出。

内置漏洞匹配覆盖常见 sanitizer 类型，例如 use-after-free、double-free、buffer overflow、integer overflow、null dereference、timeout/OOM、Rust panic 等。自定义规则通过 `FUZZ_AGENT_VULN_RULES` 加载。

### Web UI

入口：`fuzz-agent serve`，实现：`fuzz_agent/web/server.py`。

技术：FastAPI、Jinja2、StaticFiles、SSE。

主要页面/API：

- `/`：campaign 列表和创建表单。
- `/chat`：对话式 workbench。
- `/campaigns/{cid}`：campaign artifact 只读详情页。
- `/api/campaigns`：列表/创建。
- `/api/campaigns/{cid}/stats`：状态快照。
- `/api/campaigns/{cid}/crashes`：crash 列表。
- `/api/campaigns/{cid}/agent-trace`：agent trace。
- `/api/campaigns/{cid}/logs/run`：run log。
- `/api/campaigns/{cid}/logs/build`：build log。
- `/api/campaigns/{cid}/harness`：harness source。
- `/api/campaigns/{cid}/coverage/*`：coverage artifact。
- `/api/campaigns/{cid}/events`：SSE replay + live events。
- `/api/chat` 和 `/api/chat/sessions*`：chat 会话。

Web 默认只允许 loopback client。远程访问需要显式设置：

```bash
export FUZZ_AGENT_WEB_ALLOW_REMOTE=1
```

### Chat Facade

入口：CLI `fuzz-agent chat` 和 Web `/chat`，实现：`fuzz_agent/chat/`。

`ConversationAgent` 把用户消息映射到现有工具：

- `analyze <path>`
- `run <path> 30m [libfuzzer|cargo-fuzz|atheris]`
- `status [campaign_id]`
- `stop [campaign_id]`
- `resume <campaign_id> [10m]`
- `trace [campaign_id]`
- `triage [campaign_id]`

解析策略是规则优先；如果设置了 `OPENAI_API_KEY` 且 `FUZZ_AGENT_CHAT_LLM` 未关闭，会使用 LLM 做 intent 解析和普通聊天回答。Chat session 会持久化到 SQLite 的 `chat_sessions` 表。

### Sandbox 与 HITL

Sandbox provider：

- `none`：开发默认值，仅透传命令，会记录 warning。
- `docker`：用 `docker run` 包装命令，默认禁网、只读 rootfs、挂载必要路径。
- `nsjail`：用 `nsjail -Mo` 包装命令，支持 bind mount、CPU 和内存限制。

选择方式：

```bash
export FUZZ_AGENT_SANDBOX=none
export FUZZ_AGENT_SANDBOX=docker
export FUZZ_AGENT_SANDBOX=nsjail
```

HITL provider：

- `AlwaysAllow`：默认。
- `AlwaysDeny`：测试或禁用高风险动作。
- `CLIPrompt`：命令行确认。

选择方式：

```bash
export FUZZ_AGENT_HITL=cli
```

## 技术栈

### 语言和包管理

- Python `>=3.11`
- `pyproject.toml` + Hatchling build backend
- `uv.lock` 存在，说明项目可用 uv 锁定依赖
- 包名：`fuzz-agent`
- CLI entry point：`fuzz-agent = fuzz_agent.cli:main`

### 运行依赖

- `click>=8.1`：CLI。
- `openai>=1.0`：OpenAI-compatible LLM client。

### 可选依赖

- `web` extra：`fastapi>=0.110`、`uvicorn[standard]>=0.27`、`jinja2>=3.1`。
- `dev` extra：`pytest>=8`、`ruff>=0.6`、`mypy>=1.10`。
- `aflpp` extra 当前为空，占位。

### 外部工具

- `clang`：LibFuzzer 构建。
- `cargo` + `cargo-fuzz`：Rust fuzz。
- `llvm-profdata`、`llvm-cov`：coverage。
- `llvm-symbolizer`：crash frame symbolization，缺失时会降级。
- `docker` 或 `nsjail`：可选 sandbox。

### 存储和并发

- SQLite：campaign、stats、events、crashes、chat sessions。
- JSONL：events 和 agent trace。
- 文件系统：corpus、crashes、logs、coverage、generated harness。
- asyncio + background event loop thread：同步 tool facade 可启动异步 campaign。

## 常用命令

安装：

```bash
pip install -e .
pip install -e ".[dev,web]"
```

LLM 配置：

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://example.com/v1
export FUZZ_AGENT_MODEL=gpt-4o-mini
```

CLI：

```bash
fuzz-agent analyze ./my-target
fuzz-agent run ./my-target --engine libfuzzer --time 30m
fuzz-agent run ./my-rust-crate --engine cargo-fuzz --time 30m
fuzz-agent status <campaign_id>
fuzz-agent triage <campaign_id>
fuzz-agent resume <campaign_id> --time 30m
fuzz-agent serve --host 127.0.0.1 --port 8000
fuzz-agent chat
```

开发验证：

```bash
ruff check fuzz_agent tests
mypy fuzz_agent
pytest -q
```

## 测试覆盖

当前测试集中覆盖了这些行为：

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

## 当前限制和注意事项

- LibFuzzer 只支持 C/C++，且构建依赖 `HarnessSpec.extra_sources` 和本地 `clang`。
- target analyze 和入口点发现是正则启发式，不是完整语义分析。
- cargo-fuzz 需要目标路径是具体 Rust package；纯 workspace root 需要先选择实际 crate。
- cargo-fuzz coverage 尚未完善，结构化 coverage 主要是 LibFuzzer 路径。
- Atheris adapter 存在，但并非 README 主推路径，使用前需要补齐实际 Python harness 生成和验证细节。
- AFL++、Jazzer、Go native fuzz 尚未真正接入。
- 默认 `FUZZ_AGENT_SANDBOX=none` 无隔离，只适合本地可信目标。
- LLM 输出经过 JSON 解析和部分 payload 验证，但真正文件写入仍要通过工具层控制，不应绕过 `tools` 直接写目标。
- Web 默认 local-only；不要在未配置认证/隔离前直接暴露到公网。

## 给后续 agent 的开发建议

- 优先从 `state.models` 和 `tools/__init__.py` 看边界；不要让 orchestrator 直接依赖 engine 细节。
- 新增 engine 时先实现 `FuzzEngine` 接口，再补 `Runtime._engines` 注册、CLI choice、测试和 README/本文档。
- 新增自动决策能力时，优先转成结构化 `AgentObservation`，再交给 policy；避免让策略直接解析散落日志。
- 新增 artifact 时，同时考虑 `CampaignStore.paths()`、Web API、agent trace 和测试夹具。
- 对 LLM 子任务保持严格 JSON schema，失败时应有 deterministic fallback。
- 修改 Web UI 时同步检查 `tests/test_web_api.py`，尤其是 local-only、artifact endpoint 和 chat session 行为。
- 修改 campaign 生命周期时重点跑 `tests/test_campaign_resume.py`、`tests/test_orchestrator_*`、`tests/test_event_bus.py` 和相关 engine parser 测试。
