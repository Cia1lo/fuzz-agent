# fuzz-agent

> 面向 harness engineering 的 fuzz campaign 编排器，用 OpenAI-compatible LLM 生成和修复 harness，并用构建、运行、coverage、crash 复现和持久化状态做工程闭环验证。

- **仓库地址**：https://github.com/Cia1lo/fuzz-agent
- **作者**：
- **邮箱**：404notfound@nuaa.edu.cn

## 项目简介

`fuzz-agent` 是一个面向 C/C++、Rust 的编排工具。项目目标不是替代
LibFuzzer、`cargo-fuzz` ，而是把目标分析、harness 生成、构建验证、运行监督、
coverage plateau 策略、crash 复现分诊和 campaign 状态持久化串成可恢复、可审计的工程流程。

当前主线能力：

- C/C++ + LibFuzzer：最成熟路径，支持目标分析、harness 生成、构建、运行、coverage、crash triage 和 Web/Chat 查看。
- Rust + `cargo-fuzz`：已接入 build/run/reproduce 基础闭环。


核心工作流：

```text
analyze -> generate harness -> build -> validate -> smoke run
        -> start campaign -> supervise events -> triage crashes -> finalize
```

## 环境与依赖

### 运行环境

| 项目 | 版本 | 说明 |
|------|------|------|
| 操作系统 | macOS 15.7.7（本地验证）/ Linux | 开发与测试以 macOS 为主；Linux 可用于 Docker/nsjail 隔离场景 |
| Python | `>=3.11`（本地为 3.13.9） | 核心开发语言 |
| uv | 0.11.11 | 推荐的依赖同步和本地运行工具，仓库包含 `uv.lock` |
| SQLite | Python 标准库 `sqlite3` | 本地状态库，不需要单独部署数据库服务 |

### 开源程序与第三方依赖

> 体积较大或需单独安装的程序在此列出。版本号为本地已确认版本；未安装项按实际使用环境安装。

| 依赖名称 | 使用版本 | 下载链接 | 安装方式 | 说明 |
|----------|----------|----------|----------|------|
| LLVM/Clang | Apple clang 17.0.0 | https://llvm.org/ | Xcode Command Line Tools / Homebrew LLVM / 系统包管理器 | C/C++ LibFuzzer 构建，需支持 `-fsanitize=fuzzer` |
| Rust Cargo | 1.95.0 | https://www.rust-lang.org/tools/install | `rustup` | Rust crate 构建基础 |
| cargo-fuzz | 0.13.1 | https://github.com/rust-fuzz/cargo-fuzz | `cargo install cargo-fuzz` | Rust fuzz engine adapter |
| LLVM coverage tools | Apple LLVM 17.0.0（通过 `xcrun` 可用） | https://llvm.org/ | Xcode Command Line Tools / Homebrew LLVM / 系统包管理器 | `llvm-profdata`、`llvm-cov`，用于 LibFuzzer coverage；当前项目要求裸命令可在 `PATH` 中找到 |
| Docker | 29.4.2 | https://www.docker.com/products/docker-desktop/ | Docker Desktop / 系统包管理器 | 可选 sandbox provider |
| nsjail | 未安装 | https://github.com/google/nsjail | 源码构建 / 系统包管理器 | 可选 sandbox provider |

> **注意**：LibFuzzer 路径需要可用的 `clang` 和 libFuzzer runtime。macOS 系统 clang 不一定带完整 runtime；如遇 `libclang_rt.fuzzer*.a not found`，请安装 Homebrew LLVM 并设置 `CC`/`CXX`。

> **macOS 提示**：本机 `xcrun --find llvm-profdata` 和 `xcrun --find llvm-cov` 可找到 Apple LLVM
> coverage tools，但当前代码通过 `PATH` 查找裸命令。建议在项目 `.envrc` 中加入
> `PATH_add /Library/Developer/CommandLineTools/usr/bin`，然后执行 `direnv allow`。

### Python / Maven / npm 依赖

依赖清单文件：

- Python -> `pyproject.toml`（项目依赖声明）
- Python -> `uv.lock`（锁定依赖版本）


主要 Python 依赖：

| 依赖名称 | 声明版本 | `uv.lock` 锁定版本 | 说明 |
|----------|----------|--------------------|------|
| click | `>=8.1` | 8.4.0 | CLI |
| openai | `>=1.0` | 2.37.0 | OpenAI-compatible LLM client |
| fastapi | `>=0.110` | 0.136.1 | Web UI，可选 `web` extra |
| uvicorn | `>=0.27` | 0.47.0 | Web server，可选 `web` extra |
| jinja2 | `>=3.1` | 3.1.6 | Web 模板，可选 `web` extra |
| pytest | `>=8` | 9.0.3 | 测试，可选 `dev` extra |
| ruff | `>=0.6` | 0.15.13 | 代码检查，可选 `dev` extra |
| mypy | `>=1.10` | 2.1.0 | 类型检查，可选 `dev` extra |

安装命令：

```bash
# 推荐：同步基础依赖
uv sync

# Web UI 依赖
uv sync --extra web

# 开发与 Web UI 全量依赖
uv sync --all-extras

# 不使用 uv 时的替代安装方式
pip install -e .
pip install -e ".[dev,web]"
```

## 配置说明

### 数据库配置

本项目不依赖 MySQL、PostgreSQL、Redis 等外部服务。运行状态默认写入当前工作目录下的本地 SQLite
数据库和文件系统 artifact：

```text
state/state.db
state/campaigns/<campaign_id>/
state/agent_sessions/<session_id>/
```

如需改变状态目录，可设置：

```bash
export FUZZ_AGENT_HOME=/path/to/fuzz-agent-state-root
```

> **安全提示**：LLM API key、私有网关地址、项目专属漏洞规则路径等敏感配置请通过环境变量或本地 `.env` / shell profile 管理，不要提交到仓库。

### LLM 配置

```bash
export OPENAI_API_KEY=...

# 可选：兼容 OpenAI API 的其他服务
export OPENAI_BASE_URL=https://example.com/v1

# 可选：默认模型
export FUZZ_AGENT_MODEL=gpt-4o-mini
```

### 其他关键配置

| 配置项 | 默认值 | 说明 | 配置文件路径 |
|--------|--------|------|-------------|
| `FUZZ_AGENT_HOME` | 当前工作目录 | 状态库和 campaign artifact 根目录 | 环境变量 |
| `FUZZ_AGENT_SANDBOX` | `none` | sandbox provider，可选 `none` / `docker` / `nsjail` | 环境变量 |
| `FUZZ_AGENT_HITL` | `none`（等同 allow） | 人工确认 provider，可选 `allow` / `deny` / `cli` / `none` | 环境变量 |
| `FUZZ_AGENT_WEB_ALLOW_REMOTE` | 未开启 | 设置为 `1` 后允许非 loopback client 访问 Web UI | 环境变量 |
| `FUZZ_AGENT_CHAT_LLM` | 自动 | 设置为 `0` / `false` / `off` / `no` 可关闭 Chat LLM intent 解析 | 环境变量 |
| `FUZZ_AGENT_CARGO` | `cargo` | 指定 cargo 可执行文件路径 | 环境变量 |
| `FUZZ_AGENT_VULN_RULES` | 未设置 | 加载自定义漏洞匹配规则 JSON | 环境变量 |
| `CC` / `CXX` | `clang` / `clang++` | 指定 C/C++ 编译器 | 环境变量 |

如果使用 `direnv` 管理本项目的本地环境，可以在 `.envrc` 中加入：

```bash
PATH_add /Library/Developer/CommandLineTools/usr/bin
```

然后启用并验证 LLVM coverage tools：

```bash
direnv allow
which llvm-profdata
which llvm-cov
llvm-profdata --version
llvm-cov --version
```

Web UI 默认只允许本机访问：

```bash
uv run fuzz-agent serve --host 127.0.0.1 --port 8000
```

如确需远程访问，请先补充网络隔离和访问控制，再显式开启：

```bash
export FUZZ_AGENT_WEB_ALLOW_REMOTE=1
```

## 数据集

### 数据集说明

`fuzz-agent` 不需要固定训练数据集。项目处理的是 fuzz campaign 的输入语料、crash artifact 和 coverage
产物。完整 corpus、crash 文件和运行日志通常体积较大，不应提交到 Git 仓库。

| 数据集名称 | 来源 | 大小 | 格式 | 说明 |
|-----------|------|------|------|------|
| 初始 corpus | 目标项目的 `tests/`、`testdata/`、`samples/`、`examples/`、`fixtures/` 等目录 | 由目标项目决定 | 任意 bytes / 文本 / 二进制 | harness context 和 fuzz campaign 的 seed 来源 |
| 运行 corpus | `state/campaigns/<campaign_id>/corpus/` | 运行时增长 | 任意 bytes | fuzz engine 运行中产生和保留的输入 |
| crash artifact | `state/campaigns/<campaign_id>/crashes/` | 运行时产生 | 任意 bytes + 日志 | crash 输入、复现和分诊材料 |
| demo targets | `demo_targets/` | 小型样例 | C/C++ 源码和 README | 本地演示和人工验证用目标 |
| test fixtures | `tests/fixtures/` | 小型样例 | C/C++ 源码和 README | 单元测试用 fake target |

> **体积较大的 corpus、coverage profile、crash artifact 不纳入 Git 仓库**，默认通过 `.gitignore` 忽略 `state/`、`**/.fuzz/`、`*.profraw`、`*.profdata`、`crash-*`、`leak-*`、`timeout-*` 等运行产物。

> **小部分样例应提交到 Git 仓库中**，当前项目使用 `demo_targets/` 和 `tests/fixtures/` 承载最小可运行样例，便于本地调试、单元测试和 Code Review。

样例要求：

- 条数和文件体积保持最小，避免提交大型 corpus。
- 不包含真实用户隐私、生产数据或未授权样本。
- 样例应能说明输入格式、触发路径或测试意图。

### 数据集下载与放置

本项目无需统一下载外部数据集。对被测目标建议按以下方式准备 seed：

```bash
# 1. 在目标项目中准备小型 seed 目录
mkdir -p /path/to/target/testdata

# 2. 放入若干脱敏、小体积样例输入
printf 'MAGI\x00\x01demo' > /path/to/target/testdata/seed_001.bin

# 3. 运行 fuzz-agent，campaign corpus 会复制并持久化到 state/campaigns/<campaign_id>/corpus/
uv run fuzz-agent run /path/to/target --engine libfuzzer --time 30m
```

运行产物目录结构：

```text
state/
├── state.db
├── campaigns/
│   └── <campaign_id>/
│       ├── meta.json
│       ├── events.jsonl
│       ├── run.log
│       ├── corpus/
│       ├── crashes/
│       ├── coverage_summary.txt
│       ├── coverage_uncovered.json
│       ├── input_model.json
│       └── agent_trace.jsonl
└── agent_sessions/
    └── <session_id>/
        └── agent_trace.jsonl
```

目标项目内生成的 harness 和构建产物：

```text
<target>/.fuzz/
├── harness/
│   └── <entry>/
│       ├── attempt_N.cc
│       └── attempt_N.dict
└── build/
    ├── build_<entry>_attempt_N.log
    └── fuzz_<entry>_attempt_N
```

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/Cia1lo/fuzz-agent.git
cd fuzz-agent

# 2. 安装依赖
uv sync --all-extras

# 3. 配置 LLM（需要自动生成或修复 harness 时）
export OPENAI_API_KEY=...
export FUZZ_AGENT_MODEL=gpt-4o-mini

# 4. 分析目标项目
uv run fuzz-agent analyze ./demo_targets/cwe_oob_write

# 5. 启动一次 LibFuzzer campaign
uv run fuzz-agent run ./demo_targets/cwe_oob_write --engine libfuzzer --time 30m
```

常用命令：

```bash
# C/C++ LibFuzzer
uv run fuzz-agent analyze ./my-cpp-target
uv run fuzz-agent run ./my-cpp-target --engine libfuzzer --time 30m

# Rust cargo-fuzz
uv run fuzz-agent analyze ./my-rust-crate
uv run fuzz-agent run ./my-rust-crate --engine cargo-fuzz --time 30m

# 状态、分诊和恢复
uv run fuzz-agent status <campaign_id>
uv run fuzz-agent triage <campaign_id>
uv run fuzz-agent resume <campaign_id> --time 30m

# Web UI
uv run fuzz-agent serve --host 127.0.0.1 --port 8000

# CLI Chat
uv run fuzz-agent chat
```

Chat 支持的规则优先命令：

```text
analyze <path>
run <path> 30m [libfuzzer|cargo-fuzz]
status [campaign_id]
stop [campaign_id]
resume <campaign_id> [10m]
trace [campaign_id]
triage [campaign_id]
```

## 项目结构

```text
fuzz-agent/
├── fuzz_agent/
│   ├── cli.py                  # Click CLI 入口：serve/analyze/run/triage/resume/status/chat
│   ├── orchestrator.py         # 主控制循环
│   ├── state/                  # 数据模型与 SQLite/文件系统持久化
│   ├── tools/                  # orchestrator 调用的工具门面
│   ├── engines/                # LibFuzzer、cargo-fuzz、coverage adapter
│   ├── agent_harness/          # 外层 harness engineering 观察、策略、验证和 trace
│   ├── subagents/              # harness writer、coverage analyst、crash triage 等子任务
│   ├── events/                 # EventBus 和 plateau 事件
│   ├── sandbox/                # none/docker/nsjail sandbox provider
│   ├── web/                    # FastAPI + Jinja2 Web UI、artifact API、SSE、Chat 页面
│   └── chat/                   # 对话式命令 facade 和 session memory
├── tests/                      # 单元测试与 fake target fixtures
├── demo_targets/               # 手工演示用 C/C++ fake targets
├── pyproject.toml              # 项目元数据、依赖和工具配置
├── uv.lock                     # uv 锁定依赖
├── .gitignore
└── README.md                   # 本文件
```

## 开发验证

```bash
uv run ruff check fuzz_agent tests
uv run mypy fuzz_agent
uv run pytest -q
```

最近一次记录的完整验证结果：

```text
pytest -q
129 passed

ruff check fuzz_agent tests
All checks passed!

mypy fuzz_agent
Success: no issues found in 52 source files
```
