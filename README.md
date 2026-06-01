# fuzz-agent

`fuzz-agent` 是一个面向 harness engineering 的 fuzz 编排器。它用
OpenAI-compatible LLM 生成和修复 fuzz harness，但把关键判断交给可验证的工程反馈：
编译日志、fuzz 引擎事件、coverage、crash artifact、reproduce 结果和持久化 campaign
状态。

当前重点支持 C/C++ LibFuzzer 路径，并已加入 Rust `cargo-fuzz` engine adapter。

## 架构

```
        ┌─────────────────────────────────────────────────────┐
        │                Orchestrator                         │
        │ analyze → agent harness → run → triage → strategy   │
        └──────────┬──────────────────────────┬───────────────┘
                   │                          │
           ┌───────▼─────────┐         ┌──────▼───────────┐
           │   Tool Layer    │         │  Subagents       │
           │ analyze/build   │         │ harness_writer   │
           │ campaign/triage │         │ crash_triage     │
           │ strategy/resume │         │ coverage_analyst │
           └───────┬─────────┘         │ exploit_assessor │
                   │                   └──────────────────┘
           ┌───────▼─────────┐
           │  Engine Layer   │
           │ LibFuzzer       │
           │ cargo-fuzz      │
           │ Atheris(partial)│
           └───────┬─────────┘
                   │
           ┌───────▼─────────┐         ┌──────────────────┐
           │ CampaignStore   │  ◄──►   │ EventBus         │
           └─────────────────┘         └──────────────────┘
```

`agent_harness` 是外层 agent harness engineering 闭环：它把 harness 生成、
构建、验证和修复重试记录为结构化 trace。`harness_writer` 生成的是内层 fuzz
harness，即把 fuzz bytes 接到目标函数的适配代码。成功启动 campaign 后，每轮
agent harness attempt 会持久化到：

```text
state/campaigns/<campaign_id>/agent_trace.jsonl
```

## 已支持能力

| 能力 | 状态 |
| --- | --- |
| C/C++ target 分析与 LibFuzzer harness 生成 | 已实现 |
| LibFuzzer build/run/reproduce/minimize | 已实现 |
| Rust target 分析与 cargo-fuzz harness 生成 | 已实现 |
| cargo-fuzz build/run/reproduce/minimize | 已实现 |
| Python Atheris adapter | 实验性：build/import check、run、reproduce/minimize 基础路径 |
| campaign run log、build log、coverage summary 持久化 | 已实现 |
| crash reproduce、confirmed/non-reproducible/flaky 状态 | 已实现 |
| crash 漏洞类型/CWE 匹配与自定义规则 | 已实现 |
| campaign resume/recover | 已实现 |
| Web UI artifact 只读查看 | 已实现 |
| Web UI 默认 local-only | 已实现 |
| AFL++、Jazzer、Go native fuzz | 计划中 |

## 安装

```bash
pip install -e .
```

开发和测试依赖：

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

LibFuzzer 路径需要本机有 `clang`。Rust `cargo-fuzz` 路径需要：

```bash
cargo install cargo-fuzz
```

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

启动 Web UI：

```bash
fuzz-agent serve --host 127.0.0.1 --port 8000
```

Web UI 默认只允许 loopback client。确实需要远程访问时显式开启：

```bash
export FUZZ_AGENT_WEB_ALLOW_REMOTE=1
```

## cargo-fuzz 语义

`cargo-fuzz` engine 会把 LLM 生成的 Rust harness 安装到目标 crate 下：

```text
<crate>/fuzz/fuzz_targets/<entry>_attempt_N.rs
<crate>/fuzz/Cargo.toml
```

build 阶段会执行：

```bash
cargo fuzz run <target> -- -runs=0
```

run 阶段会使用当前 campaign 的持久化 corpus/crash 目录：

```text
state/campaigns/<campaign_id>/corpus/
state/campaigns/<campaign_id>/crashes/
state/campaigns/<campaign_id>/run.log
```

reproduce 阶段会执行单个 crash input，并把可复现输出写入 crash log，供 triage 使用。

## 漏洞匹配

`triage` 会在 crash reproduce 之后自动填充 `vulnerability_matches`。内置规则会根据
sanitizer kind、crash log 和 top frames 匹配常见 CWE，例如：

- `heap-use-after-free` → `CWE-416`
- `double-free` → `CWE-415`
- `heap/stack/global-buffer-overflow` 写越界 → `CWE-787`
- `heap/stack/global-buffer-overflow` 读越界 → `CWE-125`
- `integer-overflow` → `CWE-190`
- `null dereference` → `CWE-476`
- timeout/OOM → DoS 相关 CWE

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

同一条规则里的 `sanitizer_kind`、`frame_regex`、`log_regex` 会按 AND 关系匹配；
至少需要提供其中一个条件。

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
```

生成的 harness 和 build log 通常位于目标项目：

```text
<target>/.fuzz/harness/<entry>/attempt_N.*
<target>/.fuzz/build/build_<entry>_attempt_N.log
```

## Sandbox

通过 `FUZZ_AGENT_SANDBOX` 选择 sandbox provider：

```bash
export FUZZ_AGENT_SANDBOX=none
export FUZZ_AGENT_SANDBOX=docker
export FUZZ_AGENT_SANDBOX=nsjail
```

`none` 会发出 warning；`docker` 或 `nsjail` 不可用时会直接失败，避免误以为已隔离运行。

## 开发验证

```bash
ruff check fuzz_agent tests
mypy fuzz_agent
pytest -q
```

当前测试覆盖 fake LibFuzzer、fake cargo-fuzz、campaign resume、crash reproduce、strategy
dedupe、Web artifact endpoints 和 local-only middleware。

## 限制

- LibFuzzer 目前只支持 C/C++。
- cargo-fuzz 目前只支持以具体 Rust package 为根的 crate；纯 workspace root 需要先选择实际 crate 目录。
- coverage 结构化输出主要覆盖 LibFuzzer 路径；cargo-fuzz coverage 尚未完善。
- Atheris 当前是实验性 adapter，适合已有 Python harness 的基础 run/reproduce 流程；自动 harness 生成和 coverage 闭环尚未达到 LibFuzzer 路径的成熟度。
- AFL++、Jazzer、Go native fuzz 尚未接入。
