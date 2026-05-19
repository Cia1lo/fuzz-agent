# TODO

范围：优先完善当前 harness engineering 框架中的 LibFuzzer 路径。其他引擎
（AFL++、Jazzer、Go native fuzz、Rust cargo-fuzz）暂不纳入实现范围，等
LibFuzzer 路径稳定后再扩展。

## P0 - LibFuzzer campaign 正确性

- [x] 在 store、EventBus、stats 和 LibFuzzer 进程跟踪中使用同一个 campaign id。
- [x] 让 `stop_campaign()` 能终止 store campaign id 对应的真实 LibFuzzer 进程。
- [x] 在 LibFuzzer 静默输出时发出真实 heartbeat 事件。
- [x] 即使 LibFuzzer stdout 空闲，也能通过 heartbeat 驱动 plateau 检测。
- [x] 持久化最终 LibFuzzer stdout/stderr 尾部，方便调试失败运行。
- [x] 即使运行退出前没有 coverage-changing status line，也记录最终 stats。

## P1 - Harness 构建闭环

- [x] 为 harness 生成补充源码上下文：函数签名、邻近源码、include、构建系统提示和样例输入。
- [x] 将编译错误反馈给 harness writer，并进行有上限的自动重试。
- [x] 将 harness 链接到真实目标库，而不是只编译 harness 源文件。
- [x] 按 attempt 持久化生成的 harness 版本和 build log。

## P1 - Crash triage 质量

- [x] 保存为 confirmed crash 前先 reproduce 每个 crash。
- [x] 当 LibFuzzer 只写 crash artifact 时，补充保存 reproduce 输出作为 crash log。
- [x] 结合 sanitizer kind、符号化帧和 crash 行为改出去重。
- [x] 单独跟踪 flaky 或不可复现 crash。

## P1 - Coverage 与策略闭环

- [x] 将 coverage collection 错误显式记录出来，而不是静默吞掉。
- [x] 将 coverage report 转成结构化的 uncovered functions/regions。
- [x] 写入前对生成的 seeds 和 dictionary tokens 去重。
- [x] 在受控流程中用更新后的 dictionary/seeds 重启或重新启动 LibFuzzer。

## P2 - 状态、UI 与运维

- [x] 增加从持久化状态 resume/recover campaign 的能力。
- [x] 在 Web UI 增加 crash 详情、build log、harness 源码和 coverage 视图。
- [x] 在远程使用 Web UI 前增加认证或 local-only 保护。
- [x] 显式检查 sandbox 可用性，并在 `FUZZ_AGENT_SANDBOX=none` 时给出警告。
- [x] 清理 lint/type 问题，并让测试依赖与 `pyproject.toml` 对齐。
