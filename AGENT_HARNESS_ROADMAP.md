# Agent Harness Engineering Roadmap

本文档记录当前项目在完成第一版 `agent_harness` 层之后，尚未实现的目标。
当前已具备的基础能力是：harness 生成、构建、基础 artifact 验证、attempt trace
持久化，以及疑似 harness-owned crash 的初步标记。

## P0 - 完整验证闭环

- [x] 增加 `smoke_run` validator。
  - 目标：harness build 通过后，短时间运行一次，确认不是启动即崩。
  - 验收：启动即 crash、timeout、engine error 会变成 agent observation，并触发下一轮修复。

- [x] 增加 `target_reached` validator。
  - 目标：确认 fuzz harness 实际执行到目标 entry point，而不是只跑在初始化或 harness 逻辑里。
  - 当前进展：已提供 harness source 引用检查和 frame 检查，并写入 `target_reached` score。
  - 剩余工作：接入 coverage 或 engine-level runtime reachability 证据。

- [x] 增强 `harness_fault` 判定。
  - 目标：区分目标代码 crash 和 harness 自身 crash。
  - 当前进展：已结合 top frame、harness source path、`LLVMFuzzerTestOneInput`、`fuzz_target` 和 crash log 中的 Rust panic/assertion 证据。
  - 剩余工作：接入更完整的 sanitizer frame ownership 分类。

- [x] build 全失败时也持久化 agent trace。
  - 当前限制：trace 依赖 campaign id；如果 campaign 创建前 build 全失败，trace 无法落到 campaign 目录。
  - 目标：引入 pre-campaign session id，或提前创建 `PENDING/FAILED` campaign。

## P1 - 真实 Agent 决策层

- [x] 新增 `fuzz_agent/agent_harness/policy.py`。
  - 定义结构化 `HarnessDecision`，至少支持：
    - `regenerate_harness`
    - `patch_harness`
    - `add_seed`
    - `add_dictionary`
    - `change_entry_point`
    - `stop_failed`

- [x] 将 `AgentHarnessSession` 从固定 retry 改为 `observe -> decide -> act -> verify -> trace`。
  - 当前行为：build 失败后固定重新生成 harness。
  - 目标行为：policy 根据 observation 选择动作。

- [x] 限制 LLM 输出为结构化 decision。
  - 当前进展：已有结构化 `HarnessDecision` / `HarnessAction`、默认 deterministic policy 和 LLM-backed policy；未知 action 和无效 payload 会回退到 deterministic regenerate。
  - 剩余工作：对 `patch_harness` 等 payload 增加路径白名单和 action-specific schema。
  - 目标：LLM 只能返回 schema 化决策，实际文件写入、构建、运行仍由工具层执行。
  - 验收：无效 JSON、未知 action、越权路径都会被拒绝并记录 trace。

## P1 - 统一 Observation 模型

- [x] 新增统一 `Observation` 模型。
  - 汇总 build log、run log、coverage、crash、score、diagnostics。
  - 目标：所有 policy 输入使用同一数据结构。
  - 当前进展：已新增通用 `AgentObservation`，plateau policy 已开始使用。

- [ ] 将 build failure、smoke failure、coverage plateau、crash reproduce failure 都转成 observation。
  - 当前进展：coverage plateau 已转成 `AgentObservation`；build/smoke 仍使用 `HarnessAttemptObservation`。
  - 当前限制：这些反馈散落在 orchestrator、tools、engine 和 triage 中。
  - 目标：agent 决策只依赖结构化 observation，不直接解析原始日志。

- [x] 扩展只读工具 API。
  - 建议新增：
    - `read_build_log`
    - `read_run_log`
    - `read_coverage_summary`
    - `read_agent_trace`
    - `classify_harness_fault`
  - 当前进展：上述只读工具已加入 tool facade，并有单元测试覆盖。

## P2 - Coverage 驱动的 Agent Harness

- [x] plateau 处理改为 policy 决策。
  - 当前行为：`_on_plateau()` 直接调用 `mutate_strategy()`。
  - 目标行为：生成 coverage observation，由 policy 决定加 seed、加 dictionary、改 harness 或换 entry point。
  - 当前进展：`_on_plateau()` 已生成 coverage observation，交给 `CoverageStrategyPolicy` 决定是否调用 `mutate_strategy()`，并写入 agent trace。

- [ ] 增加 coverage delta 评分。
  - 目标：比较新 harness、seed、dictionary 是否实际提升覆盖率。
  - 验收：每轮 trace 写入 `coverage_delta` 和 `target_reached`。

- [ ] 根据 uncovered functions 选择动作。
  - 目标：coverage analyst 输出不只用于 seed/dictionary，也能指导 harness 输入建模。

## P2 - UI 与评测

- [x] Web UI 展示 agent trace 表格。
  - 当前状态：已有 `/api/campaigns/{cid}/agent-trace` JSON endpoint 和 artifact 链接。
  - 目标：页面直接展示 attempt、decision、build result、score、diagnostics tail。

- [x] 新增 fake target 评测集。
  - 覆盖场景：
    - target not reached
    - smoke run 启动即崩
    - harness-owned crash
    - real target crash
    - coverage plateau
  - 剩余建议场景：
    - build fail 后修复 include
    - wrong signature
    - crash 可复现和不可复现

- [ ] 定义稳定的 agent attempt score。
  - 建议字段：
    - `compiled`
    - `smoke_passed`
    - `target_reached`
    - `coverage_delta`
    - `crash_reproducible`
    - `harness_fault_detected`

## 推荐下一步切片

优先做以下三个任务，能最快把系统从“记录 retry”推进到真正的 agent harness 闭环：

1. 将 build failure、smoke failure、crash reproduce failure 也统一转成 `AgentObservation`。
2. 增加 coverage delta 评分。
3. 扩展 fake target 场景：wrong signature、flaky reproduce、build fail repair。
