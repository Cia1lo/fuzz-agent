import inspect
import importlib

coverage_analyst_module = importlib.import_module("fuzz_agent.subagents.coverage_analyst")
crash_triage_module = importlib.import_module("fuzz_agent.subagents.crash_triage")
exploit_assessor_module = importlib.import_module("fuzz_agent.subagents.exploit_assessor")
harness_writer_module = importlib.import_module("fuzz_agent.subagents.harness_writer")
vulnerability_matcher_module = importlib.import_module("fuzz_agent.subagents.vulnerability_matcher")


def test_tool_subagent_bindings_survive_prior_submodule_imports():
    # Importing a submodule sets the same name on the parent package. Tool
    # modules must bind the subagent run function, not that parent module attr.
    import fuzz_agent.orchestrator as orchestrator
    import fuzz_agent.tools.harness as harness_tool
    import fuzz_agent.tools.strategy as strategy_tool
    import fuzz_agent.tools.triage as triage_tool

    orchestrator = importlib.reload(orchestrator)
    harness_tool = importlib.reload(harness_tool)
    strategy_tool = importlib.reload(strategy_tool)
    triage_tool = importlib.reload(triage_tool)

    assert harness_tool.harness_writer is harness_writer_module.run
    assert strategy_tool.coverage_analyst is coverage_analyst_module.run
    assert triage_tool.crash_triage is crash_triage_module.run
    assert triage_tool.vulnerability_matcher is vulnerability_matcher_module.run
    assert orchestrator.assess_exploitability is exploit_assessor_module.run

    assert not inspect.ismodule(harness_tool.harness_writer)
    assert not inspect.ismodule(strategy_tool.coverage_analyst)
    assert not inspect.ismodule(triage_tool.crash_triage)
    assert not inspect.ismodule(triage_tool.vulnerability_matcher)
    assert not inspect.ismodule(orchestrator.assess_exploitability)
