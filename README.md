# fuzz-agent

A fuzz-testing orchestrator built on harness-engineering principles: a small
LLM-driven Orchestrator coordinates coarse-grained tools, delegates large
contexts to isolated subagents, and reacts to a typed event stream from the
underlying fuzz engine.

## Architecture

```
        ┌─────────────────────────────────────────────────────┐
        │                Orchestrator (main agent)             │
        │   plan / launch / supervise / decide-when-to-stop    │
        └──────────┬──────────────────────────┬───────────────┘
                   │                          │
           ┌───────▼─────────┐         ┌──────▼───────────┐
           │   Tool Layer    │         │  Subagent Pool   │
           │ analyze / build │         │ harness_writer   │
           │ campaign / ... │          │ crash_triage     │
           └───────┬─────────┘         │ corpus_curator   │
                   │                   │ coverage_analyst │
           ┌───────▼─────────┐         │ exploit_assessor │
           │  Engine Layer   │         └──────────────────┘
           │   LibFuzzer     │
           └───────┬─────────┘
                   │
           ┌───────▼─────────┐         ┌──────────────────┐
           │  CampaignStore  │  ◄──►   │     EventBus     │
           └─────────────────┘         └──────────────────┘
```

## Layout

```
fuzz_agent/
  state/models.py          shared dataclasses (TargetProfile, CampaignStats, ...)
  state/store.py           SQLite + filesystem persistence
  events/stream.py         async EventBus + PlateauDetector
  engines/base.py          FuzzEngine ABC
  engines/libfuzzer.py     reference adapter (build/run/minimize/reproduce)
  tools/__init__.py        public tool surface used by the agent
  tools/_runtime.py        process-wide singletons (store, bus, engines)
  tools/{analyze,harness,build,campaign,triage,strategy}.py
  subagents/__init__.py    subagent facade
  subagents/_llm.py        cached Claude wrapper
  subagents/{harness_writer,crash_triage,corpus_curator,
             coverage_analyst,exploit_assessor}.py
  orchestrator.py          deterministic supervision loop
  cli.py                   `fuzz-agent` entry point
```

## Quick start

```
pip install -e .
export ANTHROPIC_API_KEY=...

fuzz-agent analyze ./my-target
fuzz-agent run     ./my-target --time 30m
fuzz-agent triage  <campaign_id>
fuzz-agent status  <campaign_id>
```

## Status

| Engine    | State        |
| --------- | ------------ |
| LibFuzzer | implemented  |
| AFL++     | planned      |
| Atheris   | planned      |
| Jazzer    | planned      |
| Go fuzz   | planned      |

The harness writer, crash triager, corpus curator, coverage analyst, and
exploit assessor subagents call Claude with cached system prompts and return
strict JSON. The orchestrator never sees raw crash logs or coverage maps —
only structured summaries.
