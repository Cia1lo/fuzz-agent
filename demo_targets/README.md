# Fuzz Agent Demo Targets

These minimal C++ targets are for demonstrating the agent harness engineering
loop. Each target exposes `ParseThing(const uint8_t*, size_t)` so
`fuzz-agent analyze <target>` can discover a fuzz entry point.

Run one target:

```bash
uv run fuzz-agent analyze demo_targets/real_target_crash
uv run fuzz-agent run demo_targets/real_target_crash --engine libfuzzer --time 60s
uv run fuzz-agent serve --host 127.0.0.1 --port 8000
```

Demo intent:

- `target_not_reached`: use with a deliberately bad harness first to show
  `target_reached=false`.
- `smoke_crash`: useful for demonstrating smoke validation rejecting a harness
  that fails at startup.
- `harness_owned_crash`: useful for showing harness-owned crash classification.
- `real_target_crash`: contains a real target-owned null dereference on `BUG!`.

