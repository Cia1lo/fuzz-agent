# Fuzz Agent Demo Targets

These minimal C++ targets are for demonstrating the fuzz-agent workflow.
Each target exposes `ParseThing(const uint8_t*, size_t)` so
`fuzz-agent analyze <target>` can discover a fuzz entry point.

Run one target:

```bash
uv run fuzz-agent analyze demo_targets/cwe_oob_write
uv run fuzz-agent run demo_targets/cwe_oob_write --engine libfuzzer --time 60s
uv run fuzz-agent serve --host 127.0.0.1 --port 8000
```

Demo intent:

- `cwe_oob_write`: contains a real target-owned heap out-of-bounds write that
  should be classified as `CWE-787`.
- `real_target_crash`: contains a real target-owned null dereference on `BUG!`.
