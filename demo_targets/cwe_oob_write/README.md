# cwe_oob_write

This target demonstrates CWE classification for a real target-owned memory
bug. `ParseThing(const uint8_t*, size_t)` allocates a 4-byte heap buffer and,
when the input is at least 5 bytes, writes past the end of that allocation.

With LibFuzzer + AddressSanitizer, the reproduced crash should report
`heap-buffer-overflow` with `WRITE of size ...`. The built-in vulnerability
matcher should classify it as:

```text
CWE-787 Out-of-bounds write
```

Run:

```bash
uv run fuzz-agent analyze demo_targets/cwe_oob_write
uv run fuzz-agent run demo_targets/cwe_oob_write --engine libfuzzer --time 30s
```

For a deterministic validation run, seed the campaign corpus before running:

```bash
mkdir -p demo_targets/cwe_oob_write/.fuzz/corpus
cp demo_targets/cwe_oob_write/samples/seed1 demo_targets/cwe_oob_write/.fuzz/corpus/seed1
uv run fuzz-agent run demo_targets/cwe_oob_write --engine libfuzzer --time 10s
```

If needed, re-run triage on the returned campaign id:

```bash
uv run fuzz-agent triage <campaign_id>
```
