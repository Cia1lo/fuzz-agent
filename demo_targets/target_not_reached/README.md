# target_not_reached

Use this target to demonstrate `target_reached` validation. A bad harness such
as `LLVMFuzzerTestOneInput() { return 0; }` will build but never call
`ParseThing`; the agent harness should reject it and regenerate or patch.

