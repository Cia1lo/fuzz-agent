# harness_owned_crash

Use this target with a harness that asserts, traps, unwraps, or otherwise
crashes inside `LLVMFuzzerTestOneInput`. The crash classifier should flag the
finding as harness-owned instead of target-owned.

