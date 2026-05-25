# real_target_crash

This target contains a target-owned null dereference when the input starts with
`BUG!`. A correct harness should call `ParseThing(data, size)`, and crash
triage should classify the issue as target-owned rather than harness-owned.

