# smoke_crash

Use this target with a deliberately bad generated harness that crashes before
calling `ParseThing`, for example by dereferencing null in
`LLVMFuzzerTestOneInput`. The smoke validator should reject that harness before
the full campaign starts.

