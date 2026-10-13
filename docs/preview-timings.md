# Preview phase timing (#158 stage 1)

Production `purge` previews now carry optional `timings` (microsecond wall durations): discovery, index, classification, Git, activity, sizing, Worktrees, total. The total includes preparation/accounting between phases; per-phase medians need not sum to a median total. This is diagnostic data, excluded from approval digests and execution policy. The top-level complete/status/coverage fields still decide whether observations are complete. Fatal errors before a preview exists do not manufacture timing records.

`purge ROOT --profile projects --json --timings` keeps preview JSON on stdout and adds one bounded, path-free timing record to stderr. `output_us` includes output construction, encoding, write and flush; it is outside the engine total. The FFI's result cache still serializes a preview once. The app separately measures the native handoff, decode and validation.

The first measured optimization skips the activity phase's same-user process census and signed Git-tool resolution when classification found no artifacts. It resets the stale counter as before. Discovery/classification, scan limits, coverage, candidates, Git checks on real candidates, and nonempty activity/execution revalidation are unchanged. No stale observations are cached across operations.

Evidence is retained in the app's `docs/distribution/scan-timing-158.md`: two real no-artifact source locations, production Release CLI, one warm-up and five alternating baseline/optimized runs, all complete with identical candidate/count/issue/coverage digests. No claim is made for large nonempty trees or full GUI latency. Unit/UI tests were not run; regression sources were compile-checked only.
