# Orphan native acceptance record

## 2026-10-11: delegated acceptance, blocked before fixture execution

The owner explicitly authorized the implementation agent to perform the native
acceptance described in ORPHAN_EXECUTION.md. Unit and UI test execution remains
prohibited. This record does not open the release gate.

Environment: macOS 27.0.1 (26A434), Apple Silicon, ordinary effective user.
Initial source: sayaka `45b69d7215d0c50721b93b3e76007482003d3bb7`,
SayakaCleaner `5b762c9b4f7b6d837b8ddae55f7844e8a0a91aef`.

Manual observations:

- Launched the Debug App and opened App Leftovers. The move button was disabled.
  Triggering its read-only preview displayed `Invalid argument (os error 22)`.
  The shipped CLI read-only orphan preview reproduced the same failure.
- Read-only OS diagnostics showed that `O_NOFOLLOW` and `O_NOFOLLOW_ANY`
  separately open the account Library directory, while their combination fails
  with EINVAL. The native observation opens now retain only O_NOFOLLOW_ANY.
- The next CLI attempt failed with `unsafe_path`. Root directories including `/`
  and `/Applications` carry SF_NOUNLINK. Read-only PathWitness now permits these
  protection flags, retaining them in its identity stamp. Native Trash target
  admission remains unchanged and continues refusing protected targets.
- With both fixes, CLI preview reached `Operation not permitted (os error 1)`.
  Read-only access diagnostics confirmed that this host process cannot read the
  current user's Trash or Library/Cookies directories. No permission or
  filesystem-protection bypass was attempted.

No fixture was moved or real user data modified. No successful native cleanup,
Finder Put Back, history rendering, race/fault scenario or full acceptance is
claimed. All contract acceptance cases remain pending until the required access
is available. ORPHAN_NATIVE_ACCEPTANCE_RECORDED remains false.

Validation: workspace and test-source build passed. A read-only protected-root
regression test source was added; no unit/UI tests were executed. The manual App
observations above are separate from build validation. The two runtime fixes
received independent GPT-6 Astra code review.
