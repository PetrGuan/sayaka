# Contributor and coding-agent instructions

## Scope

Sayaka contains an MPL-2.0 Rust in-memory planning core, a macOS read-only scanner
and CLI, explicit M3 native Trash sessions, and future native bindings. Follow [ROADMAP.md](ROADMAP.md)
and the contracts in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Do not report a planned feature as implemented.

The long-term CLI objective is full major-capability coverage of Mole CLI with
evidenced usability, speed, and complete-footprint advantages. Follow
[docs/COMPETITIVE.md](docs/COMPETITIVE.md); never claim parity from the scaffold,
compare unequal workloads, omit runtime dependencies, or weaken protection to
win a benchmark. Native graphical applications are a separate comparison.

M1's `Probe` is a trusted read-only embedding interface. Its snapshot assertions
and `ValidationReport::ready` are not proof that a filesystem mutation is safe.
Do not feed it to an executor. Only the separately owned `TrashSession` can
execute its own approved `revalidated_trash_v1` plan. Follow
[docs/EXECUTION.md](docs/EXECUTION.md): this approved contract explicitly retains
a last-check/path-replacement race and must never be described as race-free.
Preserve the no-effects boundary of existing M1 and scanning APIs.

## Implementation

Keep changes surgical. The fourth crate, `sayaka-platform-macos`, is an explicitly
approved audit boundary for native FFI; keep `sayaka-engine` unsafe-free and do not
spread native FFI into its model/scan logic. Use native path types internally, opaque resource IDs
at client boundaries, explicit capability/error states, and one shared policy
path. No arbitrary commands, approval booleans, privilege escalation fallbacks,
or permanent deletion after a failed trash operation.

The browser's terminal, input and worker lifecycle belongs in `sayaka-cli`;
the immutable scan tree and directory accounting stay in the engine. Follow
[docs/BROWSING.md](docs/BROWSING.md). Keep generations and exact preview identity
bound, restore the terminal and join owned work on exit, and never turn a directory
selection or refresh into additional native Trash targets.

System status follows [docs/STATUS.md](docs/STATUS.md): keep native reads in the
platform boundary, rates/freshness in the engine, and output in the CLI. Never
replace failed probes with zero, use stale data to clear alerts, or introduce
maintenance actions/privileged collectors into the read-only sampler.

Local lifecycle work follows [docs/LOCAL_LIFECYCLE.md](docs/LOCAL_LIFECYCLE.md).
History filters must preserve pending evidence and complete operation outcomes.
Installation/removal is restricted to verified dedicated prefixes; never modify
shell startup files, overwrite unowned artifacts, erase history or auto-clean
staging by name. Validate only in explicitly owned temporary prefixes.

Follow [docs/SCANNING.md](docs/SCANNING.md). Do not weaken no-follow opens,
materialization policy, native volume classification or budget/error semantics
to make a scan or benchmark pass. Unavailable native metadata is not permission.

Add `SPDX-License-Identifier: MPL-2.0` to source files. Keep third-party provenance
and license obligations explicit. Do not publish private source, planning
archives, local paths/logs, credentials, or real user data.

## Validation

This repository explicitly permits agents to run unit, integration, and system
tests as well as builds; older build-only/unit-only restrictions do not apply
to Sayaka. Follow [docs/TESTING.md](docs/TESTING.md), including fixture isolation
and opt-in native-system cases. No destructive tests on real user data, silent
elevation, or indiscriminate trash cleanup.

Run the narrowest relevant checks and add tests with behavior changes. Report
zero tests, missing prerequisites, skipped native cases, and cleanup failures
honestly. macOS execution cannot certify Windows behavior. Do not add GitHub
Actions workflows or GUI/UI test targets.

## Handoff and publication

Follow the role boundaries and definition of done in
[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md). Keep implementation evidence
separate from independent review. Commit, push, release, or create external
resources only when authorized for the current task. Public documentation must
be self-contained and must not depend on private issue links.
