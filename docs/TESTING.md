# Testing policy

## Authorization and limits

For this repository, contributors and coding agents are authorized to run local
builds, unit tests, integration tests, and system tests. Automated validation is
the implementer's responsibility. This repository-specific policy supersedes
earlier build-only or unit-tests-only restrictions for Sayaka.

Permission to run tests is not permission to clean a workstation. Mutating tests
must operate only on explicitly created test-owned fixtures or a dedicated
disposable environment. Never scan a home directory by default, clean real
application caches, uninstall real applications, empty the user's trash, change
system protections, or request elevation silently.

No GUI/UI automation targets are planned in this core repository. Native-client
UX verification belongs to those clients. Core CLI process tests are integration
tests, not GUI tests. Headless terminal-event and pseudo-terminal checks can
validate TUI mechanics without creating native GUI test targets.

## Current baseline

The repository currently has a buildable scaffold and no substantive automated
tests. Do not interpret a zero-test `cargo test` result as engine validation.
The first real implementation must add its tests with the code.

Existing workspace commands:

```sh
cargo fmt --all -- --check
cargo build --workspace --locked
cargo test --workspace --locked
```

Use targeted package/test selectors during development, then the relevant
workspace checks before a feature handoff. Do not install coverage, fuzzing, or
benchmark tools for a documentation-only task. Add such tooling only with the
implementation work that uses it.

## Test layers

| Layer | Runs automatically where | Must prove |
| --- | --- | --- |
| Unit | Local Rust host | Pure decisions, policy precedence, state transitions, exact approval binding, deterministic clocks/IDs |
| Isolated integration | Suitable local host | Actual fixture enumeration, links, accounting, CLI exit codes/stdout/stderr, persistence and restart behavior |
| Native system | Matching OS with an explicit test environment | Real trash/recovery semantics, file sharing/locks, reparse behavior, permission failures and native API outcomes |
| Failure/property testing | Local host with controlled adapters/processes | No authorization expansion, no duplicate effects, partial failure, cancellation, crash windows, malformed input |
| Performance | Recorded host and versioned fixture | Resource caps, latency, memory, cancellation and completeness under stated conditions |
| Manual/environment acceptance | Maintainer when required | OS permission prompts, signing/install trust, hardware/volume cases that automation cannot faithfully reproduce |

Start with deterministic examples. Add property tests for plan set containment,
policy precedence, and state transitions where useful. Add fuzzing for input
parsers/FFI only once those surfaces exist. No line/branch coverage percentage
alone proves filesystem correctness; every enumerated safety case needs an
assertion, including refusal paths.

## Isolation contract

Create unique per-run fixture roots with an ownership marker. Preserve paths and
identities in the fixture registry; do not discover cleanup targets by broad name
matching or environment-controlled paths. A marker alone is not protection
against ancestor replacement: reject cleanup when containment/identity cannot be
established. Delete only fixtures owned by the current run.

Use dedicated fixture locations and redirected application state/config/temp
paths for child CLI processes. Do not allow tests to read or write normal Sayaka
state, user configuration, or unrelated files. Paths printed in shareable logs
must be synthetic or redacted. Never publish real filesystem listings.

Real-trash tests are opt-in, serialized, and must retain precise object-specific
recovery/cleanup references. They must never empty a trash directory or infer
ownership from a filename. A dedicated account or disposable VM is required when
safe per-object cleanup cannot be guaranteed. Restore conflicts must preserve the
existing destination.

Use fault injection for disk-full, journal failure, and crash timing rather than
filling the real system disk or terminating unrelated processes. Spawn and track
specific child processes for crash scenarios. Permission tests must verify the
fixture actually denies access; privileged execution can invalidate such a case.

## Default versus opt-in suites

Default workspace tests must be unattended, bounded, fixture-only, and require no
elevation, authorization dialogs, external network, or access to user data.
Register real-system tests separately and exclude them from that default path.

When a system-test target is implemented, document its exact invocation,
prerequisites, fixture lifecycle, and cleanup procedure in the same change.
An explicit opt-in is required before executing ignored/destructive-environment
cases. A missing prerequisite is recorded as skipped or blocked, not a silent
successful return. Do not run all ignored tests indiscriminately.

## Required case inventory

| Area | Cases that cannot be omitted |
| --- | --- |
| Selection/policy | Unknown IDs, expired plans, version changes, excluded/protected roots, parent/child overlaps, malformed approval |
| Paths/identity | Non-UTF-8 Unix paths, Windows native strings, display control characters, traversal, link/reparse loops, target/ancestor replacement |
| Scan/accounting | Empty and deep trees, bounded queues/handles, hard links, sparse files, unknown allocated bytes, denied subtrees, stale task events |
| Effects | Unsupported capability, target changed, busy object, cancellation before/during work, partial batch, no permanent-delete fallback |
| Journal | Intent-write failure, crash before/after effect, outcome-write failure, interrupted `Started`, reconciliation without replay |
| Recovery | Missing trash item, occupied destination, unsupported volume, recovery unavailable, no false free-space claim |
| CLI/FFI | Exact JSON shape, stdout/stderr separation, exit-status mapping; later ownership/release, callback cancellation and panic containment |

Windows-native results require a real Windows host or Windows VM. Cross-compiling
or simulating an adapter on macOS does not satisfy native acceptance. APFS, NTFS,
cloud placeholders, network volumes, and OS permission systems require their own
declared environment; unsupported environments remain outside release claims.

## Evidence and release gates

Record commit, OS/architecture, Rust version, test command/selector, fixture
version, case counts, pass/fail/skip/block status, and cleanup outcome. Keep
failure output actionable and sanitized. Performance reports also identify
hardware, workload, cold/warm state, and configured budgets.

All required cases for a claimed capability must pass on its supported platform.
Blocked native cases block that capability's acceptance, not unrelated read-only
work. Human intervention is reserved for environment/consent requirements, not
routine unit testing. No GitHub Actions workflow is used; run locally or on
explicitly provisioned native hosts. External hosts/services require separate
access and cost approval.

## Comparative acceptance

Use [COMPETITIVE.md](COMPETITIVE.md) for the pinned Mole baseline, capability
inventory, equivalent-work timing, complete distribution size, and usability
protocol. The published artifact sizes are metadata, not measured runtime or
full-install results. C0 must freeze scenario manifests and statistical rules
before collecting competitive measurements.

Do not run a competitor's broad maintenance command on a developer workstation,
even if it advertises dry-run. Use verified fixture-only entry points or a
disposable native environment and reset state between comparable runs. Preserve
both tools' real safety checks and track which eligible objects were handled.
Unknown/private user data must not enter shared benchmark artifacts.

Functional headless CLI/TUI tests validate mechanics and output contracts, not
human usability. Participant-based task success, safety comprehension and
interaction burden require real observations with consent. Record unmeasured
usability and unavailable native environments honestly; never synthesize results
to close a competitive milestone.
