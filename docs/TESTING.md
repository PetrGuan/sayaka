# Testing policy

C0 batch-2 collector regressions use unique owned workspaces and synthetic
children; they do not execute Mole. The measurement runner keeps raw process
captures private, stops on output limits or failed correctness/integrity gates,
and requires a separately reviewed guard plus explicit execution authorization.
Required setuid/setgid OS helpers are a blocked precondition, not a canary to
execute with elevated permissions. A blocked preflight marks remaining probes
as not run and prevents Phase B; current batch-2 preregistration also explicitly
disallows runtime execution.

Admission/launch diagnostics have focused Python regressions:

```sh
python3 -m unittest scripts.tests.test_check_c0_batch2_phase_b \
  scripts.tests.test_check_c0_batch3_direct_analyzer \
  scripts.tests.test_check_sayaka_admission_profile
cargo test -p sayaka-cli --locked profile_
```

The macOS-only diagnostic collector uses CLOCK_UPTIME_RAW for cross-process
clock compatibility, including Python 3.9. Its optional kqueue exit observer is
covered by owned-child cases for exit-after-EOF, inherited pipes, timeouts and
output limits. Invalid clock ordering, changed native identities, missing
fields and invalid nested phase data must fail instead of becoming timings.
The guarded benchmark runner additionally requires a frozen manifest, explicit
`--execute`, unchanged inputs, and passed allow/deny canaries. It does not run
Mole, installers, maintenance or real Trash.

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

M1 includes deterministic model/plan tests, compile-fail API privacy checks, and
isolated fixture/owned-child integration tests. The latter verify a public-API
round trip, child failure reporting, timeout termination and explicit cleanup.
Fixtures contain only synthetic files, and their probes supply synthetic identity
and capability evidence; these are not native trash or authorization tests.

Clock changes, ID collisions/exhaustion, probe failures and cancellation are
injected deterministically. The short process wait loop is only a bounded child
lifecycle mechanism, not a timing assumption for model correctness.
M2 adds bounded-scanner fault matrices, macOS metadata fixtures and CLI process
tests. Native binding tests and owned C/Swift consumers cover the read-only scan
and directory-query ABI; see [BINDINGS.md](BINDINGS.md). Windows scanning has initial
native NTFS and CLI evidence, with full acceptance still incomplete; see
[WINDOWS.md](WINDOWS.md).
See [SCANNING.md](SCANNING.md) for the precise scope and missing environments.

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

The dedicated [M2 benchmark runner](../scripts/check_m2_benchmark.py) uses only
generated fixtures and validates byte/count truth before accepting timing. Its
[versioned budgets](../benchmarks/m2-v1.json) are local regression gates; a fast
partial scan or an incomplete fixture is a failure, not a performance result.

Guarded-host C0 batch-2 Phase A uses
[`scripts/check_c0_batch2_phase_a.py`](../scripts/check_c0_batch2_phase_a.py)
to validate pinned source/assets, stage an owned install root, freeze a sandbox
profile hash, and execute owned allow/deny canaries (read/write/exec/network).
This phase does not execute Mole program commands or collect performance samples.
The current profile includes a runtime-only literal `"/"` read exception (not a
recursive root allowlist) to avoid dyld bootstrap aborts while preserving denied
child-path reads outside owned allow roots. It also includes metadata-only
literal `"/System/Volumes/Data"` (no recursive subpath grant) to satisfy
Sayaka's volume metadata lookup without expanding data-read scope. The final
host preflight is blocked by required setuid `/bin/ps`; current canaries and the
Sayaka control scan are marked `not_run_precondition`. Earlier successful
runtime-only probes are historical validation, not current execution approval.
The blocked record carries a nonzero exit and a concrete `blocked_prerequisite`
code. Phase B remains disabled by the current manifest; any future execution
requires a newly reviewed environment and explicit authorization.

## Required case inventory

The initial M3 default suite adds executor fault injection, bounded private
journal storage, child-process crash interpretation and preview/refusal CLI
checks. These do not run real Trash actions. See [EXECUTION.md](EXECUTION.md)
for the approved revalidation contract: the residual final path race is disclosed,
not a native safety property that a happy-path test can certify.
The rule-bound slice adds default tests for `rules trash` explicit selection,
schema v3 plan / schema v2 journal binding validation, and source-witness
revalidation ordering (including checks after durable intent and before native
effect). Default tests still must not invoke real Trash.

The rule-bound real native case is ignored by default and must only be invoked
once under explicit authorization:

```sh
SAYAKA_M3_TRASH_TEST=1 SAYAKA_M3_TRASH_TEST_QUIESCENT=1 \
  cargo test -p sayaka-engine --locked \
  --test rules_native real_rule_bound_trash_session_round_trip_owned_fixture \
  -- --ignored --exact --nocapture --test-threads=1
```

Prerequisites: macOS, no concurrent Trash operations, synthetic source/cache
fixture only, identity-verified destination, and no-overwrite restore via
native exclusive rename semantics. The test fixture root is created under
`<repo>/crates/engine/target/native-test-fixtures` (non-hidden project-owned
location on the same approved volume), not system temporary directories.

### Installer CLI owned-fixture native acceptance

The separate ignored platform test
`trash::native::tests::installer_roundtrip::real_installer_cli_owned_fixture_round_trips`
is an explicit native-effects gate, never a default test or permission to run
all ignored cases. It requires a previously built/reviewed `target/release/sayaka`
and that exact artifact's SHA-256:

```sh
SAYAKA_INSTALLER_TRASH_TEST=1 \
SAYAKA_INSTALLER_TRASH_TEST_QUIESCENT=1 \
SAYAKA_INSTALLER_CLI_SHA256='<reviewed-release-sha256>' \
cargo test -p sayaka-platform-macos --lib --locked \
  trash::native::tests::installer_roundtrip::real_installer_cli_owned_fixture_round_trips \
  -- --ignored --exact --nocapture --test-threads=1
```

Only use these flags after current explicit authorization and externally
confirmed absence of competing Trash/fixture namespace operations. Do not
automatically replace a failed artifact hash with a newly computed one.
The native existing Trash directory must already be accessible and pass the
retained-directory/private-mode/non-granting-ACL/same-device checks; the test
does not guess, create or repair it.

The frozen scope is one explicit-selection synthetic UDIF file, followed by
two fresh synthetic UDIF/flat-PKG files selected numerically through the actual
CLI. A bounded PTY driver observes the sealed-plan/exact-count prompt before
sending the authorized phrase. Each case has dedicated HOME/TMP/state and an
excluded sentinel. At most three installer files enter Trash; there is no retry.
The test neither mounts images nor runs package payloads, and its structural
fixtures are not assertions of mountability/installability/trust.
The supervisor uses a private socket to receive command status from a broker
that stays alive until the owned group is closed. It observes unexpected leader
exit without reaping (`WNOWAIT`) and never signals a reused/reaped group id.
Keeping a live broker avoids treating Darwin's zombie-only group signalling
failure as success or losing supervision of failed-driver descendants.

Receipts must contain precisely the registered successful identities, no
pending/unknown outcomes, and exact native paths. Only returned locations whose
parent matches the native Trash directory and whose identity/ACL/content match
retained original descriptors can be restored. Each restoration first proves
EEXIST against a newly created owned blocker without modifying either object,
relocates the blocker exclusively within the fixture, and restores the original
exclusively. It never enumerates Trash or identifies ownership by filename.
As in the production verifier, post-move ctime is anchored to the observed
location before returning to strict validation; identity, stable metadata,
ACLs and complete synthetic contents must still match.

Source/receipt/restore observations and hashes are retained privately under a
unique ignored `target/installer-evidence-*` directory. Any unexpected result
preserves the fixture and logs; a timeout after confirmation may be ambiguous
and must not trigger a rerun or guessed cleanup. After complete verification,
only registered fixture identities and bounded owned auxiliary entries are
cleaned. The final pathname race remains; this is not atomic inode-bound
recovery or a guarantee for arbitrary storage, files or accounts.

No-effect helper controls can be run independently:

```sh
cargo test -p sayaka-platform-macos --lib --locked installer_roundtrip \
  -- --skip real_installer_cli_owned_fixture_round_trips
```

An implemented test command is not evidence that its native gate has run;
record actual outcomes separately from default helper/fixture checks.
The [installer native acceptance record](INSTALLER_PREVIEW.md#recorded-native-acceptance)
documents one completed local three-file run and an earlier preserved
zero-effect tool failure; it does not authorize future runs.

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
