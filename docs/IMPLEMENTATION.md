# Implementation work packages and ownership

Status: M0, the M1 in-memory core and M2 macOS read-only scanning are implemented;
M3 adds the initial native Trash/approval/journal slice under
[the revised execution contract](EXECUTION.md). Native system acceptance remains
separate; the remaining packages are planned. These do not establish Windows
runtime behavior. See [SCANNING.md](SCANNING.md)
for implemented M2 scope, local budgets and unavailable native environments.
M7's initial terminal browser and directory accounting are described in
[BROWSING.md](BROWSING.md); broader task-family coverage and human usability
acceptance remain separate.
The initial T11 macOS read-only sampler and its remaining capability gaps are
documented in [STATUS.md](STATUS.md); it is not complete cross-platform telemetry.
Initial T12 history/completion/local-prefix behavior is described in
[LOCAL_LIFECYCLE.md](LOCAL_LIFECYCLE.md); online distribution and authentication
integration remain separate.
This document describes public technical responsibilities, not staffing or dates.

## Work packages

| Package | Files when needed | Deliverable | Dependency |
| --- | --- | --- | --- |
| T1: model and test foundation | `crates/engine/src/model.rs`, `plan.rs`, `receipt.rs`, unit tests and test support | Implemented in-memory facts/plans/results, decisions, clock/ID/probe injection and isolated test foundation | M0 |
| T2: read-only scanner and CLI | `crates/engine/src/scan/`, `platform/`, `crates/cli/`, integration fixtures | Bounded enumeration, correct accounting, structured errors/progress and versioned JSON | T1 |
| T3: execution and journal | `crates/engine/src/execute/`, `journal/`, macOS adapter, CLI confirmation | Feasibility evidence, exact-plan approval, durable intent, restricted trash actions, crash reconciliation | T2 |
| T4: early Windows adapter | Windows adapter and native integration fixtures | Real Windows read-only slice first; write/partial-failure slice after T3 contracts | T1; T3 for writes |
| T5: evidence-backed rules | `crates/engine/src/rules/`, rule fixtures | Small reviewed rule set with provenance, non-targets, version checks, recovery costs | T3 and T4 |
| T6: bindings and release contract | `crates/bindings/`, native smoke consumers, release documentation | Versioned ownership/error/cancellation contracts and documented source/binary release gates | T3 and T4 |
| C0: comparative evidence | Benchmark fixtures/harness and result manifests when implemented | Frozen capability cases, full-install size baseline, paired timing protocol, usability tasks | Starts with M0; harness grows with T1/T2 |
| T7: interactive CLI | `crates/cli/`, terminal event/rendering and process fixtures | Discoverable menu/disk explorer, filtering, multiselect, preview, cancellation | T2; T3 for actions |
| T8: full cleanup workflows | Rules, project/installer discovery and CLI flows | Clean/purge/installer task coverage with positive and protected cases | T5 and T7 |
| T9: app management | App discovery/platform operations/rules and CLI flows | Installed-app removal and related-data selection with shared-state protection | T5 and T7 |
| T10: specific system maintenance | Platform diagnostics/restricted maintenance operations and CLI flows | Explicit preconditions, reviewed privilege boundaries, native outcomes | T3 and T7 |
| T11: status monitoring | Bounded platform collectors and CLI rendering/streaming | Accurate and fresh metrics, JSON/NDJSON, alerts, measured collector overhead | T2 |
| T12: CLI lifecycle and convenience | CLI history, installation/update/removal support and completion/launch integration | Verifiable lifecycle and explicit OS-auth convenience | T3; T10 boundary for authentication setup |

Do not pre-create every listed module. Each package is a vertical slice with its
own tests and error behavior, not a reason to land an entire speculative engine.
T4 investigation starts early. Public APIs should remain cheap to change until
both platforms have exercised their semantics.

T7-T12 expand the original foundation into full CLI competition. M2 established
a fourth, narrowly scoped native FFI crate; do not add further splits without
a demonstrated boundary.
T6 bindings and native GUI work must not inflate or block the CLI comparison
profile. C0 spans all packages; C1 is the final acceptance gate, not another
feature implementation. See [COMPETITIVE.md](COMPETITIVE.md) for the ledger and
the meaning of a verified usability, speed, or size advantage.

## Responsibilities

| Role | Owns | Required handoff | Must not substitute for |
| --- | --- | --- | --- |
| Architect | Scope, invariants, interfaces, platform assumptions, dependency order | Narrow implementation contract, acceptance cases, open decisions | Working code or execution evidence |
| Implementer | Code, unit/integration/system checks, fixtures, error handling, documentation | Changed behavior, exact commands/results, environment, skipped/blocked cases | Independent approval of its own work |
| Reviewer | Contract adherence, execution boundaries, regression risk, evidence quality | Concrete findings or scoped approval; remaining uncertainty | Running one platform and asserting another works |
| Maintainer | Product priorities, supported environments, privilege/signing decisions, release approval | Decisions and environment access where necessary | Routine automated tests that the implementer can run |

Automated tests are part of implementation work, not a blanket manual handoff.
Independent review is a role requirement for feature completion, not a claim that
this initial scaffold has already received independent review.

## Required implementation contract

Before each slice, record:

- Inputs, outputs, error/status meanings, and version compatibility.
- Scope and capabilities, including explicitly unsupported behavior.
- Safety invariants, expected effects, and recovery limits.
- Unit cases, real-platform cases, fault-injection points, and fixture cleanup.
- Measurable resource/performance targets with the fixture and host definition.
- Dependencies and blocking decisions; no unstated platform assumptions.
- Mole capability cases affected, equivalent-work checks, and size/runtime budget
  impact for any change contributing to CLI parity.

For T2, enforce configured worker, queue, and handle limits in deterministic
tests. Record first-result latency, cancellation latency, peak memory, and
completeness on a versioned fixture. Fix numerical performance targets in its
implementation issue after a baseline measurement and before milestone acceptance.
Do not invent benchmark results or universal latency guarantees for blocked OS I/O.

For T3, feasibility review precedes write implementation. The original atomic
identity/scope gate was blocked and returned for a scope decision. The maintainer
explicitly approved `revalidated_trash_v1` with its residual race disclosed.
Future actions still require their own feasibility and scope review; this
decision is not permission to bypass observed changes, expand targets, or
claim atomic source binding.

## Definition of done

The required positive, rejection, cancellation, and failure cases pass on the
relevant host. Results distinguish passed, failed, skipped, and blocked; zero
matching tests does not pass a feature gate. The reviewer checks the evidence
against the actual required behavior, not just line coverage or a green build.

Public documentation and CLI help describe what exists. New behavior includes
its corresponding tests in the same change. Changes to persisted schemas, rules,
or approval semantics include compatibility and stale-plan behavior.
No open blocking finding may be hidden by narrowing a report after execution.

For competitive acceptance, report each major capability and each performance/
footprint scenario. Unsupported is not parity and unmeasured is not a win.
Do not tune away safety work, omit necessary dependencies, change the benchmark
scope after seeing results, or substitute simulated users for usability evidence.

## Outstanding decisions

Minimum supported macOS/Windows versions and CPU architectures, the Windows
execution host, initial rule categories, native binding tools, and binary
distribution/signing channels remain unselected. Initial M3 uses Foundation Trash
and the bounded journal described in [EXECUTION.md](EXECUTION.md); other action
primitives still need their own decisions. Do not assume the developer's current
machine represents a broader support matrix.
