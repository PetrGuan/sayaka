# Implementation work packages and ownership

Status: implemented foundations and partial user workflows coexist. The model,
macOS scan/native ordinary-file Trash and Windows x64 read-only scan are present.
Terminal interaction, two rules/clean, installer selection, app previews,
status/process top and local CLI lifecycle are implemented slices, not wholly
planned packages and not complete T7-T12 milestones.
The [roadmap status table](../ROADMAP.md#milestone-status-and-remaining-gates)
is the current delivery/gap summary; per-feature contracts provide evidence.
The [installer native round trip](INSTALLER_PREVIEW.md#recorded-native-acceptance)
is a scoped local macOS/APFS result, while [Windows x64 evidence](WINDOWS.md)
independently covers its read-only slice. Neither certifies all platforms,
directory effects, arbitrary recovery, public binary distribution or parity.
This document describes public technical responsibilities, not staffing or dates.

## Work packages

| Package | Implementation surfaces | Responsibility and current scope | Dependency |
| --- | --- | --- | --- |
| T1: model and test foundation | `crates/engine/src/model.rs`, `plan.rs`, `receipt.rs`, unit tests and test support | Implemented in-memory facts/plans/results, decisions, clock/ID/probe injection and isolated test foundation | M0 |
| T2: read-only scanner and CLI | `crates/engine/src/scan/`, native platform crates, `crates/cli/`, integration fixtures | Implemented bounded enumeration, accounting, errors/progress, JSON and indexes; broader environment evidence remains | T1 |
| T3: execution and journal | `crates/engine/src/execute.rs`, `execute/`, `journal.rs`, macOS adapter, CLI confirmation | Implemented ordinary-file approval, durable intent/outcomes and reconciliation under the residual-race contract | T2 |
| T4: early Windows adapter | Windows adapter and native integration fixtures | x64 fixed-NTFS read-only slice accepted; ARM64 linked/native evidence and Windows writes remain separate | T1; independent native contract for writes |
| T5: evidence-backed rules | `crates/engine/src/rules.rs`, `rules/`, rule fixtures | CPython source-backed `.pyc` and `javac` source-backed `.class`; broader rule coverage and Windows native inspection remain | T3 and platform evidence |
| T6: bindings and release contract | `crates/bindings/`, C/Swift host examples, integration documentation | Read-only scan and task-bound directory-query C ABI implemented; native App/Windows runtime, broader APIs and binary delivery remain | Shared scan/lifecycle/index; independent native platform evidence |
| C0: comparative evidence | `benchmarks/`, `scripts/`, versioned results | Fixed ledger and constrained direct-analyzer/diagnostic evidence exist; full installed size, complete equivalent-task coverage and real-user usability evidence remain gaps | M0, T1/T2; continues with T7-T12 |
| T7: interactive CLI | `crates/cli/`, terminal event/rendering and process fixtures | Implemented macOS menu/browser and ordinary-file approval entries; full UX/platform acceptance remains | T2; T3 for actions |
| T8: full cleanup workflows | Rules, installer discovery/selection and CLI flows | Two-rule clean and narrow installer workflow implemented; directory assessment is ModelOnly, not purge execution | T5 and T7; new contracts for directory actions |
| T9: app management | App discovery/association and CLI flows | Implemented read-only `apps` and `apps-related`; no uninstall/delete authorization | T5 and T7; new action/ownership contracts |
| T10: specific system maintenance | Future bounded native operations and CLI flows | No maintenance actions implemented; explicit preconditions, privilege boundaries and native outcomes required | T3 and T7 |
| T11: status monitoring | Engine/native status modules and CLI rendering/streaming | macOS status/watch/process top implemented; numeric temperature, GPU and Windows remain gaps | T2 |
| T12: CLI lifecycle and convenience | History, local installation lifecycle and completions | Local install/update/recover/remove implemented; distribution/authentication/launchers and Windows installation remain | T3; T10 boundary for authentication setup |

Do not pre-create every listed module. Each package is a vertical slice with its
own tests and error behavior, not a reason to land an entire speculative engine.
T4 already has a native x64 read-only baseline. Keep remaining platform work
early rather than inferring its semantics from macOS.

T7-T12 expand the original foundation into full CLI competition. The five-crate
workspace has separate macOS and Windows native audit boundaries; do not add
further splits without a demonstrated need.
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
Independent review is a role requirement for feature completion. Existing scoped
reviews do not replace a new review for changed behavior or a broader acceptance
claim.

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

Windows product targets are Windows 11 or later on x64 and ARM64. The early
read-only acceptance slice uses a real Windows 11 x64 host; ARM64 native acceptance
is a separate maintainer-approved follow-up, not certified by cross-compilation.
See [WINDOWS.md](WINDOWS.md) for supported scope and actual evidence.
Minimum macOS versions and the broader architecture/support matrix, additional
rule categories, native binding tools, and binary distribution/signing channels
remain open. Local arm64 evidence and the two implemented rule families do not
close those broader decisions. M3 uses Foundation Trash
and the bounded journal described in [EXECUTION.md](EXECUTION.md); other action
primitives still need their own decisions. Do not assume the developer's current
machine represents a broader support matrix.
