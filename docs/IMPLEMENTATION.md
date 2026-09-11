# Implementation work packages and ownership

Status: planned work. Only M0 is implemented.
This document describes public technical responsibilities, not staffing or dates.

## Work packages

| Package | Files when needed | Deliverable | Dependency |
| --- | --- | --- | --- |
| T1: model and test foundation | `crates/engine/src/model/`, `plan/`, unit tests and test support | Typed facts/plans/results, policy decisions, clock/ID injection, fixture ownership, rejection-case matrix | M0 |
| T2: read-only scanner and CLI | `crates/engine/src/scan/`, `platform/`, `crates/cli/`, integration fixtures | Bounded enumeration, correct accounting, structured errors/progress and versioned JSON | T1 |
| T3: execution and journal | `crates/engine/src/execute/`, `journal/`, macOS adapter, CLI confirmation | Feasibility evidence, exact-plan approval, durable intent, restricted trash actions, crash reconciliation | T2 |
| T4: early Windows adapter | Windows adapter and native integration fixtures | Real Windows read-only slice first; write/partial-failure slice after T3 contracts | T1; T3 for writes |
| T5: evidence-backed rules | `crates/engine/src/rules/`, rule fixtures | Small reviewed rule set with provenance, non-targets, version checks, recovery costs | T3 and T4 |
| T6: bindings and release contract | `crates/bindings/`, native smoke consumers, release documentation | Versioned ownership/error/cancellation contracts and documented source/binary release gates | T3 and T4 |

Do not pre-create every listed module. Each package is a vertical slice with its
own tests and error behavior, not a reason to land an entire speculative engine.
T4 investigation starts early. Public APIs should remain cheap to change until
both platforms have exercised their semantics.

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

For T2, enforce configured worker, queue, and handle limits in deterministic
tests. Record first-result latency, cancellation latency, peak memory, and
completeness on a versioned fixture. Fix numerical performance targets in its
implementation issue after a baseline measurement and before milestone acceptance.
Do not invent benchmark results or universal latency guarantees for blocked OS I/O.

For T3, the feasibility review precedes write implementation. It must identify the
OS mutation primitive and its identity-binding limits. If no safe primitive
supports the proposed operation/threat model, keep that operation unavailable
and return the scope decision to the Architect rather than weakening the gate.

## Definition of done

The required positive, rejection, cancellation, and failure cases pass on the
relevant host. Results distinguish passed, failed, skipped, and blocked; zero
matching tests does not pass a feature gate. The reviewer checks the evidence
against the actual required behavior, not just line coverage or a green build.

Public documentation and CLI help describe what exists. New behavior includes
its corresponding tests in the same change. Changes to persisted schemas, rules,
or approval semantics include compatibility and stale-plan behavior.
No open blocking finding may be hidden by narrowing a report after execution.

## Outstanding decisions

Minimum supported macOS/Windows versions and CPU architectures, the Windows
execution host, initial rule categories, state-store details, concrete mutation
primitives, native binding tools, and binary distribution/signing channels remain
unselected. Decide each before its dependent gate, not by silently assuming the
developer's current machine represents the support matrix.
