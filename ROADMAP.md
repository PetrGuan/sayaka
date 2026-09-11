# Roadmap

This is a development plan, not a list of supported features or promised dates.
Only the initial workspace and CLI help/version are implemented today.

## Product objective

Cover all major Mole CLI capabilities, then demonstrate better usability, faster
execution, and a smaller complete distribution. This is a staged engineering
objective, not a claim that Sayaka already matches Mole. Compare CLI to CLI;
native graphical applications have a separate roadmap.
The [competitive contract](docs/COMPETITIVE.md) fixes the reference version,
capability ledger, fair measurement rules, and acceptance gates.

## Delivery sequence

| Stage | Deliverable | Depends on | Exit gate |
| --- | --- | --- | --- |
| M0 | Workspace, MPL-2.0, basic CLI entry point | None | Complete |
| M1 | Deterministic domain model, safety policy, plan lifecycle, test harness | M0 | Every defined decision/state transition has positive and rejection cases; no filesystem mutation API exposed |
| M2 | Bounded, read-only macOS scanning and structured CLI output | M1 | Correct fixture accounting, explicit partial results, enforced resource budgets, cancellation evidence |
| M3 | Narrow macOS approval/execution/journal loop | M2 and a successful platform mutation feasibility review | Only approved eligible objects are handled; failure, cancellation, and crash windows have truthful receipts |
| M4 | Early Windows vertical slice | Starts after M1; complete before M5 | Shared contracts validated with real Windows filesystem and process behavior |
| M5 | Small evidence-backed rule set | M3 and M4 | Each rule has ownership evidence, protected non-targets, recovery limits, and native-platform evidence |
| M6 | Versioned client bindings and source-release readiness | M3 and M4; may proceed alongside M5 | Native consumer smoke builds, lifecycle/error checks, documented support matrix and reproducible release instructions |
| C0 | Frozen Mole capability inventory and benchmark harness | Starts now; real harness alongside M1/M2 | Versioned cases, full-install footprint, equivalent-work speed protocol and usability study design |
| M7 / T7 | Interactive CLI and disk explorer | M2; confirmed actions need M3 | Keyboard navigation, filtering, multiselect, previews, cancellation and terminal restoration |
| M8 / T8 | Full cleaning, project-artifact and installer workflows | M5 and T7 | Version-pinned rule/task ledger covered with safe effects and protected non-targets |
| M9 / T9 | Application discovery and uninstall workflows | M5 and T7 | Supported installation/removal cases, related-data plans, multi-copy protection, truthful partial outcomes |
| M10 / T10 | Bounded system diagnostics and maintenance | M3 and T7 | Specific maintenance operations, capability/privilege review, recovery limits and native evidence |
| M11 / T11 | Read-only system status and streaming | M2; can run alongside M3 onward | Native metric freshness, bounded sampling, JSON/NDJSON, alerts and steady-state overhead |
| M12 / T12 | CLI history, install/update/remove and convenience | M3; auth convenience needs T10's reviewed boundary | Verified distribution lifecycle, completion, launch integration, explicit supported authentication setup |
| C1 | Full CLI competitive acceptance | C0, T7-T12 and their prerequisites | Every major capability covered; usability, speed and complete-size gates all evidenced |

M4 is an early parallel workstream, not a port postponed until macOS feature
expansion. Start with the shared model and read-only fixtures while M2/M3 proceed;
its write path depends on the execution contract established in M3. If no Windows
host is available, record that gate as blocked rather than calling mocks a port.

M1-M6 remain foundation work, not full Mole parity. T6's native bindings are not
a prerequisite for CLI competitive acceptance; their integration work can proceed
separately. T12 owns the full CLI distribution lifecycle and uses the source/
compatibility rules established by the core. Do not serialize T11 behind every
mutating feature, or defer C0 measurements until the end.

## Milestone boundaries

### M1: make decisions testable

Define observations, findings, immutable plans, approval, execution receipts,
stable reason codes, and explicit capability states. Separate pure decisions from
platform effects. Introduce controlled fixtures and failure injection alongside
the first real logic; a passing suite with zero tests is not completion.

### M2: understand a selected scope

Scan only explicitly selected roots. Do not follow links/reparse points, cross
volumes, traverse network/removable volumes, or hydrate cloud placeholders by
default. Do not treat denied access as an empty directory. Track logical bytes,
allocated bytes when known, hard-link deduplication, completeness, and task IDs.
No cleaning commands are available at this stage.

### M3: a narrow, honest write path

First prove which platform operations can satisfy identity and scope constraints.
The initial candidate is moving explicitly selected ordinary files to the system
trash on a supported local volume, with ordinary user permissions. Recursive
directory mutation, permanent deletion, broad cache clearing, and uninstallers
are excluded from this milestone.

An API that checks an object and then mutates an unbound pathname is not sufficient
proof against replacement races. Unsupported guarantees must block that operation
or keep it read-only, not be waived to finish a milestone. Review and document the
supported threat model and remaining OS guarantees before enabling writes.

Persist execution intent before effects, record per-item outcomes afterward,
and preserve `Unknown` across ambiguous crashes. Never automatically replay
unresolved actions. A trash move does not mean disk space was freed or that
restoration is guaranteed.

### M4: prove the Windows differences

Exercise native path representation, volume/file identity, sharing violations,
reparse points, cancellation, supported trash behavior, and partial results.
macOS mocks and cross-compilation are supporting evidence, not the exit gate.
Keep unsupported behavior explicitly unavailable.

### M5: expand only from evidence

Select a small rule set after measuring actual value and confirming supported
software versions. Every rule must identify what it will not touch. Built-in Rust
rules ship with the engine; no executable rule DSL, shell snippets, or plugin
marketplace. Application discovery can precede uninstall support, but lack of an
observed owner is never proof that data is abandoned.

### M6: integrate without duplicating policy

Keep native graphical clients outside this repository. Evaluate Swift bindings
and a small C ABI for Windows consumers against the proven engine contracts.
Choose binding dependencies only when implementing those consumers. Publish the
actual tested OS/architecture matrix, not assumed support. Source publication is
already enabled; binary releases, signing, and package publication are separate
release gates, not consequences of a successful development build.

## Deferred

Basic operation history/export is now part of T12. Comparable historical storage
trends may follow reliable accounting and journal behavior.
AI may later explain structured facts, but cannot authorize actions or bypass
policy. Linux scheduling is undecided; Android is out of the current scope.
No administrator helper, daemon, automatic cleanup schedule, remote execution,
account service, or self-updater is a prerequisite for the initial loop.
Explicit CLI updates, read-only monitoring, and specific system maintenance are
now in the later competitive scope. They do not authorize always-on services,
silent elevation, or vague "speed up the computer" behavior. Broader irreversible
actions need new action-specific gates, not an expansion of M3 by implication.

## How work is accepted

See [architecture](docs/ARCHITECTURE.md), [implementation and ownership](docs/IMPLEMENTATION.md),
and [testing](docs/TESTING.md), plus the [competitive contract](docs/COMPETITIVE.md).
A milestone requires implementation, observable
failure behavior, relevant automated evidence, and review; documentation or a
successful build alone does not satisfy its exit gate.
