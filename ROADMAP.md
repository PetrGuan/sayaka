# Roadmap

This is a development plan, not a list of supported features or promised dates.
Only the initial workspace and CLI help/version are implemented today.

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

M4 is an early parallel workstream, not a port postponed until macOS feature
expansion. Start with the shared model and read-only fixtures while M2/M3 proceed;
its write path depends on the execution contract established in M3. If no Windows
host is available, record that gate as blocked rather than calling mocks a port.

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

Comparable history summaries may follow reliable accounting and journal behavior.
AI may later explain structured facts, but cannot authorize actions or bypass
policy. Linux scheduling is undecided; Android is out of the current scope.
No administrator helper, daemon, automatic cleanup schedule, remote execution,
account service, or self-updater is a prerequisite for the initial loop.

## How work is accepted

See [architecture](docs/ARCHITECTURE.md), [implementation and ownership](docs/IMPLEMENTATION.md),
and [testing](docs/TESTING.md). A milestone requires implementation, observable
failure behavior, relevant automated evidence, and review; documentation or a
successful build alone does not satisfy its exit gate.
