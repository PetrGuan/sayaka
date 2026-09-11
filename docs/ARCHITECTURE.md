# Core architecture

Status: planned contracts. The current engine and bindings crates are scaffolds.
Names below describe responsibilities, not APIs that already exist.

## Dependency direction

```text
CLI / native-client bindings
            |
       versioned DTOs
            |
model -> scan / rules -> plan -> approval -> execute -> journal
                  platform adapters
            |
     OS APIs and filesystem
```

Keep three crates initially. Within `sayaka-engine`, use `model`, `scan`, `rules`,
`plan`, `execute`, `journal`, and `platform` modules when their implementations
arrive. Do not create empty module trees, services, or general plugin frameworks
in advance. Use direct calls and concrete types; introduce narrow effect
interfaces only where deterministic tests or real platform differences need them.

Clients do not own separate rule lists. All supported clients use the same
planning and execution policy. Start embedded in the caller's process, not a
daemon. Async runtimes, database crates, and bindings tools require a concrete
implementation need rather than being workspace defaults.

## Domain contracts

| Concept | Required information and invariant |
| --- | --- |
| Observation | Resource reference, measured facts, timestamp, scope, completeness, platform evidence |
| Finding | Stable reason code, evidence, rule/version where applicable, allowed candidate actions; not authorization |
| Plan | Immutable selected resources/actions, exclusions, costs, preconditions, expiry, engine/rule semantics, schema version |
| Approval | Bound to the exact plan content and a defined caller/session confirmation flow; never a client-supplied boolean |
| Receipt | Per-item result, reason, time, measurement meaning, and actual recovery capability |
| Capability | Available, unsupported, not authorized, temporarily unavailable, or unknown; never one ambiguous boolean |

`ResourceId` is an opaque engine reference, not a displayed path. Internally
retain native paths/strings and platform identity evidence. Lossy text is for
display only and must never be round-tripped into an execution target. Escape
control characters in terminal/log output. Identity evidence does not alone
prove unchanged contents or absence of races.

## Plan and approval

The engine owns the resource registry and validated plan records. Selected IDs
must belong to the active authorized scope. Reject unknown, expired, overlapping,
or incompatible inputs with stable reasons; do not broaden matches to succeed.
Revalidation may only reduce the approved set, never rescan into a larger set.

M1 uses an in-memory registry with an injectable clock and ID source. Before M3,
decide how the CLI retains versioned plans across invocations. If persisted, keep
them in a user-owned application state directory and validate schema, integrity,
scope, expiry, and semantics on load. An arbitrary imported JSON document is not
an executable authorization. A content digest binds content; it does not by
itself authenticate a caller or establish user consent.

The trusted client must show the specific plan and obtain explicit confirmation.
No unattended approve-all flag is part of the initial interface. Approval UX is
not a security boundary against other malicious processes already running with
the user's privileges. If cross-process privilege boundaries are later added,
caller authentication and separate enforcement require a new design review.
AI input can propose selections but cannot create a valid approval.

## Effect boundaries

Isolate filesystem probes, bounded enumeration, capability/owner-state queries,
restricted mutation operations, journal persistence, clocks, and cancellation.
Use a fake implementation to force deterministic failures and a real adapter to
validate actual platform behavior; neither replaces the other.

The mutation adapter accepts a validated action and retained resource evidence,
not a general `delete(path)` or `run(command)` API. Its contract must describe
object/ancestor identity binding, links, volume boundaries, and the actual
guarantees of each OS operation. Check-then-use pathname sequences cannot be
advertised as race-free. If the required guarantee is unavailable, report an
unsupported action and leave the object untouched.

No permanent-delete fallback for trash errors, permission escalation on failure,
shell interpolation, or implicit user-data cleanup. External tools are deferred;
when added, require a known executable, structured arguments, constrained
environment, affected-scope evidence, and observable timeout/cancellation.

## Task and result semantics

Scanning has bounded concurrency, queued work, open handles, and output buffering.
Every progress event belongs to a task/generation. Cancellation stops scheduling
new work; adapters document which in-flight OS calls can be interrupted.
An uninterruptible call is not a reason to silently detach continued mutations.

Per-item journal lifecycle:

```text
Planned -> Started -> Succeeded | Skipped | Failed | Unknown
```

Unstarted cancelled items become `Skipped` with a cancellation reason. Completed
items retain their outcomes. An ambiguous effect is `Unknown`, not fabricated
failure or success. An interrupted `Started` entry is reconciled on restart,
without automatic destructive replay.

Durably record intent before effects. If that write fails, do not act. If outcome
recording fails after an effect, stop further mutations and surface the ambiguity.
Choose journal storage in M3 (SQLite is a candidate, not a filesystem transaction).
Specify schema evolution, retention, local export, and recovery-information
handling before shipping persistent records.

## Accounting and recovery

Keep logical bytes, allocated bytes when supported, estimated reclaimable bytes,
handled bytes, and measured free-space delta separate. Unknown is not zero.
Deduplicate hard links and overlapping selections at a documented scope.
Compressed/sparse/shared storage prevents naive sums from promising reclaimed
space. A moved-to-trash file is still consuming storage.

Distinguish recoverable, rebuildable, and irreversible actions. Recovery depends
on current platform capabilities, retained evidence, and destination state.
Never overwrite an occupied restore destination or promise universal rollback.

## CLI and bindings

M2 introduces a versioned JSON result envelope with task ID, status, completeness,
structured errors, and measurements. Emit diagnostics to stderr and machine
results to stdout. The implementation issue must fix command names, output shape,
and exit-code mapping before adding commands; `scan`, `plan`, `execute`, and
`receipt` are candidate names only.

For bindings, expose versioned DTOs, stable error codes, opaque task/resource IDs,
and explicit allocation, release, cancellation, and callback rules. No panic
may cross an ABI boundary. Keep native path handling inside the engine and do
not force Rust internals into lossy FFI-friendly strings.

## Full CLI capability expansion

The foundation is not the final feature boundary. T7-T12 add interactive
navigation, full cleanup/project/installer workflows, application removal,
specific system maintenance, live status, and the CLI distribution lifecycle.
See [COMPETITIVE.md](COMPETITIVE.md) for the required user outcomes.

Keep interactive state, key handling, rendering, and terminal restoration in
`sayaka-cli`; the engine remains usable without a terminal. Selection and preview
still feed the shared plan/approval path. UI responsiveness must not depend on
running enumeration or maintenance synchronously in the rendering loop.

Introduce bounded read-only collectors in an engine module when T11 needs them.
Retain sample timestamps, source/capability states and stale/unknown distinctions.
Separate fast metrics from expensive probes; share snapshots where safe and
measure overhead at the configured interval. Watch mode lives only as long as
the explicitly started command; it does not install a daemon. A diagnostic
observation or alert is never authorization to terminate a process or "optimize."

T8-T10 may require new directory, irreversible, external-tool or privileged
actions. Each requires an action-specific effect/identity/recovery contract,
fresh approval, and native evidence before being supported. M3's ordinary-file
trash proof is not sufficient for those actions. Preserve protected data and
refuse unsupported semantics rather than implement arbitrary command execution.

T12's updater, self-removal and authentication convenience are separate
side-effect boundaries. Require verified artifact identity/compatibility,
bounded owned installation paths, explicit user intent, and failure/recovery
behavior. No silent global authentication changes, background auto-update, or
credential storage follows from offering convenient CLI commands.
