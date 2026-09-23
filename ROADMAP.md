# Roadmap

Current status reviewed on 2026-09-16: Sayaka is a source-built developer preview
with usable narrow CLI workflows, not a complete maintenance suite or stable
binary distribution. This document separates delivered slices from remaining
milestone gates; it is not a schedule or a claim that all listed goals are done.
Use the [README capability/platform summary](README.md#current-capabilities) as
the entry point and the linked technical contracts for precise restrictions.

The model, macOS scanner, Windows x64 native read-only scan, macOS ordinary-file
Trash/journal, terminal browser/menu, two built-in rules, installer-file approval,
application previews, status/process top and local CLI lifecycle are present.
Read-only native scan, directory queries and installer selection checks are present; directory effects, uninstall
and system-maintenance actions are not. Local controlled native evidence exists, including installer
single/batch round trips; it neither closes the former atomic-binding proposal
nor authorizes new real-Trash runs.

## Product objective

Cover all major Mole CLI capabilities, then demonstrate better usability, faster
execution, and a smaller complete distribution. This is a staged engineering
objective, not a claim that Sayaka already matches Mole. Compare CLI to CLI;
native graphical applications have a separate roadmap.
The shared engine is also intended for the macOS and Windows SayakaCleaner
applications. Prioritize reusable capabilities and user workflows across those
clients and the CLI; standalone CLI distribution is not the immediate prerequisite
for continued engine development. Native client UI remains outside this repository.
The [competitive contract](docs/COMPETITIVE.md) fixes the reference version,
capability ledger, fair measurement rules, and acceptance gates.

## Milestone status and remaining gates

"Implemented foundation" means the bounded contract is present; it is not a
blanket production/platform certification. "Partial" means useful slices exist
but the named milestone's wider outcome is incomplete.

| Stage | Current state | Delivered scope | Remaining gate / dependency |
| --- | --- | --- | --- |
| M0 | Implemented foundation | Workspace, MPL-2.0, source repository and CLI entry | Binary/package publication is separate from source availability |
| M1 | Implemented foundation | Deterministic observations, plans, exact approval and read-only preflight | Remains model-only; never substitutes for native authority |
| M2 | Implemented foundation | Bounded macOS scanning, JSON/progress, directory accounting and diagnostics | Broader OS/hardware/volume evidence; cloud/network/removable scope is not inferred |
| M3 | Implemented narrow workflow | macOS ordinary-file revalidated Trash, durable intent/outcomes, receipts | Residual pathname race; broader environments and new action kinds need separate contracts |
| M4 | Partial; x64 read-only slice accepted | Native Windows 11 x64 fixed-NTFS scan/CLI evidence | ARM64 linked/native acceptance, Windows writes and other native workflows remain separate |
| M5 | Partial | CPython source-backed `.pyc` and OpenJDK `javac` source-backed `.class` rules | Broader useful rules/non-targets; native inspection currently macOS, not Windows rule parity |
| M6 | Partial, read-only ABI | Scan/directory/diagnostic queries, macOS installer discovery/selection checks and local C/Swift hosts | Native Windows linking/runtime, App integration, broader APIs and distribution |
| C0 | Partial evidence | Pinned Mole ledger, constrained direct-analyzer comparison, corrected collector and scan diagnostics | Full installed footprint, wider equivalent workloads, cancellation and real-user usability evidence |
| M7 / T7 | Partial | macOS terminal browser/menu, filters/navigation, file selection and shared approval entries | Full task-family/UX acceptance and broader platform support |
| M8 / T8 | Partial | Two-rule `clean`, persisted clean exclusions, installer-file selection/approval, project-artifact purge execution and developer-cache location preview | Broad clean/purge catalog; non-project cache execution and broader directory effects need separate contracts |
| M9 / T9 | Partial, read-only | macOS `apps` inventory and `apps-related` association preview | Running/shared/multi-copy ownership, supported uninstall flows and native effects |
| M10 / T10 | Not implemented | No system-maintenance action or privilege helper | Specific operations, authorization/recovery contracts and native evidence |
| M11 / T11 | Partial | macOS native status, JSON/watch panel, freshness/alerts and opt-in process top | Numeric temperature/GPU, Windows sampler and broader metric/host coverage |
| M12 / T12 | Partial, local lifecycle | History, completions, dedicated-prefix install/update/recover/remove | Public binary distribution, publisher authentication, online channels and Windows installation |
| C1 | Not met | Goals and evidence rules defined | All major capabilities plus usability/speed/full-size evidence; current slices are not superiority proof |

Canonical evidence: [scanning](docs/SCANNING.md), [Windows](docs/WINDOWS.md),
[execution](docs/EXECUTION.md), [installer native acceptance](docs/INSTALLER_PREVIEW.md#recorded-native-acceptance),
[application previews](docs/APPLICATIONS.md), [status/process top](docs/STATUS.md),
[local lifecycle](docs/LOCAL_LIFECYCLE.md), and [C0 limits](docs/COMPETITIVE.md).

M4 started early and already has real x64 read-only evidence; it is not an
unstarted port. Keep its remaining work parallel to macOS expansion. A macOS
write contract or cross-compilation result cannot certify Windows native effects.
Unavailable native hosts/toolchains must remain blocked/unverified, not mocked
into a platform pass.

M1-M6 remain foundation work, not full Mole parity. T6's native bindings are not
a prerequisite for CLI competitive acceptance; their integration work can proceed
separately. T12 owns the full CLI distribution lifecycle and uses the source/
compatibility rules established by the core. Do not serialize T11 behind every
mutating feature, or defer C0 measurements until the end.

## Near-term priorities

1. **Reusable engine capabilities and workflows (T5/T8).** Strengthen useful
   discovery, selection, planning, cancellation and truthful result flows without
   making business rules depend on a terminal. CLI and future SayakaCleaner
   macOS/Windows clients must share policy and operation state, not duplicate
   cleanup decisions. Expand one evidence-backed cleanup task at a time.
2. **Native-client integration readiness (T6).** Establish a small read-only
   consumer path for scanning, progress, cancellation and result ownership before
   exposing effects. The [first C ABI](docs/BINDINGS.md) now covers that read-only
   path plus task-bound root/node/children queries, bounded pagination and shared
   directory summaries/sorting, with local C/Swift host evidence and Windows x64
   type checks. Installer discovery/candidate queries and explicit read-only
   selection checks now reuse the macOS engine path without exposing authority.
   These App-reusable workflows take priority over standalone
   CLI distribution or further scan-duration tuning. Actual
   native App integration and Windows runtime remain separate gates; expand
   against real consumers rather than building a broad SDK in advance.
3. **Directory effect decision gate (T8).** The
   [ModelOnly foundation](docs/DIRECTORY_ACTIONS.md) is implemented. Choose and
   explicitly approve exact-member-set versus whole-container semantics and
   native/recovery limits before adding any directory effect. Read-only blocker
   checks and a stable root inode are not permission.
   Project cleanup still needs concrete ownership/non-target rules; names such
   as `target/build` never authorize removal. App uninstall and broad system
   maintenance retain their own gates.
4. **Distribution readiness when needed (T12).** Local packaging, license notices,
   checksums, installation instructions and publisher authentication remain
   necessary delivery work, but do not displace shared-engine functionality.
   No GitHub Release is currently published and Cargo publication is disabled.

Continue bounded C0/platform evidence alongside those tasks. Do not spend
another performance-only slice trying to claim a win by reducing information,
checks or workload. Native bindings are needed for in-process app integration,
not a prerequisite for using or independently delivering the CLI.

## Milestone boundaries

### M1: make decisions testable

Define observations, findings, immutable plans, approval, execution receipts,
stable reason codes, and explicit capability states. Separate pure decisions from
platform effects. Introduce controlled fixtures and failure injection alongside
the first real logic; a passing suite with zero tests is not completion.

Implemented in `sayaka-engine`: injected clock/IDs/probes, protected/excluded
selection, immutable plans, session-bound approval, one-shot read-only preflight
and pure receipt transitions. See the [M1 contract](docs/ARCHITECTURE.md#implemented-m1-contract).
M1 separates deterministic planning from platform adapters; current models and
records also use serialization support. M2 adds targeted native scanner
dependencies, while fixture tooling remains dev-only.

### M2: understand a selected scope

Scan only explicitly selected roots. Do not follow links/reparse points, cross
volumes, traverse network/removable volumes, or hydrate cloud placeholders by
default. Do not treat denied access as an empty directory. Track logical bytes,
allocated bytes when known, hard-link deduplication, completeness, and task IDs.
The scanner itself performs no cleaning; separately implemented commands own
all approval and effect behavior.

The [M2 scanning contract](docs/SCANNING.md) specifies actual native restrictions,
wire semantics, fixtures and resource/performance gates. The separate macOS
and Windows FFI crates preserve the engine's unsafe-free boundary. Windows x64
has its own recorded fixed-NTFS native evidence; ARM64 runtime and cloud-provider/
external/network environments are not certified by that or the macOS slice.

### M3: a narrow, honest write path

First prove which platform operations can satisfy identity and scope constraints.
The initial candidate is moving explicitly selected ordinary files to the system
trash on a supported local volume, with ordinary user permissions. Recursive
directory mutation, permanent deletion, broad cache clearing, and uninstallers
are excluded from this milestone.

The original atomic source-and-ancestor binding proposal remains unsupported.
The revised, explicitly approved `revalidated_trash_v1` contract requires exact
approval and immediate native revalidation, while disclosing that replacement
after the final check can still move a different object. This is a substantive
scope decision, not proof that path races were eliminated. See
[EXECUTION.md](docs/EXECUTION.md) for the implementation and remaining native gates.

Persist execution intent before effects, record per-item outcomes afterward,
and preserve `Unknown` across ambiguous crashes. Never automatically replay
unresolved actions. A trash move does not mean disk space was freed or that
restoration is guaranteed.

The installer-file frontend now has scoped local single/batch native CLI
Trash/receipt/no-overwrite-restore evidence. It reuses the ordinary-file contract;
that does not approve directory actions, arbitrary restoration or package trust.

### M4: prove the Windows differences

Exercise native path representation, volume/file identity, sharing violations,
reparse points, cancellation, supported trash behavior, and partial results.
macOS mocks and cross-compilation are supporting evidence, not the exit gate.
Keep unsupported behavior explicitly unavailable.

The Windows 11 x64 read-only closeout is already recorded in
[WINDOWS.md](docs/WINDOWS.md). ARM64 has compilation checks but no linked/native
acceptance, and Windows Trash/status/installation remain unavailable.

### M5: expand only from evidence

Select a small rule set after measuring actual value and confirming supported
software versions. Every rule must identify what it will not touch. Built-in Rust
rules ship with the engine; no executable rule DSL, shell snippets, or plugin
marketplace. Application discovery can precede uninstall support, but lack of an
observed owner is never proof that data is abandoned.

The current catalog contains two implemented rule families: CPython source-backed
cache files and same-directory `javac` class files. `clean` wraps those rules
with explicit selection and persisted exclusions; it is not a general purge
engine or permission to remove whole build directories.
The purge preview catalog also includes a `developer_caches` profile for
documented rebuildable cache/download-store locations under explicit user-granted
roots: Xcode DerivedData/cache/CoreSimulator cache, npm/pnpm/Yarn/pip/Cargo/
Gradle caches and Homebrew downloads. It excludes Xcode Archives and other user
products. This is App-reusable discovery and unsupported-operation reporting,
not approved execution for non-project caches.

### M6: integrate without duplicating policy

Keep native graphical clients outside this repository. Evaluate Swift bindings
and a small C ABI for Windows consumers against the proven engine contracts.
Choose binding dependencies only when implementing those consumers. Publish the
actual tested OS/architecture matrix, not assumed support. Source publication is
already enabled; binary releases, signing, and package publication are separate
release gates, not consequences of a successful development build.
The current binding slice uses a narrow C ABI with caller-owned result buffers,
opaque non-reused handles and nonblocking release retries. It exports scan only;
no foreign callback or cleanup/approval API has been introduced.

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
