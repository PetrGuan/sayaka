# Mole CLI comparison and acceptance contract

Status: development objective and measurement protocol, not a superiority claim.
Sayaka has an M1 in-memory core, M2 macOS read-only scanning/CLI, and an initial
M3 explicit-file Trash/receipt workflow under the revised revalidation contract.
Initial M7 browser, T11 status, and T12 local lifecycle slices have local fixture
regression baselines only (`benchmarks/m7-v1.json`, `benchmarks/t11-v1.json`,
`scripts/check_local_install.py`); these are not Mole parity proof.
Native Trash/recovery acceptance remains a separate gate.
No comparative runtime, usability, or full installation-footprint benchmark
against Mole has been executed.

## Objective and scope

Cover all major Mole CLI capabilities, then demonstrate better usability, faster
execution, and smaller delivery/installation footprint without weakening safety,
correctness, or scope. Deliver incrementally; an early subset must not be marketed
as comprehensive parity. SayakaCleaner and Mole's native Mac application are
outside this comparison and need a separate product roadmap.

Primary apples-to-apples comparisons run on macOS with matching architecture,
permissions, filesystem, task, and selected resources. Windows remains an early
Sayaka platform workstream, not evidence of a macOS performance win. Mole also
documents an experimental Windows branch; this is not a stable benchmark target.

## Frozen reference

Initial stable reference, observed 2026-09-11:

- Mole release **V1.53.0**, published 2026-08-30.
- Release source commit **1b9023b5f151c2d963bbcb9cb658f4824137b8aa**.
- [Release and artifacts](https://github.com/tw93/Mole/releases/tag/V1.53.0).
- [Pinned command documentation](https://github.com/tw93/Mole/blob/1b9023b5f151c2d963bbcb9cb658f4824137b8aa/README.md).
- [Pinned build definition](https://github.com/tw93/Mole/blob/1b9023b5f151c2d963bbcb9cb658f4824137b8aa/Makefile).

The previously inspected development commit
`015c1e45711eaa42972aeda3a78f1a664a60f882` is not the release commit. Do not mix
development scripts with release binaries and call that a stable-release result.
Freeze source, artifact SHA-256, installer path, tool versions, and fixture
manifest in each benchmark record. Update this baseline explicitly when the
comparison version changes; do not silently move the goalposts.

C0 source/ledger/protocol manifests are now pinned in:

- `benchmarks/c0-mole-v1.53.0-source.json`
- `benchmarks/c0-mole-v1.53.0-ledger.json` (clean section flow and all 21 optimize catalog actions are explicitly enumerated)
- `benchmarks/c0-install-v1.json`
- `benchmarks/c0-fixtures-v1.json` (includes sparse, denied-subtree, overlapping-root, controlled-churn, history/lifecycle, and owned-prefix fixtures)
- `benchmarks/c0-statistics-v1.json` (frozen scenario matrix, fixture/ledger/source hashes, equal-work checks, candidate-not-runnable blocked adapters, and required failure/skip retention schema)
- `benchmarks/results/c0-blocked-results-v1.json` (machine-readable blocked/not-measured result record for current preregistration state)

Protocol-only validation is explicitly protocol-only. It verifies preregistered
shape/locks and blocked-state disclosure, but it is never a supported result,
competitive speed claim, or full C1 parity claim.

GitHub release metadata reports these artifact sizes:

| Architecture | Analyze artifact bytes | Status artifact bytes | Sum of the two | Binary archive bytes |
| --- | --- | --- | --- | --- |
| macOS arm64 | 3,620,258 | 4,065,586 | 7,685,844 | 3,010,562 |
| macOS x86_64 | 3,747,504 | 4,139,040 | 7,886,544 | 3,197,762 |

These are published asset sizes, not a measured full installation. Mole also
uses scripts and support files. Do not add an archive to its extracted contents,
equate the two-Go-artifact sum with the whole tool, or compare these figures to
Sayaka's current feature-subset executable. Complete footprint is still unmeasured.
Pinned assets can be downloaded and verified by exact payload SHA-256 and byte
length without executing them; this provenance step is not installation, runtime,
or competitive execution evidence. No competitor installer or maintenance command
was executed for this document.

## Capability ledger

This is a command-family inventory, not yet an exhaustive rule/subcommand audit.
C0 must expand each row into version-pinned task cases, supported platforms,
eligible targets, expected effects, exclusions, and evidence before parity is
accepted. Read-only scan/JSON, explicit-file previews/confirmation and local
receipt export implement only parts of the ledger; interactive exploration
and the other complete task families remain unimplemented.

| Mole capability | Required Sayaka user outcome | Delivery |
| --- | --- | --- |
| Menu and `analyze` / `analyse` | Discover commands; responsive disk explorer, filtering/sorting, keyboard navigation, multiselect, system reveal/preview, scope selection, confirmed actions | T2 + T3 + T7 |
| `clean` | Evidence-backed caches/logs/temp/removed-app leftovers and explicitly selected trash cleanup, protected targets and preview; itemized results and real recovery limits | T5 + T8 |
| `uninstall` | Installed-app discovery, related-data selection, multi-copy/shared-data protection, supported removal flows | T9 |
| `purge` | Project-aware rebuildable artifacts, configurable roots, activity/ownership checks, explicit selection and costs | T8 |
| `installer` | Identify supported installer formats/sources, provenance and size, preview and selected removal without cloud hydration | T8 |
| `optimize` | Bounded diagnostics and specific OS/service/cache/database maintenance with preconditions, exclusions, cancellation and outcome reporting | T10 |
| `status` | Read-only CPU/memory/disk/network/process/power/thermal/GPU information where available, bounded sampling, freshness/unknown states, JSON/NDJSON, alerts | T11 |
| `history` and JSON export | Query real operation records, per-item failures and recovery information, stable machine-readable output | T3 + T12 |
| Dry run, whitelist, configured roots | Persisted exclusions, exact-plan preview, explicit scope, reasons for skipped/denied actions | T1 + T3 + T7 + T8 |
| Help, version, aliases, completion | Discoverable commands/options and shell completion; document equivalent names rather than require a `mo` alias | M0 + T12 |
| Install, update, nightly selection, remove | User-owned installation where supported, explicit release channel, verified update/compatibility and safe self-removal | T12 |
| Touch ID convenience | Explicit, supported authentication setup or an effective OS-native equivalent; no hidden privilege escalation | T10 + T12 |
| Raycast/Alfred quick launchers | Documented terminal launch integration using supported terminal choices, with uninstallable owned artifacts | T12 |

Feature parity concerns user outcomes, not copying command names or implementing
an arbitrary count of rules. Nevertheless, omitted functionality is a gap.
A refusal can be the correct safety result without satisfying the user's task;
record both. Do not mark a major capability complete merely because it reports
"unsupported." A safety-motivated scope change requires an explicit decision and
a qualified comparison claim.

Potentially irreversible maintenance, directory actions, and privileged
operations require new action-specific design gates after M3. They are not
authorized by the initial ordinary-file trash contract. "Optimize" must name the
actual operation and evidence, not promise generic speedups or RAM boosting.
Never make permanent deletion a fallback after a failed trash operation.

## C0: build the benchmark before claiming a win

Use independent, synthetic, versioned fixtures with recorded expected outcomes:
small/deep/wide trees, many small files, large and sparse files, hard links,
overlapping roots, denied subtrees, links/reparse points, and controlled churn.
Add supported synthetic project/app/installer cases as each capability arrives.
Do not use personal home directories, installed production apps, or real caches.

Provide the same logical task and eligible set to both tools. Compare equivalent
output/accounting definitions against ground truth, not one tool's numbers as
the oracle. Separate semantic differences, correctly refused cases, genuine
errors, and unsupported cases from timed successes.

Benchmark each frozen feature only after verifying its result. A skipped scan,
stale cache, shallower traversal, weaker preconditions, or fewer handled targets
is not a faster result. Restore/recreate fixtures between mutation runs; run
system-wide competitor commands only in a disposable native environment. A
`--dry-run` label is not proof that no state or cache will be changed.

## Faster: acceptance rather than selected screenshots

Before timing, register the scenario matrix, metrics, sample counts, ordering,
outlier policy, and acceptance thresholds. Keep raw sanitized samples and failed
runs. Use alternating/randomized tool order, matching power/thermal conditions,
and confidence intervals to avoid selecting a favorable run.

Measure separately:

- Process/interactive startup and time to first useful result.
- Complete scan/analysis and clean/plan discovery.
- Equivalent approved effects including required journal/safety work.
- Cancellation response, including in-flight system-call limitations.
- Status startup and steady-state CPU, memory, sampling latency and freshness.
- Peak memory, open handles, and worker/queue limits.

Report fresh-process and warm-process behavior separately from OS-cache state.
An application cache miss is not an OS-cold disk. Do not flush global caches on a
developer workstation to manufacture cold runs; use a documented disposable-host
protocol or label OS-cold behavior unmeasured. Warm comparisons must satisfy the
same result freshness requirement.

Minimum gate: each registered primary speed scenario has a lower median with a
confidence interval supporting a real improvement, and no statistically supported
tail-latency or peak-memory regression at equivalent work. Ties/inconclusive
results do not establish "faster." Record p95 even when the median improves.
For long-running monitoring, compare steady-state resource use at the same sample
frequency and metric coverage, not just startup speed.

An initial stretch target is a 20% reduction in primary median times, not a
measured result or a reason to change semantics. C0 must fix the estimator,
confidence level, repetitions, and material-regression tolerance before actual
competitive runs. Publish per-scenario results; an aggregate cannot hide a loss.

## Smaller: complete and equivalent distributions

For each architecture, measure:

1. Total bytes downloaded for a clean installation, without caches.
2. Installed regular-file bytes and allocated filesystem bytes, deduplicating
   hard links and accounting for symlinks consistently.
3. Required non-OS runtimes/libraries/helpers and full-feature support resources.
4. Optional extras and accumulated caches/journals as separate, named categories.

Compare the same installation method/class. Record direct installation and
package-manager installation separately, including incremental dependencies.
Exclude the same preinstalled OS frameworks on both sides; report environment
assumptions. Do not charge one side for an entire shared package manager while
pretending the other's external dependencies are free.

Use production release artifacts and a full-capability Sayaka build. Keep debug
symbols/source out of runtime totals only if treated equivalently and report
separately shipped symbols. Report signed/unsigned state and compression method.
Account for launchers, completion, rule data, and helpers in equivalent profiles.
A tiny minimal build is a separate product profile, not the full-parity result.

Minimum gate: Sayaka's full-profile download bytes and installed regular-file
bytes are both strictly lower; report allocated bytes and dependency breakdown
alongside them. A reduction in only one does not satisfy the whole size objective.
An initial stretch target is 20% below the measured full-profile baseline.
Neither artifact metadata above nor a stripped scaffold establishes this gate.

Optimize based on evidence: reuse enumeration/metadata, avoid duplicate work and
unnecessary subprocesses, keep dependency features narrow, and evaluate release
LTO/codegen/size options with runtime measurements. Do not switch panic strategy
or use executable packing just to win size without reviewing FFI failure,
startup, signing, diagnostics, and platform compatibility consequences.

## Easier to use: task outcomes

Define representative tasks from every major ledger family. Include first-use
discovery, locating a large item, reviewing/excluding an item, cancelling a task,
understanding a partial failure, finding a receipt, and recovering when supported.
Use the same task wording and comparable training. Counterbalance tool order,
record sample size and prior experience, and collect results with participant
consent; do not invent participants or fabricate user-study results.

Measure task success, task time, navigation/typing burden, mistaken approvals,
and whether participants correctly understand effects, failures, and recovery.
Lower keystroke count never justifies removing meaningful confirmation. Include
small terminals, keyboard-only use, plain output, readable contrast, and terminal
restoration after errors. Native GUI comparisons are excluded.

Minimum gate: no lower task success or safety comprehension on registered tasks,
no additional unsafe approvals, and an evidenced improvement in task completion
time or interaction burden for each major task family. Missing/ambiguous evidence
keeps the usability claim open. Scripted CLI checks prove mechanics, not human
usability; independent user acceptance still matters.

## Ownership and completion

C0's Architect freezes the comparator, case ledger and measurement protocol;
Implementer creates/runs isolated harnesses and records evidence; Reviewer checks
equivalence, completeness, statistics, and omitted failures; Maintainer resolves
scope, native-host access, and release claims. No extra external host purchases
or test-participant recruitment is implied by this plan.

The comprehensive claim requires every major family covered (or an explicitly
qualified scope), and the usability, speed and full-size gates all satisfied.
Keep pending, partial, unsupported, failed and verified states visible. A release
that only clears M1-M6 is a foundation release, not "better than Mole."

Benchmark behavior independently. Mole is GPL-3.0; Sayaka is MPL-2.0. Public API
facts and comparative results do not authorize copying/translating Mole code,
rules, protected explanatory text, or artwork into Sayaka. Preserve provenance
and review license compatibility for any material actually incorporated.
