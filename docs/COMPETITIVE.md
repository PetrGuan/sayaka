# Mole CLI comparison and acceptance contract

Status: development objective and measurement protocol, not a superiority claim.
Sayaka has the model/scan foundations, Windows x64 native read-only evidence,
macOS ordinary-file Trash/receipts, terminal workflows, two built-in rules,
installer selection, application previews, status/process top and local CLI
lifecycle. See the [current milestone/gap table](../ROADMAP.md#milestone-status-and-remaining-gates).
These are bounded slices, not complete maintenance capability coverage.
M7, T11 and T12 have local regression budgets/checks
(`benchmarks/m7-v1.json`, `benchmarks/t11-v1.json`, `benchmarks/t11-top-v1.json`,
`scripts/check_local_install.py`), and installer CLI has separate controlled
native round-trip evidence. None establishes Mole parity or general recovery.
One guarded direct-analyzer comparison against Mole has been executed on a
flat regular-file fixture (see batch 3 below). Installed-CLI, human usability,
and full installation-footprint comparisons remain unmeasured.

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
- `benchmarks/c0-batch2-manifest-v1.json` (Phase A guarded-host preregistration for one flat regular-file JSON scenario with frozen 31-pair AB/BA schedule)
- `benchmarks/c0-batch2-results-schema-v1.json` (strict shareable Phase A result schema with unknown-field rejection)
- `benchmarks/results/c0-batch2-phase-a-ready-v1.json` (current blocked guard record; the filename does not imply readiness)
- `benchmarks/results/c0-batch2-phase-b-results-v1.json` (Phase B pipeline artifact produced without execution; `--execute` remains required and parent authorization is still required before any Mole execution)
- `benchmarks/c0-sayaka-capability-current-v2.json` (machine-readable current Sayaka feature-subset capability ledger for batch-2 planning)
- `benchmarks/c0-batch3-direct-analyzer-v1.json` (independent batch-3 preregistration for direct verified Mole `analyze` artifact vs owned Sayaka `scan` on the same frozen flat fixture and AB/BA order)
- `benchmarks/results/c0-batch3-direct-analyzer-results-v1.json` (completed direct-artifact comparison: correctness checks, warmups, 31 AB/BA pairs, and no-effects fingerprints)
- `benchmarks/c0-batch3-direct-analyzer-v2.json` (corrected preregistration using the post-validation last-non-whitespace collector method; keeps the same frozen 31-pair schedule and fixture contract)
- `benchmarks/results/c0-batch3-direct-analyzer-results-v2.json` (completed corrected-method run using the original pinned binaries)
- `benchmarks/c0-sayaka-scan-profile-diagnostic-v1.json` and its result (separate diagnostic-build phase/overhead experiment)

### Batch 3: guarded direct-artifact observation

The table immediately below is historical v1, using repeated prefix parsing.

On macOS arm64, the pinned Mole analyzer artifact and the unchanged Sayaka
product build both returned the exact 1,024-file, 4,194,304-byte fixture result.
Both correctness checks, both warmups, and all 62 measured invocations passed.
Fixture, binary, denied-control, and empty-PATH fingerprints stayed unchanged;
expected cache effects were confined to each invocation's owned HOME/TMP.

| Tool | Median completion | p95 completion | Maximum observed per-process peak RSS |
| --- | ---: | ---: | ---: |
| Mole direct analyzer | 31.00 ms | 44.73 ms | 9.61 MiB |
| Sayaka scan | 51.98 ms | 66.08 ms | 10.42 MiB |

These are local guarded **direct-artifact** observations, not installed CLI or
full-product superiority evidence. PATH was an owned empty directory, so Mole's
optional `mdfind`/`du` lookups were unavailable; the flat fixture's exact common
file statistics were nevertheless verified. Sayaka emitted additional metadata
(about 601 KB JSON versus 262 KB for Mole). The result must not be generalized
to normal Mole configuration, larger/nested trees, other platforms, or
installation size. Cancellation latency remains unmeasured in this scenario.
The historical v1 rows were collected with the legacy prefix-decode timing
method and remain immutable. v2 keeps them unchanged and records a separate
collector/method binding for corrected reruns.

### Corrected v2 and separate Sayaka phase diagnostics

V2 uses the same original Mole/Sayaka artifact hashes and the same 31-pair
fixture/order, but records the last non-whitespace stdout receipt in the capture
loop and validates JSON once afterward. No growing-prefix JSON decoding is done
for this method. All measured rows and immutable-input checks passed.

| Tool | Median completion | p95 completion | Maximum observed peak RSS |
| --- | ---: | ---: | ---: |
| Mole direct analyzer | 32.37 ms | 43.17 ms | 9.75 MiB |
| Original Sayaka scan artifact | 50.00 ms | 65.84 ms | 10.44 MiB |

The v1/v2 runs happened at different times: differences between their medians
must not be treated as an exact causal estimate of removed observer overhead.
No superiority claim follows from this limited common-result projection.

A separate diagnostic build was paired with its own profiling flag off/on
(15 pairs on the 1024-file fixture, 7 on an empty fixture). It was not substituted
for the original binary in the v2 comparison.

| Diagnostic phase, median | 1024 files | Empty directory |
| --- | ---: | ---: |
| Run entry to scan dispatch (not OS loader) | 0.153 ms | 0.147 ms |
| Scan setup | 0.036 ms | 0.034 ms |
| Scan call, including native scope admission | 13.74 ms | 8.63 ms |
| JSON encoding, write and flush combined | 4.55 ms | 0.037 ms |

The median paired profiling-on overhead on the full fixture was 0.50 ms, with
a 95% paired bootstrap interval of [-2.36, 9.58] ms. That is not evidence of
zero overhead. Seven guarded version-only runs had median completion 21.17 ms.
The median per-sample wall-time residual outside the four reported phases was
31.46 ms on the full fixture; it mixes launch, loader, sandbox, observation and
finalization costs and must not be labeled entirely as application startup.
These observations prioritize fixed admission/launch costs for further study;
they do not justify removing safety checks or JSON information.

Further admission/launch diagnostics use
`scripts/check_sayaka_admission_profile.py`. The runner reuses the direct-artifact
guard, owned fixtures, exact output validation, and immutable input checks.
The completed v2 baseline/new-off/new-on triples separate code-change overhead
from opt-in instrumentation; empty and three-root controls distinguish first
from subsequent native volume queries. Version-only pairs estimate added parent
timestamp overhead. Parent spawn return, stdout receipt, pipe closure,
and reaping are observations, not OS-loader or exact child-exit timestamps.
The spawn interval overlaps child execution and must not be added to the
launch-to-dispatch interval. This is not a new Mole comparison or permission to
cache volume decisions, drop safety checks, or overwrite prior evidence.
The first admission attempt is retained as failed: Python 3.9's
`monotonic_ns()` rebases the clock per process despite reporting
`mach_absolute_time()` as its implementation. Its cross-process timestamps were
rejected, not reported as valid intervals. Admission protocol v2 instead uses
Darwin `CLOCK_UPTIME_RAW` for all diagnostic parent timestamps, matching the
child's mach-absolute nanoseconds; ordinary collector runs retain their previous
Python-monotonic behavior.

### Admission attribution and exit-observer correction

The independent admission v2 manifest/result are
`benchmarks/c0-sayaka-admission-profile-v2.json` and
`benchmarks/results/c0-sayaka-admission-profile-v2.json`. All 135 scan samples
(15 randomized baseline/off/on triples on each of flat/empty/three-root fixtures)
and 30 version-control samples passed, with unchanged immutable inputs.

| v2 profiled median | Flat 1024 files | Empty root |
| --- | ---: | ---: |
| Caller I/O-policy entry | 0.0032 ms | 0.0033 ms |
| Root no-follow open | 0.0569 ms | 0.0492 ms |
| Native volume validation | 9.1562 ms | 8.6541 ms |
| First local-volume resource-property read (nested) | 9.1320 ms | 8.6282 ms |
| Parent start to scan dispatch | 27.5461 ms | 27.9430 ms |

In the three-root case, independently checked volume queries took
8.5484 / 0.0217 / 0.0145 ms in admission order. This localizes the dominant
fixed admission cost to the first native resource query, consistent with
initialization/cache effects; it does not isolate CoreFoundation's internal
work or justify skipping/caching any safety decision. The other native flags
remain checked. Parent-to-dispatch still includes sandbox/env/loader/scheduling
costs, not just Sayaka startup; Popen itself took about 3 ms and overlaps that
interval. CLI dispatch (~0.15 ms) and thread policy are not the main targets.
V2 full-fixture code-change overhead was +2.4691 ms paired median (95% CI
[-6.6285, 7.1701]); profiling on-minus-off was -0.0005 ms
([-1.8655, 2.1339]). These noisy estimates do not establish zero overhead.

V2 also exposed occasional 5 ms post-EOF process-exit polling. The selected
optimization is **measurement-side only**: optional
`post_eof_kqueue_exit_v1` observes the owned child's NOTE_EXIT event. Pipe EOF
alone never authorizes reaping as if the process had exited. Output caps,
inherited-pipe deadlines, process-group termination and per-child `wait4` RSS
collection remain. The original `post_eof_poll_5ms_v1` stays the default for old
callers; the new method is explicitly bound in the v3 diagnostic manifest.

V3 uses the **same** diagnostic binary for baseline/off/on (polling with
profiling off / kqueue with profiling off / kqueue with profiling on), not a
faster product build. Freeze a new manifest, then execute it:

```sh
python3 scripts/check_sayaka_admission_profile.py --freeze \
  --baseline-binary target/release/sayaka --manifest benchmarks/admission-new.json
python3 scripts/check_sayaka_admission_profile.py --execute \
  --baseline-binary target/release/sayaka --manifest benchmarks/admission-new.json \
  --output benchmarks/results/admission-new.json
```

Neither mode overwrites existing evidence. Recorded v3 data are in
`benchmarks/c0-sayaka-admission-profile-v3.json` and the corresponding
`benchmarks/results/c0-sayaka-admission-profile-v3.json`. All 186 scan samples
(31 triples on flat/empty) and 30 version controls passed.

| Post-EOF reaping observation p95 | Polling | kqueue |
| --- | ---: | ---: |
| Flat 1024 files, profiling off | 5.9764 ms | 0.0649 ms |
| Empty root, profiling off | 5.2684 ms | 0.0869 ms |

The preregistered primary **paired median** tail changes were -0.0023 ms
(95% CI [-5.4929, 0.0041]) and -0.0002 ms ([-0.0018, 0.0013]); neither interval
excludes zero. The p95 reduction is a descriptive tail observation, not a
substitute statistical win for that primary metric. Secondary flat-fixture
completion changed by -2.0458 ms paired median ([-4.3488, -0.8069]); empty
completion was inconclusive. Parent timestamp overhead in v3 version controls
was +0.4804 ms ([0.1190, 4.5036]), so it is not free. No observed completion
change here is a Sayaka algorithm speedup or a renewed Mole comparison.

No product optimization was selected that would remove native admission,
cache volume classifications across runs, reduce JSON information, or change
the process model. Such changes need separate evidence and contracts.

Batch 2 currently closes as tooling and preregistration only, not measured
Mole installation or performance evidence. The pinned official installer calls
`/bin/ps` in its install-lock path; on the recorded macOS host that OS helper is
setuid and Seatbelt refuses it as `forbidden-exec-sugid`. The preflight now
detects required setuid/setgid helpers from metadata before launching canaries.
No privilege exception, replacement system tool, patched installer, or
unsandboxed fallback is permitted. A new disposable-environment contract and
explicit authorization are required before runtime work resumes.

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
accepted. Scan/JSON, terminal exploration, rule/installer file approval, application
previews, status/process top and local lifecycle implement parts of the ledger.
Directory purge, uninstall, system maintenance and full distribution are still
gaps; implemented command families must not be mistaken for complete task
coverage.

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

The current installer slice adds explicit ordinary-file selection and native
Trash approval to bounded UDIF/flat-PKG discovery. It retains inspection/native
identity binding, no-effect default JSON, explicit exclusions, exact confirmation
and ordinary-file receipts. Corrupt/unsupported formats and incomplete discovery
cannot authorize that action; a native refusal blocks the entire batch.
One explicitly authorized local macOS synthetic-fixture CLI Trash/receipt/
no-overwrite-restore run now has
[separate native evidence](INSTALLER_PREVIEW.md#recorded-native-acceptance).
Provenance/signatures/installation state, directory installers, Windows actions
and broader account/volume/real-download acceptance remain separate gaps.
This is not full T8/Mole installer parity, a new competitive timing result, or
permission to rerun/alter the historical C0 benchmark records.

Directory cleanup remains unavailable. The separate
[read-only directory foundation](DIRECTORY_ACTIONS.md) records observed
subtree/ancestor blockers and unresolved native gates; its owned in-fixture
rename counterexample shows why a stable root inode is not an exact member-set
guarantee. This is preparation for a separately approved contract, not directory
purge, application uninstall or additional parity coverage.

Recent slices narrow four ledger rows without closing them. The terminal menu
now launches the read-only `apps-related` association preview after two
explicit root prompts (browse/rules/installer/apps entries already existed);
full task-family and human UX acceptance remain open. `status` reports native
GPU utilization from the first public IOKit `IOAccelerator` subclass
publishing `Device Utilization %`, with freshness/validation discipline;
numeric temperature stays an explicit gap. `apps --running` adds opt-in
read-only running-process attribution by exact resolved executable path —
observational evidence, not uninstall authorization. Raycast/Alfred terminal
launchers are delivered as documented script generation plus preview-first
owned-artifact install/remove under a SHA-256 manifest (Terminal.app/iTerm2
choices); by design no launcher configuration is written on the user's
behalf. None of these are new benchmark results, complete task-family
coverage, or distribution evidence.

Two further slices narrow the `purge` and `uninstall` rows without closing
them. `sayaka purge ROOT...` is a read-only preview grouping rebuildable
artifact directories under their project-marker roots (default/custom roots,
staleness cutoff, grouped output, dry-run only); selected removal stays a
future directory-effects contract. `sayaka uninstall --bundle PATH
[--execute]` moves one explicit non-running `.app` bundle to the user Trash
under the `revalidated_bundle_trash_v1` contract — typed exact-name
confirmation, journaled intent/outcome with the Trash destination witness,
Finder 'Put Back' recovery, and sealed manifest identity; multi-copy flows,
related-data selection and official uninstaller paths remain gaps. Numeric
temperature is now a recorded deliberate gap (no public unprivileged Apple
Silicon source; no Intel validation host), not an unexamined one.

Potentially irreversible maintenance, directory actions, and privileged
operations require new action-specific design gates after M3. They are not
authorized by the initial ordinary-file trash contract. "Optimize" must name the
actual operation and evidence, not promise generic speedups or RAM boosting.
Never make permanent deletion a fallback after a failed trash operation.
The T10 operation/threat/recovery contract is drafted in
[MAINTENANCE.md](MAINTENANCE.md); it authorizes nothing by itself.

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
