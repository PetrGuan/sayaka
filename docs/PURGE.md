# Project artifact (purge) preview and bounded execution

`sayaka purge ROOT...` previews rebuildable project artifact directories,
grouped by project, from one bounded scan. It advances T8
(PetrGuan/SayakaCleaner#28) and the C0 `purge` ledger row. The default is a
read-only preview; `--execute` with explicit `--only` selections moves the
selected artifacts to the user Trash under the
[purge execution/recovery contract](PURGE_EXECUTION.md). There is no
select-all flag, no staleness auto-selection and no permanent deletion.

```sh
sayaka purge .
sayaka purge . --stale-days 60
sayaka purge . --json
sayaka purge ~/Library --profile developer-caches --json
sayaka purge . --execute --only ./app/target
```

## Qualification rules

A directory is an artifact candidate only when **all** hold:

1. Its name is bound to a project marker present as a direct child file of
   the same project root (`Cargo.toml` → `target`; `package.json` →
   `node_modules`, `dist`; `pyproject.toml` → `dist`, `build`;
   `Package.swift` → `.build`). A bare `target`/`build` directory without
   the marker never qualifies.
2. The marker file is the rebuild evidence; it is named in every output.
3. Neither the project nor the artifact nests inside another project's
   artifact (nested copies are excluded and counted, never merged).
4. Dataless (cloud placeholder) artifact directories are excluded, never
   hydrated or counted as cleanable.

Each artifact reports known logical/allocated subtotals (unknown stays
unknown, partial coverage is marked), the observed directory mtime, project activity evidence, and a
staleness flag against `--stale-days` (default 30, max 3650). **mtime is an
observation, not proof of disuse**; a "stale" artifact may still be wanted,
and a "fresh" one may be disposable. Sizes are deduplicated within each
artifact subtree; sibling totals can overlap through hard links and are not
additive, and no displayed byte count is guaranteed reclaimable.

## Git safety for project artifacts

Project scans omit `.git` directories and worktree link files before admitting
entries or following links. Exclusions share the entry/path retention budgets and
are counted under `exclusion_reasons.vcs_metadata`; they are not scan errors.
Explicit roots inside `.git` are excluded too. The repository root itself stays
in scope. An artifact containing nested Git metadata is refused as a whole.

Each artifact carries additive `git` evidence (`state`, `reason`, `repository`,
`ignored`, `tool`) and `execution_supported`. The fixed Apple-signed
`/usr/bin/git` executable is resolved and recorded once per observation pass.
Queries are grouped by repository and share a two-second deadline. `ls-files`
uses literal case-insensitive pathspecs, NUL records, bounded output and native
paths. `check-ignore` records positive ignore evidence; ignore status alone
never authorizes cleanup. Missing/failing Git produces `unknown`, not an empty
index. Tracked files produce `tracked` and refuse the complete artifact.

The process environment is cleared and allow-listed, with `GIT_OPTIONAL_LOCKS=0`,
system/global Git configuration disabled, no prompt, and fsmonitor/hooks disabled.
No shell or caller-supplied commands are accepted. Linked worktree Git state is
read through Git's own link handling; worktree inventory and removal are outside
this contract. No AI-tool contents are read.

Unknown Git state stays Review and is not selectable until a successful refresh.
Artifacts outside a repository retain the existing marker/activity rules. Git
observations participate in preview fingerprints and are refreshed at session
preparation, approval and the final native guard. Preparation and the final guard
also demand a complete bounded streaming metadata walk of selected artifacts to refuse
nested repositories, including public engine selections not created by a preview.
These checks can refuse very large/inaccessible selected trees; they never turn
partial coverage into permission. The documented last-check/path-replacement
race remains; Git observations are not filesystem locks.

## Project discovery and sizing budgets

macOS project previews classify before sizing. `ClassifyLimits` retains the
100,000-record / 32 MiB / 30-second discovery bounds. A marker-bound artifact
is recorded but never descended into for classification, even when directory
ordering lists its marker later. Marker lookups use the admitted parent fd and
no-follow metadata. Unknown layouts remain ordinary discovery; this does not
add Xcode signatures or new artifact rules.

`SizeLimits` separately allows 2,000,000 visited entries and 60 seconds across
all discovered artifacts, with at most four artifact workers. Each runs a
streaming `getattrlistbulk` DFS (with the existing safe native fallback), without
retaining regular-file paths. Hard-link identities deduplicate sizes within an
artifact; sibling totals can still overlap. The per-worker directory/hard-link
identity tables retain at most one million entries, and descriptor/path budgets
are divided between workers. The default project request has a 90-second total
wall-clock budget; Stop remains cancellable throughout Git inspection and sizing.

Every discovered artifact survives a sizing limit. `size_complete=false` marks
unknown or lower-bound totals, not zero and not permission to clean. Such items
remain unselected Review. `complete` also includes discovery coverage; global
partial-preview execution guards are unchanged. Git metadata found during bulk
sizing is not traversed and refuses the enclosing artifact. Native cleanup
admission uses this bounded streaming metadata path too, avoiding the old
100,000-record execution ceiling while preserving all native Trash guards.

JSON includes additive `scan_metrics` (discovery records, artifact/Git-descendant
records, sizing visits and phase times). These diagnostics do not participate in
plan identity. CLI progress includes `total_artifacts` and `sized_artifacts`;
existing ABI preview `total_items` / `completed_items` fields carry the same
counts without changing struct size. Candidate discovery is published before
sizing starts; the existing App scanning screen shows the number of folders
found and fills in measured bytes while Developer stays active. Classification
file bytes are not presented as cleanable artifact bytes.

See `benchmarks/project-classify-size-v1.json` for the real, copy-free mixed
project measurement. No unit/UI tests, fixture test runners or cleanup effects
were executed for that measurement.

## Developer cache profile

`--profile developer-caches` previews known developer-tool cache locations under
the effective account's passwd-database home directory (not `$HOME`, which may
point at an app container in the macOS App Sandbox). App/FFI callers can execute
complete, cleanup-supported cache candidates by passing their same-preview item
references, the exact plan digest, an absolute journal `state_dir`, and the
approval token `trash N caches`; the engine moves each approved cache directory
to Trash under `revalidated_cache_trash_v1`.
Rules are anchored to the documented absolute locations such as
`~/Library/Caches/pip`: granting that cache directory itself, the account home,
or an ancestor such as `~/Library` can report it, but an unrelated descendant
whose components merely end in `Library/Caches/pip` never qualifies.

The matcher builds each expected rule path lexically from the canonical
passwd-home path and the documented suffix, then stops considering descendants
once a rule location is matched. Each component below the home, including the
final cache directory, must be a real directory rather than a symlink; symlinked
intermediates or cache directories are not followed into their targets and are
not developer-cache candidates.

The CLI and binding previews discover rule-owned cache directories first, then
measure each cache with a cancellable streaming walk. Ordinary single-link files
contribute totals without retaining a file record or path. Directory identities
and multiply-linked file identities are retained in separately bounded tables;
hard-linked file contents are counted once per cache. The default cache preview
budget is 300 seconds across discovery and measurement, with at most one million
identities in each table, 128 open directory cursors/depth levels, and 32 MiB of
retained stack paths. Discovery still has the generic 100,000-entry/32 MiB index
limits. Generic disk and project scans keep their existing limits.

On macOS, cache measurement fetches native entry metadata in bounded
`getattrlistbulk` batches (at most 64 KiB per open cursor, plus one initialized
64 KiB spare buffer per enumerating thread). Buffers are acquired lazily and
returned as soon as a batch is consumed, including terminal EOF/error, while
directory descriptors and cursor positions remain held. Undecoded records retain
their buffer exclusively. The spare reuses allocation only; no entries, cursor
offsets or metadata observations are reused. This avoids a separate
stat call for every ordinary entry. Only returned, validated attributes are used;
missing file attributes can fall back to descriptor-relative no-follow stat.
Directories with missing boundary attributes remain incomplete rather than
falling back to a pathname lookup that could hide a firmlink.
An unsupported first bulk call can rewind and use the original directory cursor;
errors after iteration starts remain errors. Mount points/firmlinks are rejected
before descent. Directory opens, identity checks, modification stamps and the
thread's no-materialization policy are retained. No previously measured size or
eligibility is reused. Cache preview defaults use the available CPU count capped
at eight workers (fallback four), retaining at least 32 default open-directory
slots per worker, up to 256. Explicit caller worker/handle/path/depth limits still
apply. Up to eight workers measure independent root children,
with a bounded directory-only queue and shared identity, open-cursor and
retained-path budgets. Each worker applies the no-materialization thread policy
and walks its subtree without retaining file records. Hard links are deduplicated
across workers. The root remains open and is checked for changes after workers
finish; descendants are checked after their own subtree finishes. Cancellation,
the deadline and errors stop or mark the same measurement incomplete. The
generic scan cursor is unchanged.

Symbolic links *inside* a recognized cache are counted in `links_not_followed`;
their targets are neither opened nor included in the byte totals. They do not
make the cache incomplete. Root/ancestor symlinks, unreadable entries, dataless
contents, mount boundaries, concurrent directory changes, cancellation and
exhausted budgets still prevent complete coverage. Byte totals are observations
of regular-file contents, not a promise of reclaimed space. Rule recognition
and execution revalidation remain separate from size accounting.

Cache execution revalidates immediately before approval and again before each
Trash move: the directory must still be the same device/inode and type observed
in the preview, every component below the home through the target must still be
a real directory at exactly the recognized passwd-home rule path, and profile
eligibility checks must still pass. Candidates with `cleanup_supported: false`
(for example, a lock file was observed) are never approvable. Trash is the only
effect; a failed Trash operation never falls back
to permanent deletion. As with project purge, the residual final pathname or
ancestor replacement race remains disclosed rather than claimed closed.

## Output and exit codes

Human output groups artifacts under their project root with marker kinds;
JSON is a versioned envelope (`sayaka.purge_preview` schema 1) always
carrying `effects_performed: false`. Exit codes: **0 complete, 3 partial or
refusals, 130 cancelled, 1 runtime failure, 2 invalid arguments**.

Execution requires a complete preview, an interactive terminal, 1..32
explicit `--only` selections from the same invocation's preview, and a typed
exact confirmation (`purge N artifacts`, 120-second approval). Each artifact
moves as one container with per-item journaled outcomes; the binding marker
(rebuild evidence) is revalidated and never touched. Displayed byte totals
are observations, not reclaimed space. Project build activity is rechecked
before removal — see [PURGE_EXECUTION.md](PURGE_EXECUTION.md) for the full
contract and its disclosures.

## Custom Xcode build data (signature v1)

Project discovery recognizes a directory by its contents, independent of its name:
`Build/Intermediates.noindex` or `Build/Products`, plus at least one of
`Logs/Build`, `ModuleCache.noindex`, `Index.noindex`, `SourcePackages`, or a bounded
`info.plist` whose `WorkspacePath` is an absolute native path. A `Build` folder alone
never qualifies. Native descriptor-relative probes reject symlinks, dataless
objects and mount crossings. Their transient handles and retained evidence count
against classification resource budgets. Matching descendants are pruned from
classification and independently sized as described above. Classification retains
directories and binding marker files, not unrelated regular files; Git tracked-file
inspection remains independent and complete-or-refused.

Evidence: a fresh macOS Xcode Debug build observed on 2026-10-12 contained both
Build signals, Logs/Build, ModuleCache.noindex, Index.noindex, SourcePackages and
info.plist with WorkspacePath in a custom derivedDataPath. A standard per-project
DerivedData directory contained the same layout except ModuleCache.noindex.
Each preview carries the signals actually matched, workspace provenance and a
present/not_found/unknown state. Missing workspace metadata is not proof of safety
or a reason to bypass Git checks. Standard native-home
`Library/Developer/Xcode/DerivedData` is excluded from this signature because the
cache profile owns it. Only the matching child is targeted: `.build/xcode` does not
make the entire `.build` parent disposable.

Signature targets use ordinary native directory admission and Trash-only execution,
with fresh signature checks at preparation/revalidation/last guard plus existing Git
checks. The exact `.build` path component is permitted for this target kind; all other
hidden, system, cloud, package, identity, ownership and protection boundaries remain.
Changes in the previewed signature/workspace provenance require a fresh preview.
Path replacement races remain disclosed. The recommendation tier uses the same
age, size, completeness, protection and Git policy as marker-bound artifacts.

## Extended macOS project rules

See [Project artifact rules](PROJECT_ARTIFACT_RULES.md) for the shared fixed table, nested paths, directory markers, tag-only observations and Pods prerequisites.

## Project activity

Native project previews include `project_activity`: commit and bounded source
metadata dates (Unix milliseconds), the artifact date, nullable uncommitted/build
state and source-coverage status. Project source/commit dates take precedence;
artifact mtime is a fallback only. A fresh build alone does not make old source
active. Stale means at least the configured age, clean observed Git status (or a
positively observed non-repository), complete bounded source observation, and no
observed build activity. Unknown is not inactive; this does not weaken Git safety.

Source observation reads metadata at depths 1–2 (500 entries / one second per
project), skips artifact and known AI-tool directories, and observes HEAD/index
metadata without traversing Git objects. Git queries use the fixed verified tool
boundary with a two-second per-repository budget and no optional index locks.
Build observations use same-user native executable/cwd metadata for cargo, rustc,
xcodebuild, swift-build, swift, node, npm, pnpm, yarn, gradle and java. Unknown
process visibility refuses cleanup. Cargo profile lock checks are bounded to
500 entries / 250 ms / four directory levels, skip generated leaf trees, and
immediately release a nonblocking shared lock used to detect an exclusive holder.
Swift workspace-state metadata modified within two seconds is treated as writing.
Bounds or unreadable lock state remain unknown. No files are created or written.

Preview and native session admission refuse running/unknown builds; the final
native guard repeats this observation. The existing last-check/path-replacement
and process-start race remains: these checks are not an atomic exclusion lock on
all build tools. Fresh metadata and an explicit Trash confirmation remain required.

### Cache sizing diagnostics and complete-traversal tuning

Debug cache sizing emits `[SayakaSizing]` summaries per candidate. The engine
summary reports visited entries, unique regular files, links, directory identities,
peak live directory handles, requested worker limit, completeness, cancellation
and issue count. The native summary separates directory-open/admission time,
post-traversal change checks, bulk-call count/time, returned entries, buffer
allocation/reuse and legacy/stat fallbacks. Native operation durations are summed
across workers and overlap; they must not be added as sequential wall time.
Detailed clocks/logging are disabled in release builds.

An owner App observation measured DerivedData in 48.372 s. A production CLI
read-only preview reproduced 49.933 s sizing, complete with no issues. A short
live-process sample found most active worker samples inside directory `openat`
and `getattrlistbulk`, rather than size arithmetic. The existing safe opens and
all enumeration/change checks remain. Cache preview defaults now allow up to
eight workers as described above; project worker scheduling and generic limits
are unchanged. A per-thread spare reuses initialized buffer storage without
sharing a live buffer between cursors or caching any prior metadata result.

Final single CLI observation: 42.968 s sizing, 4,202,640 entries, 3,820,712 unique
regular files, 381,711 directories, 218 links not followed, peak 82 handles,
complete and zero issues. Logical bytes (337,363,491,558), allocated bytes
(305,931,964,416) and private bytes (259,929,829,376) exactly matched the baseline.
There were 381,711 directory opens and completion checks, 760,197 bulk calls,
55,955 fresh buffers and 325,756 reused buffers, with no legacy/stat fallback.
This is about 14% less sizing time in these observations; an earlier modified
run was 41.046 s. Filesystem cache and machine-load variation were not controlled,
so these are not median/p95 benchmarks, a claimed per-change causal speedup, or
full-App acceptance. No entries or safety checks were skipped to obtain the result.

Engine/platform/bindings regression sources compile without execution, including
buffer exclusivity/capacity and 1/8/32 requested-worker hard-link accounting,
handle closure and policy-restoration checks. CLI build and release library check
passed (the latter uses the repository's existing unstripped build-time proc-macro
workaround on macOS 27). No unit/UI tests, test binaries, harnesses or benchmarks
were executed. Full App scan and Stop acceptance remain manual owner validation.

### Registered-owner preflight

A later owner App scan completed classification at 53/53, but a development app's
registered build copy spent the five-second per-owner budget inside
`registry_bundle`. The timeout protected that cache and allowed classification to
continue. A subsequent read-only CLI run did not reproduce that native stall, and
a later sample of the original App showed no surviving owner worker. The specific
blocking system call is not established by those observations.

Cache ownership now preflights registered paths before expensive bundle capture.
The existing no-follow presence check excludes absent registrations; normalized
paths are deduplicated together with matching captured inventory paths. If their
union exceeds eight present candidates, classification refuses with
`copies_unknown: registered candidate limit exceeded; bundle identities unverified`.
This is a conservative candidate-budget refusal, not a claim that those paths are
verified owners. It prevents needless bundle reads for this already unsupported
many-registration case. At or below the limit, every present registration still
receives fresh bundle/manifest capture, bundle-ID comparison and identity
revalidation, followed by the existing mandatory Spotlight and activity checks.
Unknown, malformed or changed observations never become permission to clean.
Generic copy discovery retains its 256-owner limit.

Observed registry bundle capture now identifies `bundle_witness`,
`manifest_witness`, `manifest_read`, `bundle_revalidate` and
`manifest_revalidate`. Each boundary checks the same deadline/cancellation control;
late results remain rejected. Debug details retain their shared 256-record bound,
with up to 32 extra slow-completion records so early owners cannot hide all later
slow stages. The five-second wait, two-worker process-wide bound, no-follow,
no-materialization, parser/entity limits and fresh execution revalidation remain.
An in-flight native call cannot be forcibly interrupted; a late worker can retain
its slot until that call returns.

Actual production CLI observation after this change: the many-registration owner
was protected in 5.423 ms, classification processed 53/53 in 7.770 s including a
6.751 s inventory, and engine preview took 9.627 s with no effects. The preceding
CLI run protected that owner in 155.577 ms and classified in 10.151 s; it did not
reproduce the five-second App timeout. Both previews remained partial due to the
single protected owner. Cache/machine load were uncontrolled; these are individual
CLI observations, not full-App acceptance or proof that all native stalls are
fixed. Engine/bindings regression sources compiled without execution and CLI
build passed. No unit/UI tests, test binaries, harnesses or benchmarks were run.

### Drained-batch recycling and lazy entry paths

Further investigation of an owner App's 39.554-second complete DerivedData scan
found the same native bottleneck. In a sampled production CLI preview (42.020 s
sizing), all eight workers were active and roughly 94% of their stack samples
were in directory open or bulk metadata syscalls, with little mutex waiting.
It opened/checked 381,711 directories and made 760,197 bulk calls. Summed native
operation durations overlap across workers and are not wall-clock stages.

The scanner now returns an exhausted batch's initialized storage immediately,
while keeping the directory FD, iteration state and end-of-subtree change check.
It acquires storage only for the next read. Partially consumed batches remain
exclusive; returned entries own their names and metadata. EOF and error also
release storage without changing first-call fallback or terminal semantics.
The one-spare-per-thread / 64 KiB-per-live-batch bounds remain unchanged.

Successful file accounting also avoids constructing a temporary full path. The
same native-byte path-length limit is checked first (including root/trailing
separators), and a path is materialized once when descent, a project policy check
or an error needs it. Directory paths move into the DFS frame without a duplicate
allocation. No-follow/volume/dataless checks, hardlink deduplication, completeness,
progress, cancellation, resource bounds and all sizing attributes are unchanged.

Final actual production CLI sizing: 40.682 s, complete/zero issues/no effects;
4,202,640 entries, 3,820,712 unique regular files, 381,711 directories and 218 links
not followed. Logical 337,363,491,558 / allocated 305,931,964,416 / private
259,929,829,376 bytes exactly matched the sampled baseline. Fresh buffer
allocations fell from 55,955 to 39,152 (about 30%); reuse counters now count each
batch reacquisition, including EOF reads, rather than only initial cursor reads.
Directory opens and bulk calls stayed identical, with no legacy/stat fallback.

This does not establish a wall-time improvement over the owner's prior 39-second
App scan: filesystem caches/load were uncontrolled and the 42-second CLI baseline
was sampled. The native I/O floor remains. A ten-worker observation took 43.619 s
and was discarded; final worker and handle limits remain unchanged. CLI build and
engine/platform/bindings regression-source compilation passed without execution.
Regression sources cover unread/last-record buffer lifetime, terminal errors,
owned entries/held descriptors and byte-exact path limits/error paths including
non-UTF8 names. No unit/UI tests, test binaries, harnesses or benchmarks were run.
A new owner App scan and manual Stop check remain runtime acceptance work.
