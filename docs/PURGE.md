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
`getattrlistbulk` batches (at most 64 KiB per open cursor). This avoids a separate
stat call for every ordinary entry. Only returned, validated attributes are used;
missing file attributes can fall back to descriptor-relative no-follow stat.
Directories with missing boundary attributes remain incomplete rather than
falling back to a pathname lookup that could hide a firmlink.
An unsupported first bulk call can rewind and use the original directory cursor;
errors after iteration starts remain errors. Mount points/firmlinks are rejected
before descent. Directory opens, identity checks, modification stamps and the
thread's no-materialization policy are retained. No previously measured size or
eligibility is reused. Up to four workers measure independent root children,
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
