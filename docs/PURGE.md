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
unknown, partial coverage is marked), the observed directory mtime, and a
staleness flag against `--stale-days` (default 30, max 3650). **mtime is an
observation, not proof of disuse**; a "stale" artifact may still be wanted,
and a "fresh" one may be disposable. Sizes are deduplicated within each
artifact subtree; sibling totals can overlap through hard links and are not
additive, and no displayed byte count is guaranteed reclaimable.

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
are observations, not reclaimed space, and a running build tool is not
detected — see [PURGE_EXECUTION.md](PURGE_EXECUTION.md) for the full
contract and its disclosures.
