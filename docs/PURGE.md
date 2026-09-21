# Read-only project artifact (purge) preview

`sayaka purge ROOT...` previews rebuildable project artifact directories,
grouped by project, from one bounded scan. It advances T8
(PetrGuan/SayakaCleaner#28) and the C0 `purge` ledger row. **It performs no
effects**: directory effects remain unapproved (see
[DIRECTORY_ACTIONS.md](DIRECTORY_ACTIONS.md)); there is no `--execute`, no
selection approval and no permanent deletion.

```sh
sayaka purge .
sayaka purge . --stale-days 60
sayaka purge . --json
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

## Output and exit codes

Human output groups artifacts under their project root with marker kinds;
JSON is a versioned envelope (`sayaka.purge_preview` schema 1) always
carrying `effects_performed: false`. Exit codes: **0 complete, 3 partial,
130 cancelled, 1 runtime failure, 2 invalid arguments**.

Removal of selected artifacts is a future directory-effects contract; this
preview is its evidence base, not an approval.
