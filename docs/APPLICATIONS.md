# Read-only macOS application inventory

`sayaka apps ROOT...` inventories `.app` bundle candidates from explicit roots.
It is read-only discovery: no app launch, no bundle loading, no execution, no
uninstall, no user-data mutation, no receipt/signature/entitlement checks.

`sayaka apps-related --app-root ROOT --library-root ROOT` adds a read-only
attribution preview for a small public-evidence ruleset. It reports possible
related data paths, certainty, and protection reasons only. It does not grant
deletion/uninstall authorization.

## CLI contract

```sh
sayaka apps .
sayaka apps . --json
sayaka apps . --filter Safari --exclude ./archive
sayaka apps . --running
```

- Roots are explicit (1..64). No implicit HOME/CWD/system roots.
- Scan traversal is bounded and prunes descent at `.app` directories, including
  a direct root that itself ends with `.app`.
- Nested apps inside bundle resources are intentionally not discovered in this
  slice.
- `--exclude` is explicit and command-local (not inherited from `clean`).
- `--running` is opt-in read-only running-process attribution: visible PIDs
  are enumerated once and matched by the exact canonically resolved
  `Contents/MacOS/<CFBundleExecutable>` path. Each record reports `running`,
  `not_running`, `not_attributable` (no trustworthy executable path) or
  `unknown` (enumeration failed or was truncated — never evidence of
  absence). Without the flag every record is `not_checked`. This is an
  observation only; it does not signal, trace or terminate processes, and a
  `not_running` result is not proof that no instance exists (skipped PIDs,
  helper processes and renamed executables are not matched).

Exit codes: **0 complete, 3 partial, 130 cancelled, 1 runtime failure, 2 invalid arguments**.

## Uninstall preview and execution contract

```sh
sayaka uninstall --bundle ./Fixture.app
sayaka uninstall --bundle ./Fixture.app --json
sayaka uninstall --bundle ./Fixture.app --execute
sayaka uninstall --bundle ./Fixture.app --copies-root /Applications --copies-root ~/Applications
```

The T9 uninstall contract for one explicit `.app` bundle. Default is a
read-only preview (evidence, protections, refusals); `--execute` moves exactly
the named bundle to the user Trash after typed exact-name confirmation under
`revalidated_bundle_trash_v1` (see
[UNINSTALL_EXECUTION.md](UNINSTALL_EXECUTION.md)). Execution requires an
interactive terminal; piped approval is refused. Recovery is Finder 'Put Back'
from Trash with its documented limits; there is no programmatic restore and no
permanent-delete fallback. Related data, preferences, caches and other copies
are never touched. A running bundle is refused at preview, at approval, and
again immediately before the native call.

`--copies-root` (repeatable) asks the preview to observe **coexisting copies**
of the same bundle identifier under the explicitly given roots, reusing the
bounded app-bundle scan (30-second cooperative engine cap) and the
inventory's plist metadata and running attribution (60-second budget); both
effective budgets are published in the JSON report. Copies are evidence only
— the named bundle itself is excluded by device/inode identity, never by
path text, and no copy is selected, touched, signaled or cleaned up after.
The observation is honestly stated: `not_checked` (no roots given),
`not_attributable` (the target's own `CFBundleIdentifier` or device/inode
identity could not be established, so no trustworthy comparison exists),
`unsupported_platform`, `complete`, `partial`, `cancelled` or `failed`; an
empty copy list is never evidence that no other copy exists.

The preview publishes the bundle identity (nofollow), the count of regular
executables directly under `Contents/MacOS`, a running-process observation
(any match refuses with the exact PIDs; enumeration failure is `unknown`,
never `not_running`), explicit refusals (`not_found`, `not_directory`,
`not_app_bundle`, `symlink_bundle`, `missing_info_plist`,
`info_plist_not_regular_file`, `system_location`, `non_local_volume`,
`running`, `internal_error`), the standing protections (related data,
preferences, caches, credentials and other copies untouched; running bundles
refused, never signaled; no permanent-delete fallback; `/System` refused) and
the recovery note (the bundle moves to the user Trash with Finder
'Put Back'; no programmatic restore). Exit codes: **0 clean / succeeded,
3 refusals or partial, 130 cancelled, 1 runtime failure, 2 invalid arguments**.
Journaled intent/outcome follows the M3 schema (directory item under the
bundle contract); interrupted durable `started` records reconcile to
`unknown`, never `succeeded`.

## Related-data preview contract

```sh
sayaka apps-related --app-root /Applications --library-root "$HOME/Library"
sayaka apps-related --app-root /Applications --library-root "$HOME/Library" --json
sayaka apps-related --app-root /Applications --library-root "$HOME/Library" --filter Chrome
```

- `--app-root` is required and repeatable (1..64).
- `--library-root` is required and repeatable (1..8), must explicitly end in
  `Library`, and is admitted only when native volume metadata confirms a local
  internal non-removable/non-ejectable filesystem.
- All roots are explicit; no implicit HOME/library discovery.
- `--filter` narrows display only. It does not authorize more probing.
- Candidate probes stay anchored to the validated `Library` root file identity.
  Descendant mount/device changes, symlink hops, dataless nodes, root replacement,
  and unknown native volume metadata fail closed and are reported as issues.
- `issues` includes upstream inventory diagnostics; `counts.issues_omitted` carries
  both inventory-side and app-related-side omission counts so partial output explains
  diagnostic truncation.
- Every candidate remains protected:
  - `deletable=false`
  - `authorized_action=null`
  - `preview_disposition=protect_for_manual_review`

The preview probes only path metadata with no-follow semantics. It does not read
browser profile contents, preferences, cookies, history databases, credentials,
or runtime lock/config files.

Current source rules:

- `org.chromium.default_user_data.macos.v1`
- `org.chromium.default_cache.macos.v1`
- `org.mozilla.firefox.default_profiles.macos.v1`
- `org.mozilla.firefox.default_profile_caches.macos.v1`
- `org.mozilla.firefox.profile_groups.macos.v1`
- `org.apple.library.application_support.bundle_id_convention.v1`
- `org.apple.library.caches.bundle_id_convention.v1`

The Chromium rules require observed app copies that declare allowlisted
`CrProductDirName` values. Bundle ID or name alone is insufficient.
Firefox rules are family-level shared-location hypotheses, not per-copy proof.
Generic Apple Library rules are convention hypotheses only.

## Identity and metadata

- Primary row identity is the native bundle-directory identity.
- Same physical bundle seen via overlapping roots is deduplicated and records
  root coverage.
- Same declared `CFBundleIdentifier` across distinct physical bundles remains
  separate rows.
- Declared identifier strings are preserved exactly (no case folding/normalization).

Read scope is fixed to:

- `Contents/Info.plist` (bounded XML/binary parsing for selected top-level keys)
- Optional metadata-only stat of `Contents/MacOS/<CFBundleExecutable>` when the
  declared executable is a single filename component.

Selected keys:

- `CFBundleDisplayName`
- `CFBundleName`
- `CFBundleIdentifier`
- `CFBundleShortVersionString`
- `CFBundleVersion`
- `CFBundlePackageType`
- `CFBundleExecutable`

Display name fallback is labeled:
`CFBundleDisplayName` -> `CFBundleName` -> bundle filename.
Localization (`InfoPlist.strings`) is out of scope (`localized: false`).

## Frozen parser/budget limits

- 4096 candidates
- 1 MiB per `Info.plist`
- 64 MiB aggregate plist reads
- Binary plist: 16,384 objects, 32,768 visited refs, depth 8
- XML plist: 20,000 nodes, depth 16
- 4 KiB per selected string field
- 64 KiB retained strings per plist
- 16 MiB retained metadata strings per inventory
- 1024 retained issues
- Cooperative 30s combined scan+probe budget (or smaller CLI timeout)

Budget checks happen before allocation/read when possible; charged bytes reflect
successful reads only.

## Non-goals for this slice

- installability/authenticity/trust claims
- whole-bundle byte accounting
- LaunchServices/running-state/process inspection
- signatures/receipts/quarantine/provenance
- reading icons/resources/helpers/framework internals

## Public references

- Apple Bundle Programming Guide: bundle structure (`Contents/Info.plist`,
  `Contents/MacOS`, `Contents/Resources`)
- Apple Info.plist Key Reference: `CFBundle*` keys above
- Apple Property List docs: XML/binary plist formats
- Apple File System Programming Guide (Library directory conventions):
  https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html
- Chromium user data directory defaults:
  https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md
- Firefox profile service and shared profile groups:
  https://firefox-source-docs.mozilla.org/toolkit/profile/index.html
