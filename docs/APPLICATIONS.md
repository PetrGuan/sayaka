# Read-only macOS application inventory

`sayaka apps ROOT...` inventories `.app` bundle candidates from explicit roots.
It is read-only discovery: no app launch, no bundle loading, no execution, no
uninstall, no user-data mutation, no receipt/signature/entitlement checks.

## CLI contract

```sh
sayaka apps .
sayaka apps . --json
sayaka apps . --filter Safari --exclude ./archive
```

- Roots are explicit (1..64). No implicit HOME/CWD/system roots.
- Scan traversal is bounded and prunes descent at `.app` directories, including
  a direct root that itself ends with `.app`.
- Nested apps inside bundle resources are intentionally not discovered in this
  slice.
- `--exclude` is explicit and command-local (not inherited from `clean`).

Exit codes: **0 complete, 3 partial, 130 cancelled, 1 runtime failure, 2 invalid arguments**.

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
