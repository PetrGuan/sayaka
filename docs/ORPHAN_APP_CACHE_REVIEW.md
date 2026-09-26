# Possible app cache leftovers (issue 144)

The Mac App Store client asks for two explicit, read-only grants: one folder
containing `.app` bundles and one `Library/Caches` folder. The shared core
inventories physical app bundles in the chosen folder and scans the direct
children of the chosen Caches folder. A direct child named like a bundle ID is
compared with observed `CFBundleIdentifier` values using exact string equality.
Display names and case-insensitive substring matches do not establish identity.

The report distinguishes `installed_app_observed`,
`possible_orphan_review_only` and `protected_shared_or_system`. A candidate is
only *possibly* orphaned when no exact identifier match was observed. Even a
complete scan of the selected Applications folder is not a complete inventory
of the Mac: app copies may live in other folders or volumes. Partial scans,
row/path limits, skipped symlinks/cloud placeholders and missing metadata are
explicit uncertainty, never zero apps. Skipped direct children are listed
separately and make selected-library coverage incomplete even if the generic
scanner considers a no-follow symlink skip within its normal policy.
No row is preselected or authorized for Trash by this report.

The first scope is deliberately limited to `Library/Caches/<bundle ID>`.
`Application Support`, Preferences, Keychain, LaunchAgents, `Containers`,
`Group Containers`, shared `group.*` identifiers and Apple-owned `com.apple.*`
identifiers do not become possible cleanup targets. A name-based candidate is
review evidence, not proof of ownership, inactivity or rebuildability. The
App presents each candidate separately with observed app copies and uncertainty
and can reveal it in Finder for owner-side inspection. A future Trash action
requires a separate execution contract that rechecks identity, activity,
ownership and native Trash eligibility at approval time.

The `sayaka_orphan_preview_v1` C ABI is synchronous, bounded and read-only;
clients call it off the UI thread with two live security-scoped grants. It
returns one versioned JSON report with no executable selection or action token.
