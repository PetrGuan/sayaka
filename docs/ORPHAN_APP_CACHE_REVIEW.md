<!-- SPDX-License-Identifier: MPL-2.0 -->

# Possible app cache leftovers: retained read-only v1

The existing `sayaka_orphan_preview_v1` C ABI remains synchronous, bounded and
strictly read-only. It compares direct `Library/Caches` children with actual
`CFBundleIdentifier` values from physical app bundles in the selected app root.
Identity comparisons are exact; display names and case-insensitive substring
matches do not establish ownership.

The report distinguishes `installed_app_observed`,
`possible_orphan_review_only` and `protected_shared_or_system`.
`globally_complete` is always false: a complete selected-root scan is not an
inventory of the Mac. Partial scans, row/path limits, skipped links or cloud
placeholders and missing metadata are uncertainty, never zero apps. Skipped
direct children make selected-library coverage incomplete. No row is
preselected or authorized for Trash; the report contains no execution token.

Its scope remains `Library/Caches/<bundle ID>`. Application Support,
Preferences, Keychain, LaunchAgents, Containers, Group Containers, shared
`group.*` and Apple `com.apple.*` identifiers do not become execution targets.
Name-based evidence alone proves neither ownership nor inactivity.

The Developer ID App currently still presents the legacy two-folder selection
and Finder-reveal workflow. That is an existing UI/API choice, not a claim that
sandbox authorization is required to inspect native home. Existing callers
retain v1's request and access-lifetime requirements unchanged and call it off
the UI thread.

[ORPHAN_EXECUTION.md](ORPHAN_EXECUTION.md) proposes a separate, acceptance-gated
contract with native-home discovery, tiered evidence and typed approval. Its
App integration will replace the two-folder workflow and stop using v1, while
preserving the v1 ABI for existing clients. That integration is not implemented
by this documentation change. A v1 result can never instantiate an executable
orphan session or bypass the new observations, policy and native guards.
