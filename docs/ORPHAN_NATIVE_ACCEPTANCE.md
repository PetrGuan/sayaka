# Orphan native acceptance record

## 2026-10-11: delegated acceptance, blocked before fixture execution

The owner explicitly authorized the implementation agent to perform the native
acceptance described in ORPHAN_EXECUTION.md. Unit and UI test execution remains
prohibited. This record does not open the release gate.

Environment: macOS 27.0.1 (26A434), Apple Silicon, ordinary effective user.
Initial source: sayaka `45b69d7215d0c50721b93b3e76007482003d3bb7`,
SayakaCleaner `5b762c9b4f7b6d837b8ddae55f7844e8a0a91aef`.

Manual observations:

- Launched the Debug App and opened App Leftovers. The move button was disabled.
  Triggering its read-only preview displayed `Invalid argument (os error 22)`.
  The shipped CLI read-only orphan preview reproduced the same failure.
- Read-only OS diagnostics showed that `O_NOFOLLOW` and `O_NOFOLLOW_ANY`
  separately open the account Library directory, while their combination fails
  with EINVAL. The native observation opens now retain only O_NOFOLLOW_ANY.
- The next CLI attempt failed with `unsafe_path`. Root directories including `/`
  and `/Applications` carry SF_NOUNLINK. Read-only PathWitness now permits these
  protection flags, retaining them in its identity stamp. Native Trash target
  admission remains unchanged and continues refusing protected targets.
- With both fixes, CLI preview reached `Operation not permitted (os error 1)`.
  Read-only access diagnostics confirmed that this host process cannot read the
  current user's Trash or Library/Cookies directories. No permission or
  filesystem-protection bypass was attempted.

No fixture was moved or real user data modified. No successful native cleanup,
Finder Put Back, history rendering, race/fault scenario or full acceptance is
claimed. All contract acceptance cases remain pending until the required access
is available. ORPHAN_NATIVE_ACCEPTANCE_RECORDED remains false.

Validation: workspace and test-source build passed. A read-only protected-root
regression test source was added; no unit/UI tests were executed. The manual App
observations above are separate from build validation. The two runtime fixes
received independent GPT-6 Astra code review.

## 2026-10-11: access enabled; discovery and copy-coverage blockers

After the owner enabled the required OS access, the same CLI read-only preview
advanced past the permission failure and returned `discovery_incomplete`.
Read-only directory counts showed more than 500 filename matches, with system
preferences and non-reverse-DNS names consuming the 256-candidate limit.

The discovery scope correction excludes non-reverse-DNS names and permanently
denied owners before row accounting. All encountered entries still consume the
shared entry/time budgets; excess in-scope candidates still fail closed. This
narrows the target set and does not increase limits or open either native gate.
Workspace and test sources compiled successfully; no tests were executed.
Independent GPT-6 Astra source review reported no actionable findings.

With that correction, the CLI advances to `copies_unknown: symlink`. A read-only
inventory identifies the system-provided `/Applications/Safari.app` link to
`../System/Cryptexes/App/System/Applications/Safari.app`. The current copy-coverage
contract refuses such links rather than silently skipping them. The system app
was not removed, relocated, modified or exempted for acceptance.

No disposable fixture execution can be approved while mandatory copy coverage
is unknown. Positive move/recovery acceptance remains pending; this observation
is evidence of fail-closed behavior, not a passed execution acceptance matrix.

## 2026-10-11: approved Safari observation and disposable fixture preview

The owner approved the narrowly typed system Safari amendment. The implementation
supports only the documented two-link OS layout, verifies the Apple code identity,
and retains the chain/manifest evidence across preview and final guards. No
system app was modified. A complete read-only preview returned 43 in-scope rows
with no global issues. Both new native regression sources are explicitly ignored
host-layout cases and were compiled, not executed. Independent GPT-6 Astra review
found the original unconditional host-layout test inappropriate; it was fixed
and reverified with no remaining findings.

A separate pre-existing process initially had no readable executable path. The
owner handled it; the next read-only UID census had no unreadable paths. No
signals were sent by the implementation or acceptance agent.

Disposable fixture data used the `org.sayaka.acceptance144` namespace, with four
small ordinary data leaves: a 40-day-old cache, a 40-day-old cache containing a
one-day-old file, an Application Support leaf, and a cache with a matching
self-created app moved to Trash manually through Finder. The preview then
completed with 47 rows and these fixture observations:

- The app-in-Trash fixture was recognized as `trashed_bundle`.
- The old and recent caches were `name_only`; the recent descendant added
  `recently_modified` as required.
- The Application Support fixture was `name_only_read_only`.
- All fixture rows remained default-off and non-executable under the closed gate.

An additional existing LaunchAgent's program path contains a symlink. The current
writer-evidence contract fails closed with `symlink_path`; this also refuses all
four fixture rows. The real updater/LaunchAgent configuration was not modified,
unloaded, moved or exempted to obtain a passing result. The Safari exception is
not a general symlink-resolution permission and does not alter this check.

Thus tier/age/read-only/gate observations are recorded, but no positive native
cleanup or complete acceptance is claimed. The execution gate remains false.
Positive moves, recovery, approval/race/fault cases remain pending while this
writer-evidence prerequisite is unknown. Any extension of LaunchAgent evidence
rules requires its own explicit contract decision and independent review.

## 2026-10-11: approved LaunchAgent location observation

The owner approved the separate LaunchAgent proposal. The implementation retains
bounded, descriptor-relative location evidence with explicit link interpretation.
Independent GPT-6 Astra review found missing fresh-vs-retained program comparison,
unsafe device opening before type rejection, and an unspecified volume policy.
All were fixed and reverified: only directories are opened, leaf/link metadata
is bracketed and retained, and positive local APFS volume evidence is compared.
Workspace and test sources compiled successfully; no tests were executed.

A native read-only CLI preview completed with no global issues and no LaunchAgent
path refusal for the disposable fixtures. The old cache now has only
`native_acceptance_pending`; the recent cache retains `recently_modified`, and
Application Support retains `name_only_read_only`. The previous app-in-Trash
fixture currently appears as `name_only`, so this run does not renew the earlier
T1 observation. No real service configuration or application was modified.

No native move was performed. The production gate remains false and the full
move/restore/race/fault matrix remains pending.


## 2026-10-11: delegated manual native fixture observations

The owner explicitly delegated manual application/native fixture acceptance.
No unit or UI tests, test runners, scenario harnesses or automated UI tests were
executed. Individual native CLI interactions and Finder/App inspection were
performed manually through the interactive tools.

Build provenance:

- Core production source: `c5d085260961c9ca923b88b24c93ef1e55ec88df` (PR #114).
- App: `d73fe6c` (PR #434), pinning that core; build-for-testing succeeded
  without executing tests.
- macOS 27.0.1 (26A434), Apple Silicon, local APFS.
- Unpublished detached fixture checkout: `/private/tmp/sayaka144-native-fixture`.
  Its only source change sets `ORPHAN_NATIVE_ACCEPTANCE_RECORDED=true`.
  The production checkout, shipped pin and App retain the false gate.
- Modified source SHA-256: `2cdf58c6fdad4f3e99cb4ec7e7a22d8c8fbc4e60f69da8bf2c5452afff62580f`.
- Fixture CLI SHA-256: `5063d5283b6b835a3aea70b24375b1349c517935e6660051fd0a82095973a434`; built in the fresh isolated
  `/private/tmp/sayaka144-native-build-v2` directory. Earlier reused build output
  still reported the closed gate and was not used for moves.
- Initial CLI policy path was the absent legacy `SayakaCleaner Direct` location;
  subsequent refusal observations used current `SayakaCleaner`. These fixture
  runs do not independently verify nonempty policy matching.

Observed outcomes (all data self-created under `org.sayaka.acceptance144`):

| Observation | Actual result |
| --- | --- |
| T3 old cache | Forty-day-old leaf was eligible and default-off; exactly one explicitly selected cache moved. Operation `12d45-1a1298351d9-1`, schema 9, `succeeded/moved_to_trash`. |
| T3 recent descendant | Forty-day-old root with one-day-old file remained non-executable with `recently_modified`. |
| T3 user data | Application Support remained non-executable with `name_only_read_only`. |
| T3 Finder recovery | Put Back restored the original path, device 16777231, inode 1714500 and exact disposable contents. Other three original fixture identities/content were unchanged. |
| T1 normal | Self-created App manually moved to Trash; matching cache became `trashed_bundle`, eligible/default-on. Exactly the selected cache moved. Operation `12e61-1a12985b173-1`, schema 9, `succeeded/moved_to_trash`. |
| T1 recovery | Finder Put Back restored the cache; the recovered artifact was preserved in the fixture workspace. Finder added native metadata attributes; a subsequent cleanup preview conservatively refused that recovered cache rather than relaxing admission. |
| T1 restore after preview | A new disposable cache (inode 1774380) was previewed with the App in Trash. Finder then restored the App. Approval refused `resource_changed: trash evidence`; cache unchanged and no new journal. |
| Observed installed copy | Restored/new fixture Apps outside the mandatory roots were found as copies; their cache rows refused `installed_copy_present`. This does not cover every mandatory/extra-root or family case. |
| Running after preview | A separate App/cache (`org.sayaka.acceptance144.running`, cache inode 1774562) was eligible while the App was in Trash. Starting its self-built sleep executable after preview made approval refuse `running`; cache unchanged, no new journal. The cleanup implementation sent no signals. Only the disposable process was interrupted afterward. |
| Journal initialization refusal | With an eligible fixture selected, an existing ordinary fixture source file supplied as state-dir caused `Not a directory (os error 20)` before any move. Cache inode 1774562 and source contents remained unchanged. This covers initialization rejection, not a later atomic-publication fault. |
| App permissions/gate | Initial `Operation not permitted` was resolved by the owner updating Full Disk Access for the compiled App. The next App preview completed and visibly kept removal disabled pending native acceptance. |
| History | Copies of the two actual fixture records placed in App's dedicated LeftoversJournal rendered as successful Apps operations with 62 logical bytes per row and recovery caveats. An existing legacy record remained visible. These are CLI execution records, not App-issued moves. |

Success journal originals remain in `~/Library/Application Support/Sayaka144AcceptanceJournal`.
Disposable source/apps, restored T1 cache, manifest and local progress evidence
are under the App workspace `.build/acceptance144-20261011` directory. No real
application/service or user data was moved, removed or signalled for acceptance.

These observations are partial acceptance, not permission to open the gate.
Still pending: bundle/manifest replacement; exhaustive copy/family roots;
LaunchAgent fixture reference/malformed/replacement cases; native spelling,
ancestor and dataless cases at each phase; altered digest/count/token/IDs, replay,
expiry/clock rollback and over-32 batching; interruption after started and unknown
recovery/no retry. No positive fault-injection result is inferred from source
review or compiled test sources. The production gate remains false.
