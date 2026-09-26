# User application cache rules (issue 140)

The Mac App Store Developer Caches view exposes exact, documented cache
locations under a user-granted root. It lists each rule's source and does not
preselect a name-based `~/Library/Caches` sweep. Selection is explicit, and
the same rule/path is revalidated before native Trash execution. There is no
permanent-delete fallback.

## Classic Microsoft Teams cache, rule version 1

| Field | Contract |
| --- | --- |
| Client version | Classic Teams for macOS only; **New Teams is excluded** |
| Exact location | `~/Library/Caches/com.microsoft.teams` under the current account's anchored home |
| Owner evidence | Microsoft-hosted Classic Teams cache guidance identifies this exact path; the folder is selected only by that full anchored path, not by a suffix found elsewhere |
| Rebuildability | Microsoft documents clearing this cache after quitting the client; rebuilding may take time, and a new sign-in may be needed |
| Activity | Running `Teams`/`Microsoft Teams` or a Teams helper blocks selection and execution even when the `.app` bundle is renamed; unavailable process census also blocks; state is checked again at approval and immediately before the move |
| Non-targets | Application Support, New Teams container/group data, preferences, Keychain credentials and logs are never part of this rule |
| Scope | The sandbox still needs explicit user authorization for the folder or an ancestor; a denied or partial scan cannot become an executable selection |

[Microsoft Teams cache guidance](https://learn.microsoft.com/en-us/answers/questions/4437348/i-deleted-classic-teams-from-my-mac-and-now-i-have) names the Classic Teams path. [Microsoft's New Teams cache article](https://learn.microsoft.com/troubleshoot/microsoftteams/teams-administration/clear-teams-cache) locates its data in protected Containers and Group Containers, outside this rule.

The nearby fixture assertions cover a positive exact-path candidate, running
Classic Teams after a bundle rename and unknown process state, and negative
Application Support, group, preference, Keychain, sync-staging and diagnostic-log
paths. Existing native
execution guards reject symlinks, dataless placeholders, cloud roots, changed
identities, unsupported volumes and incomplete coverage. Real application
activity and Trash effects still need owner-side isolated native observation;
the automated unit/UI suites are intentionally not run by agents.

## Discord stable desktop cache, rule version 1

| Field | Contract |
| --- | --- |
| Client version | Discord stable desktop app for macOS 11 or later; Canary, PTB and sandboxed variants are excluded |
| Exact location | `~/Library/Application Support/discord/Cache` under the current account's anchored home |
| Owner evidence | Discord's [troubleshooting guide](https://support.discord.com/hc/en-us/articles/31623498041623-Discord-Troubleshooting-Guide) names this exact Mac cache directory |
| Rebuildability | Discord instructs users to clear this cache for troubleshooting and restart the app; the cache is re-created as needed, while signing in again may be necessary |
| Activity | Running `Discord` executable or a `Discord Helper` process blocks selection and execution even if the `.app` bundle is renamed; unavailable process census also blocks; the check is repeated before the move |
| Non-targets | Sibling settings, credentials, downloads, other Application Support data, and Canary/PTB directories are excluded |
| Scope | The sandbox needs explicit user authorization for this folder or an ancestor; incomplete or denied scans cannot become executable selections |

The App shows this app-specific cache for explicit review, never as a
preselected recommendation. The fixture assertions cover the exact path,
sibling data, renamed-bundle activity and unknown process state. Native isolated observation
remains necessary before treating the rule as fully accepted.

## Logs and shared caches are deliberate non-targets

Zoom's [macOS troubleshooting-log instructions](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0065734)
identify `~/Library/Logs/zoom.us` and ask users to send those files to Support
for an active ticket. The log history is diagnostic evidence that cannot be
reconstructed after deletion, so it is listed as unsupported in the App rather
than treated as a rebuildable cache. Generic logs and crash reports remain
non-targets because a directory name alone does not establish ownership or
absence of user content.

Dropbox's [cache-folder guidance](https://help.dropbox.com/delete-restore/cache-folder)
describes `.dropbox.cache` as staging for uploads and downloads. Its sync state
is not established by a directory scan, so it is also excluded. Preferences,
Keychain credentials, Teams group data and application support remain outside
the exact approved rules. More app-cache rules require their own vendor path,
version and non-target evidence; broad `~/Library/Caches` sweeps are not part
of the Mac App Store product.
