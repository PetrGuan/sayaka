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
| Activity | Running `Microsoft Teams.app` or unavailable process census blocks selection and execution; state is checked again at approval and immediately before the move |
| Non-targets | Application Support, New Teams container/group data, preferences, Keychain credentials and logs are never part of this rule |
| Scope | The sandbox still needs explicit user authorization for the folder or an ancestor; a denied or partial scan cannot become an executable selection |

[Microsoft Teams cache guidance](https://learn.microsoft.com/en-us/answers/questions/4437348/i-deleted-classic-teams-from-my-mac-and-now-i-have) names the Classic Teams path. [Microsoft's New Teams cache article](https://learn.microsoft.com/troubleshoot/microsoftteams/teams-administration/clear-teams-cache) locates its data in protected Containers and Group Containers, outside this rule.

The nearby fixture assertions cover a positive exact-path candidate and
negative Application Support, group and preference paths. Existing native
execution guards reject symlinks, dataless placeholders, cloud roots, changed
identities, unsupported volumes and incomplete coverage. Real application
activity and Trash effects still need owner-side isolated native observation;
the automated unit/UI suites are intentionally not run by agents.

Generic logs and crash reports remain non-targets: their ownership and
diagnostic value cannot be established from a directory name. The broader
Mole-style user/app cache and log catalog remains an open expansion area;
each new rule needs its own vendor path, version and non-target evidence.
