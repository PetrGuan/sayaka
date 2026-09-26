# Cloud, office, utility and virtualization cleanup boundary (issue 143)

This is the Mac App Store catalog for the application families below. The
directly relevant supported app-cache examples are Classic Teams and Discord,
added under issue 140; developer-tool download caches are documented
separately in [the native binding catalog](BINDINGS.md). The
`developer_caches` preview reports each excluded operation, while its candidate
list and execution plan remain an exact allowlist of separately documented
rules. A name containing `cache` does not establish rebuildability.

| Family and version scope | Exact path or storage class | App Store decision |
| --- | --- | --- |
| Classic Microsoft Teams for macOS only; New Teams excluded | `~/Library/Caches/com.microsoft.teams` | Supported by rule `com.microsoft.teams.classic_cache.macos` v1. The exact leaf is review-only, needs a user-granted root and an idle process census, and is revalidated before Trash. Application Support, credentials and group data are non-targets. |
| Discord stable desktop for macOS 11 or later; Canary, PTB and sandboxed variants excluded | `~/Library/Application Support/discord/Cache` | Supported by rule `com.discord.stable.cache.macos` v1. The exact leaf is review-only and requires the same grant, idle-state and revalidation checks. Sibling settings, downloads and credentials are non-targets. |
| Dropbox desktop, non-File Provider setup (vendor documentation current 2026-04-17) | `.dropbox.cache` in the Dropbox root | Excluded: also stages uploads and downloads; a scan cannot prove synchronization is complete. File Provider setups have an OS-managed cache location, which is likewise excluded. |
| OneDrive for Mac with Files On-Demand (Microsoft documentation current 2026-09-26) | Online-only files in the user's sync root | Excluded: placeholders are not locally reclaimable bytes and must not be downloaded for measurement. The sync root is never a cache rule. |
| Microsoft 365 Office document cache (Microsoft documentation current 2026-09-26) | Office-managed document cache; exact macOS path and version mapping are not established | Excluded: may hold pending uploads and reconciliation metadata. No path guess is promoted to a rule. |
| Docker Desktop for Mac (`Docker.raw` and older `Docker.qcow2` layouts, vendor documentation current 2026-09-26) | `~/Library/Containers/com.docker.docker/Data/vms/0/data/` or vendor-configured disk location | Excluded: the disk image stores containers and images, not disposable cache. Moving it to Trash would lose user data. |

Evidence:

- [Classic Teams exact-path guidance](https://learn.microsoft.com/en-us/answers/questions/4437348/i-deleted-classic-teams-from-my-mac-and-now-i-have) and [New Teams cache layout](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache)
- [Discord macOS troubleshooting guide](https://support.discord.com/hc/en-us/articles/31623498041623-Discord-Troubleshooting-Guide)
- [Dropbox cache documentation](https://help.dropbox.com/delete-restore/cache-folder)
- [OneDrive Files On-Demand on Mac](https://learn.microsoft.com/en-us/sharepoint/files-on-demand-mac)
- [Office document cache size and pending uploads](https://support.microsoft.com/en-us/office/collab-files/managing-office-document-cache-size)
- [Docker Desktop for Mac disk image FAQ](https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/)
- [Docker Desktop backup and restore](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/)

The scanner does not open file content to measure it. Its macOS stat path
recognizes dataless objects, does not descend dataless directories, and never
turns a dataless directory into a cleanup candidate. The two app-cache rules
in the table are documented in [the app-cache contract](USER_APP_CACHE_RULES.md).
Execution rechecks the rule path, process state, cloud/dataless attributes and
native Trash eligibility. Docker disk images, sync roots, Office document
caches and other utility data are not inferred from names or size; a new rule
needs its own version, ownership, rebuildability and non-target evidence.
