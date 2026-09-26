# Cloud, office and virtualization cleanup boundary (issue 143)

This is the Mac App Store catalog for the application families below. The
current supported cleanup rule count for these families is **zero**. The
`developer_caches` preview reports each excluded operation, while its candidate
list and execution plan remain an exact allowlist of separately documented
rules. A name containing `cache` does not establish rebuildability.

| Family and version scope | Observed path or storage class | Decision |
| --- | --- | --- |
| Dropbox desktop, non-File Provider setup (vendor documentation current 2026-04-17) | `.dropbox.cache` in the Dropbox root | Excluded: also stages uploads and downloads; a scan cannot prove synchronization is complete. File Provider setups have an OS-managed cache location, which is likewise excluded. |
| OneDrive for Mac with Files On-Demand (Microsoft documentation current 2026-09-26) | Online-only files in the user's sync root | Excluded: placeholders are not locally reclaimable bytes and must not be downloaded for measurement. The sync root is never a cache rule. |
| Microsoft 365 Office document cache (Microsoft documentation current 2026-09-26) | Office-managed document cache; exact macOS path and version mapping are not established | Excluded: may hold pending uploads and reconciliation metadata. No path guess is promoted to a rule. |
| Docker Desktop for Mac (`Docker.raw` and older `Docker.qcow2` layouts, vendor documentation current 2026-09-26) | `~/Library/Containers/com.docker.docker/Data/vms/0/data/` or vendor-configured disk location | Excluded: the disk image stores containers and images, not disposable cache. Moving it to Trash would lose user data. |

Evidence:

- [Dropbox cache documentation](https://help.dropbox.com/delete-restore/cache-folder)
- [OneDrive Files On-Demand on Mac](https://learn.microsoft.com/en-us/sharepoint/files-on-demand-mac)
- [Office document cache size and pending uploads](https://support.microsoft.com/en-us/office/collab-files/managing-office-document-cache-size)
- [Docker Desktop for Mac disk image FAQ](https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/)
- [Docker Desktop backup and restore](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/)

The scanner does not open file content to measure it. Its macOS stat path
recognizes dataless objects, does not descend dataless directories, and never
turns a dataless directory into a cleanup candidate. The execution allowlist
must continue to reject cloud roots, dataless targets, and these storage
classes. No positive application cache rule is supplied here because the
available evidence does not establish an exact path, supported version,
rebuildability, idle-state proof and non-target boundary for one.
