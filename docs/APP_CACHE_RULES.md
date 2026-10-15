# App cache expansion contract — owner approved

Owner approved this contract on 2026-10-11. Reviewed sources: 2026-10-11. This is the approved contract for the
Developer ID, non-sandboxed macOS product. The two exact Adobe leaves and separately typed generic shape below are authorized for incremental implementation. Existing 19-rule admission
repair is separate and described in [PURGE_EXECUTION.md](PURGE_EXECUTION.md).
Approval is not native fixture acceptance or evidence of reclaimed space. Implement exact additions and bundle-owned discovery in
separate subsequent PRs, each independently reviewed before merge.

## Approved decisions

| Decision | Proposed resolution |
| --- | --- |
| Existing-rule repair | Direct native repair of the already documented 19 rules; no extra engine rules. |
| Bundle-owned discovery | Accept the narrow contract below; always Review, never preselected. |
| Protection data | Static, reviewed namespace table below; visible in documentation/help, not user-editable. User exclusions may add protection but cannot remove built-in protection. |
| Logs/diagnostics | Excluded, including age-based DiagnosticReports cleanup. |
| Containers | Excluded in v1. A future proposal must separately address other-app-data prompts and data semantics. |
| Electron evidence | Vendor cache-clear instructions plus a version-specific, verified path mapping can support a future rule. The Electron/Chromium convention alone cannot. Unverified candidate leaves below remain unsupported after this proposal is approved. |

## Exact-rule second batch

Two proposed rules only. Approval of this document authorizes these two precise
native shapes, not the containing Adobe/Common directory or a configurable path.
Both remain Review by default and require explicit selection. A later rule needs
its own evidence review and native table change.

| Proposed rule ID (v1) | Exact account-home-relative directory | Version/evidence boundary | Consequence and non-targets |
| --- | --- | --- | --- |
| `com.adobe.common.media_cache_files.macos` | `Library/Application Support/Adobe/Common/Media Cache Files` | Default shared cache layout documented in current Premiere desktop guidance (January 2026), corroborated by Media Encoder guidance (March 2026). This is a layout-qualified rule, not a claim about all past/future versions. | Generated conformed audio/index/peak data must rebuild from source media; reopening projects may be slower. No source footage, project files, previews beside footage, exports, customized cache locations, or sibling Adobe data. |
| `com.adobe.common.media_cache_database.macos` | `Library/Application Support/Adobe/Common/Media Cache` | Same documented default layout; Adobe explicitly distinguishes the cache database from generated files. | Index/database links must rebuild. Same exclusions; no parent-directory cleanup. |

Evidence, reviewed 2026-10-11:

- [Premiere: manage media cache](https://helpx.adobe.com/premiere/desktop/troubleshooting/media-issues/manage-media-cache.html)
  identifies the two folder names and explains regeneration from source media.
- [Premiere: playback troubleshooting](https://helpx.adobe.com/ie/premiere/desktop/troubleshooting/playback-issues/choppy-playback-and-poor-performance-issue.html)
  supplies the default macOS `Library/Application Support/Adobe/Common` location.
- [Media Encoder: shared media cache database](https://helpx.adobe.com/sg/media-encoder/desktop/encoding-and-exporting/media-cache-database.html)
  establishes shared writers: Premiere, After Effects and Media Encoder.

Activity admission must block **all shared writers**, not only Premiere:
complete effective-user executable census; exact executable names
`Adobe Premiere Pro`, `Adobe Premiere`, `After Effects`, `Adobe After Effects`,
`Adobe Media Encoder`, `aerender`, `dynamiclinkmanager`, `dynamiclinkmediaserver`;
executable-name prefixes `Adobe Premiere`, `Adobe After Effects`,
`Adobe Media Encoder`, `After Effects`, `dynamiclink`, `Adobe QT32 Server`,
`AdobeIPCBroker`; and executable paths within any observed bundle whose identifier
starts with `com.adobe.Premiere`, `com.adobe.AfterEffects`, or
`com.adobe.AdobeMediaEncoder` (ASCII-insensitive denial only).
Resolve those installed writer bundles through bounded native inventory and use
component-aware ancestry, not textual path prefixes. Unknown/incomplete process
or writer discovery blocks both rows. Implementation must refuse an unrecognized
writer layout rather than claim this list covers every Adobe version. Apply these
checks at preview, approval and each final native guard. Do not run Adobe commands.
Owner isolated acceptance must include each writer and its background helpers.

### Investigated candidates not authorized as exact rules

Each row is a negative decision about the proposed paths, not proof that a
vendor never uses caches there. Reviewed vendor documentation does not establish
the complete exact-leaf/version/rebuildability chain for these shapes.

| Candidate/version scope | Proposed leaves | Evidence reviewed and unresolved point |
| --- | --- | --- |
| Slack direct desktop; store variant excluded | `Application Support/Slack/{Cache,Code Cache,GPUCache}` | [Slack reinstall guidance](https://slack.com/intl/en-gb/help/articles/360048367814-Update-the-Slack-desktop-app) identifies the data root, but deleting all app data during reinstall does not prove each leaf's cache-only semantics. Exact leaf mapping remains unverified. |
| VS Code stable desktop; Insiders/portable excluded | `Application Support/Code/{Cache,Code Cache,GPUCache}` | These three leaves remain unverified. The separately documented CachedData and CachedExtensionVSIXs leaves below are now supported; no User, workspaces, logs or WebStorage. |
| Cursor desktop | `Application Support/Cursor/{Cache,Code Cache,GPUCache}` | These three leaves remain unverified. The two documented staff-supported leaves are covered separately below; VS Code ancestry alone is not proof. |
| Zoom desktop; version mapping unresolved | `Caches/us.zoom.xos` | [Zoom cache guidance](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0058835) describes an Application Support data location instead. That is not evidence for this leaf; do not substitute account data. |
| Figma desktop; current support layout | `Caches/com.figma.Desktop` | [Figma reset guidance](https://help.figma.com/hc/en-us/articles/22380853110551-Clear-the-Figma-desktop-app-cache) refers to `Application Support/Figma`, not this Caches leaf. No exact-rule promotion. A separate bundle-owned candidate may qualify only under the full contract below. |
| Brave desktop; stable default profile | `Caches/BraveSoftware/Brave-Browser/<profile>/{Cache,Code Cache,GPUCache}` | [Brave data deletion guidance](https://support.brave.app/hc/en-us/articles/4413256282765-How-do-I-delete-my-data-in-Brave) describes broader profile data. Separate cache-tree leaf mapping remains unverified. |
| Vivaldi desktop; default profile layout | `Caches/Vivaldi/<profile>/{Cache,Code Cache,GPUCache}` | [Vivaldi troubleshooting](https://help.vivaldi.com/desktop/troubleshoot/troubleshooting-issues/) explains in-app cache clearing, not this filesystem mapping. |
| Arc desktop for macOS; profile layout unresolved | vendor cache root / `<profile>/{Cache,Code Cache,GPUCache}` | [Arc troubleshooting](https://resources.arc.net/hc/en-us/articles/25626856007959-How-to-Troubleshoot-Crashes-and-Performance-Issues-on-Arc-for-Desktop) documents in-app cache clearing, without an exact cache-root/leaf contract. Do not guess the vendor root. |
| Spotify desktop; configurable storage | `Caches/com.spotify.client` | [Spotify storage](https://support.spotify.com/us/article/storage-information/) distinguishes cache and offline downloads and permits relocation; it does not prove this path excludes offline content. Exact and generic admission both denied. |
| New Teams macOS | `Caches/com.microsoft.teams2` | [Microsoft Teams guidance](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache) names Containers and Group Containers. Neither is a target, and neither proves the proposed Caches path. |

These decisions do not narrow the existing Classic Teams, Discord, Chrome, Edge,
Firefox or developer rules. Unsupported exact evidence does not by itself forbid
a distinct generic Caches leaf if the bundle-owned contract permits it; static
protection and exact-rule reservations always take priority.

## `bundle_owned_cache_v1`

This is a candidate rule kind within `developer_caches`, **not a new effect
contract**. Keep `revalidated_cache_trash_v1`, the current same-preview digest,
1..32 item cap, exact `trash N caches` typed token and existing expiry. No empty
or stale approval; refresh creates a new preview and invalidates old selection.
No automatic retry, privilege fallback, permanent delete, or vendor command.

### Path, ownership and process proof

1. Derive home from `getpwuid_r` for the effective account; never `$HOME` or a host
   supplied arbitrary home. Only `<home>/Library/Caches/<bundle-id>` is eligible.
   Reuse `app_orphans::cache_bundle_id`: at least three nonempty dot-separated
   ASCII alphanumeric/hyphen labels, one path component, at most 255 bytes.
   No underscores, Unicode normalization, case folding for identity, or partial
   ID matching. All ancestors below home and the leaf must be real directories;
   retain no-follow identity witnesses and reject links, dataless/cloud objects,
   unsupported volumes or changed device/inode/type.
2. Query `NSWorkspace URLsForApplicationsWithBundleIdentifier:`. Reuse the
   `platform-macos::related` native helper added for related uninstall, including
   Objective-C exception conversion. Do not create a second FFI implementation.
   Require at least one installed `.app` whose bounded, no-follow Info.plist
   actually contains that exact case-sensitive CFBundleIdentifier. Empty,
   failed, stale, malformed or ambiguous results cannot establish ownership and
   are not labelled an orphan. Bundles at the filesystem root, under `/System`, or in Trash must not
   qualify. Root ownership alone does not disqualify an otherwise verified
   third-party app in `/Applications` (the bundle is read-only evidence). Reject symlinked, unreadable or unstable app/manifest paths.
3. Retain the complete verified owner set (1..8 apps, not a truncated display
   subset), bundle identities, manifest identities/content digests, and native
   paths in the in-memory session and plan digest. More results, a lookup budget
   failure or any result whose status cannot be established makes the row
   non-executable. Multiple installed copies are evidence for the same one cache
   directory, not separate targets. Never use displayed owner text as authority.
4. Combine `NSRunningApplication runningApplicationsWithBundleIdentifier:` with
   the complete effective-user executable census from the same native helper.
   Match executable paths against every retained installed bundle's component
   ancestry. Either probe reporting running or unknown blocks the row. Bound
   enumeration/time; permission errors, PID churn and unreadable executable paths
   are unknown, not idle. Other-user/root writers are outside this proof; disclose
   that limitation. No assertion that every external helper shares the bundle ID.
5. Repeat ownership and running checks during approval and immediately before
   each native move. Any owner-set/path/manifest identity change, removal or
   replacement refuses with `resource_changed`; unknown process state refuses
   with an explicit activity reason. Moving an app out of its retained path
   requires a new preview even when LaunchServices finds the same ID elsewhere.
6. Only move the approved leaf directory itself. A stable container identity
   does not freeze its descendants; external writers and the final pathname
   replacement race remain possible. Cache-directory ownership is an inference,
   not proof of exclusive use or guaranteed regeneration. Disclose re-download,
   re-login and loss of offline/uncommitted contents where applicable.

### Protection and precedence

Built-in protection below is static, versioned engine data. Compare deny entries
against an ASCII-lowercased copy of the ID so case variants cannot bypass denial;
retain original bytes for every path and owner comparison. Each namespace entry
matches the exact namespace or that namespace followed by `.`. Entries explicitly
marked `prefix` use byte prefix matching. No basename/keyword sweep is authorized.
This table governs **generic discovery**; it does not disable separately approved
exact developer rules such as Xcode. Their existing individual guards remain.

| Protected category | Initial denied namespaces / explicit prefixes |
| --- | --- |
| Apple/shared | `com.apple`, `group` |
| EDR/MDM/vendor workflow | `com.crowdstrike`, `com.sentinelone`, `com.sentinel-labs`, `com.eset`, `com.jamf`, `com.jamfsoftware`, `com.paloaltonetworks`; prefixes `com.cisco.anyconnect`, `com.cisco.secureclient` |
| Passwords/authentication | `com.1password`, `com.agilebits`, `com.lastpass`, `com.dashlane`, `com.bitwarden`, `com.keepassx`, `org.keepassx`, `org.keepassxc`, `com.authy`, `com.yubico` |
| VPN | `com.nordvpn`, `com.expressvpn`, `com.protonvpn`, `net.protonvpn`, `com.tunnelbear`, `com.surfshark`, `net.ivpn`, `net.mullvad`, `com.wireguard`, `net.tunnelblick`, `net.openvpn`, `com.openvpn`, `io.tailscale`; Cisco/GlobalProtect also covered above |
| Sync/backup | `com.dropbox`, `com.getdropbox`, `com.google.googledrive`, `com.microsoft.syncreporter`, `com.backblaze`; prefixes `com.microsoft.onedrive`, `com.box.desktop` |
| Offline media/shared media | `com.spotify`, `com.adobe`; Apple Music/Podcasts covered by `com.apple` |
| Local models | `com.ollama`, `ai.ollama`, `com.lmstudio`, `ai.lmstudio`, `page.jan`, `com.drawthings`, `com.divamgupta.diffusionbee` |
| Virtualization/container images | `com.utmapp`, `com.parallels`, `com.vmware`, `dev.orbstack`, `com.orbstack`, `com.docker`, `org.virtualbox` |

This is a conservative initial list, not a claim that all products in a category
can be recognized by ID. Unknown sensitive applications remain a limitation of
generic ownership inference. New protected namespaces require a reviewed data
change; no user override can force a denied row executable. The namespace facts
were cross-checked against the public [Mole protection catalog](https://github.com/tw93/Mole/blob/383a037f/lib/core/app_protection_data.sh)
for overlapping EDR/password/sync/model/VM categories; no shell code, wildcard
name policy or permanent deletion behavior is imported. Extra deny namespaces
above are proposed conservative policy, not claims of vendor endorsement.

Before generic discovery, reserve every existing exact-rule shape by native
rule ID, regardless of current eligibility or presence. An exact rule refused
for activity, policy or evidence must never fall back to generic admission.
Deduplicate by native path/identity, including overlapping scan roots. Apply the
shared `exclusions-v1` policy first and revalidate it at execution; all applicable
saved exclusions and active journal/policy directory overlaps remain protected.
Failed policy loading is not an empty exclusion set.

### Native boundary and bounded discovery

Add only the separately typed bundle-owned cache shape to the native static
allowlist after approval. It is not enabled by an arbitrary rule-ID string on the
existing exact path. Native admission independently derives home, verifies the
exact `Library/Caches/<id>` depth/grammar and refuses `com.apple`/`group` namespaces
case-insensitively. Preserve the standard no-follow, identity, materialization,
volume and protected-path guards; the engine's final callback supplies the
additional owner/process/policy proof. A caller declaration alone proves none
of those facts. No native wildcard for Application Support or Containers.

Discovery adds only `Library/Caches` to `sayaka_purge_cache_scan_roots_v1`, preserving
at most 64 returned roots and at most 16 components per root. Enumerate only its
direct children for generic attribution. Proposed ceilings: 10,000 entries,
256 candidate rows, 8 installed owners per ID, 1 MiB per Info.plist and 30 seconds
for the discovery/ownership pass; use the existing separately bounded size scan.
Any exhausted discovery/metadata/process budget marks the preview incomplete and
all its rows non-executable. Unknown/partial size remains nullable with a reason;
it never becomes zero. Size probes must not materialize cloud content. Bounded
errors must distinguish absent, protected, inaccessible and incomplete evidence.

### ABI, selection and history compatibility

Candidate JSON may add `rule_kind` (`exact` or `bundle_owned`) and `owner_app`
(array of 1..8 `{display_name, bundle_path: NativePath}` values for generic rows;
exact rows use an empty array). Use `org.sayaka.bundle_owned_cache.v1` as the
stable generic rule ID with rule version 1; exact IDs remain unchanged. Existing
App DTOs must tolerate these additive keys, while new validation accepts this
specific ID and validates owner paths/counts before rendering. Increment the
cache ruleset revision for each behavior expansion and include all retained
owner evidence in preview identity; no caller can manufacture it in execute input.

Journal schema stays 5 with exactly the current item key set. Ownership evidence
stays in the retained capability; no new journal fields are silently added.
History keeps exact native paths, destinations, outcomes and recovery evidence.
Never count skipped/unknown items or missing size as successful cleanup. Both old
and updated App history readers must still decode schema 5. Tests for schema and
DTO compatibility are compiled but not run by agents.

App behavior: all generic rows are Review and never automatically selected, even
when idle/complete/executable. Display owner names as evidence (all 1..8, escaped
and selectable for detail) and the complete exact selected path. Required copy:

- English: “Inferred from {App}'s cache directory. Clearing it may require downloading data again or signing in again.”
- 简体中文：“根据 {App} 的缓存目录推断归属。清理后可能需要重新下载数据或重新登录。”
- 日本語：“{App} のキャッシュディレクトリから推定しています。削除後、データの再ダウンロードや再ログインが必要になる場合があります。”

Reject selection above 32 with a visible limit and leave the selection unchanged;
do not silently truncate or automatically split one approval into multiple jobs.
The size explanation must say that installed-app-inferred caches are included,
that the amount is logical size, and that Trash movement is not reclaimed space.
Keep explicit approval and existing AppKit exception boundaries after awaits.

## Deliberate non-targets

No name/keyword sweep of `~/Library/Caches`, no general `Google`/`Yarn` root,
no generic Apple/shared cache, Group Containers or Containers. Non-sandboxed
shipping does not turn sandbox app data or other-app-data prompts into cache
permission. No logs or DiagnosticReports (including Zoom's support evidence),
no orphan cache execution, Preferences, Keychain, Cookies, HTTPStorages, WebKit,
or Application Support except individually approved leaves. No `/Library/Caches`,
`/private/var/folders`, elevated cleanup or vendor self-clean commands.

Use accurate unsupported explanations in the next implementation PR: New Teams
is excluded for container/shared identity/settings semantics and macOS data access
prompts; Safari website data is outside the exact cache contract; Homebrew's own
cleanup command is outside the allowed effect class, while its exact downloads
leaf remains supported. These decisions do not depend on an App Store sandbox.

## Validation and rollout

PR 1 repairs existing native shapes; App pin PR 1b follows. This proposal is PR 2
and must receive owner approval before merge or new-rule implementation. PR 3
adds only the two approved Adobe leaves (and accurate unsupported copy); PR 4
adds generic discovery/ownership/native shape; PR 5 adds App presentation and pin.
Each implementation PR gets different-model independent review and compile-only
validation. No agent-run unit/UI suites or native Trash acceptance.

Owner isolated acceptance: existing Discord idle/running/restarted cases; two
Chrome profiles and SingletonLock; Firefox parent.lock; each Adobe writer and
helper blocks both leaves; verified ordinary installed app appears Review/off;
running/unknown/uninstalled/renamed/replaced owner refuses; symlink/ancestor/leaf
replacement refuses; deny namespaces/exclusions/state overlap refuse; exact-rule
refusal cannot fall back; 33-item selection is explicit; schema 5 history remains
readable. Use disposable data with backups and inspect every outcome; record
observations separately from build results. No real-user-data deletion is needed
for agent validation. Native acceptance and any residual limitations must be
reported before describing new coverage as verified.

### Exact batch implementation

Ruleset revision 5 adds the two Adobe leaves to both engine and native tables.
A bounded native app inventory and complete effective-user process census guard
all shared writers at preview, approval and final revalidation. Unknown writer
metadata/layout is a refusal. Test sources are compiled only; native acceptance
is pending. Generic discovery and App presentation follow in separate PRs.

### Bundle-owned core implementation

Ruleset revision 6 implements the separately typed generic native shape and
additive candidate `rule_kind` / `owner_app` fields. The direct-child discovery
policy cannot descend into unknown trees, including directories created after
enumeration. Exact rules reserve their shapes even when inactive/ineligible.
Ownership retains no-follow bundle/manifest/cache witnesses and a digest; all
saved exclusion roots and physical state/config overlaps are protected. Unknown
owner evidence is a bounded scan issue and makes the preview incomplete; running
owners are visible but non-executable. Every retained owner is rechecked before
approval and at the final native guard. Other-user/root/external-helper writers
and the final pathname race remain limitations. Schema 5 keys are unchanged.

Compilation and independent review do not establish native Trash acceptance.
The App presentation/pin is a separate implementation PR.

### System Safari inventory observation (owner approved 2026-10-11)

The shared inventory may observe the exact signed system Safari link through the
narrow retained evidence rule in `ORPHAN_EXECUTION.md`'s approved system Safari
amendment. This only prevents an OS-provided link from making all copy coverage
unknown. It never admits a symlinked cache owner/target or an Apple-owned cache;
all existing owner/target restrictions remain. The held system evidence is
revalidated with the preview proof, and other links still make coverage unknown.

## VS Code stable default cache leaves (2026-10-14)

Two exact directory rules extend the existing revalidated cache Trash contract:
`com.microsoft.vscode.cached_data.macos` and
`com.microsoft.vscode.extension_vsix_cache.macos`, at the passwd-home suffixes
`Library/Application Support/Code/CachedData` and
`Library/Application Support/Code/CachedExtensionVSIXs` respectively.

Evidence combines Microsoft's official stable macOS data-root documentation
with MIT-licensed VS Code 1.104.3 source for the leaf mapping and behavior
(reviewed 2026-10-14), not generic Electron naming. The source alone uses
product.nameShort and does not establish the branded root:
- [official clean-uninstall data locations](https://code.visualstudio.com/docs/setup/uninstall#clean-uninstall)
  explicitly identifies `$HOME/Library/Application Support/Code` on macOS.
  This is evidence for the root name only, NOT permission to delete that root or
  its other user data. The 1.104.3 source below establishes the two cache leaves.
- [macOS default user-data mapping](https://github.com/microsoft/vscode/blob/1.104.3/src/vs/platform/environment/node/userDataPath.ts).
- [compiled cache path and creation](https://github.com/microsoft/vscode/blob/1.104.3/src/main.ts).
- [product cleanup of old compiled caches](https://github.com/microsoft/vscode/blob/1.104.3/src/vs/code/electron-utility/sharedProcess/contrib/codeCacheCleaner.ts).
- [extension download cache path](https://github.com/microsoft/vscode/blob/1.104.3/src/vs/platform/environment/common/environmentService.ts).
- [download on cache miss and eviction](https://github.com/microsoft/vscode/blob/1.104.3/src/vs/platform/extensionManagement/node/extensionDownloader.ts).
- [Microsoft's VSIX cache validation instructions](https://github.com/microsoft/vscode/issues/99873).

This is a default-layout qualification, not a promise for every product version.
Moving compiled data can slow the next startup. Moving VSIX downloads requires
redownloading packages and can prevent offline reinstalls; installed extensions
are outside these leaves. The App must offer these as Review, not preselected.
User, workspace state, logs, extensions, Cache, Code Cache, GPUCache, Insiders,
portable/custom data roots and derivatives such as Cursor remain excluded.

Preview and pre-move engine guards reject active or unknown process census.
Executable basenames Electron, Code, code, code-tunnel and node, and Code Helper
or Code - Insiders Helper prefixes block both leaves. Blocking generic Electron
and Node is deliberately conservative, including renamed bundles/CLI writers;
it may also block unrelated apps. No process is terminated. Native allowlisting
independently admits only the two leaves; existing home anchoring, complete scan,
hard-link accounting, no-follow/cloud checks, exclusions, identity revalidation,
typed approval and Trash-only journal semantics remain unchanged.

Build and compile-only evidence do not establish native cleanup acceptance.

## Cursor default cache leaves (2026-10-14)

The exact rules `com.cursor.cached_data.macos` and
`com.cursor.extension_vsix_cache.macos` admit only passwd-home
`Library/Application Support/Cursor/CachedData` and
`Library/Application Support/Cursor/CachedExtensionVSIXs`.

[Cursor's official staff reply](https://forum.cursor.com/t/unable-to-load-any-extensions-2-5-26/153436/8)
by deanrie on 2026-03-03 explicitly lists both macOS paths as cache-only cleanup
and distinguishes it from deleting settings/data. The [public topic metadata](https://forum.cursor.com/t/153436.json)
identifies post 8 as `staff: true`, `primary_group_name: CursorStaff` (checked
2026-10-14). The evidence concerns the 2.5.26 default layout; it does not establish
all future versions or custom data roots. No vendor commands are executed.

Both leaves are Review-only in the App, never automatically selected. Explain
startup rebuilding and possible package redownload/offline reinstall cost.
Settings, chats, User/workspace storage, installed extensions, logs, other cache
leaves, custom roots and other products are excluded. No whole Cursor data-root
cleanup is allowed. Preview, approval and last native revalidation deny active or
unknown writers: Cursor, cursor, cursor-agent, Electron, node, and Cursor Helper
prefixes. Generic Electron/Node denial is deliberately conservative and can block
unrelated apps; never terminate a process to enable cleanup.

Existing complete scan, hard-link accounting, no-follow, cloud/identity checks,
exclusion policy, native exact allowlist and typed Trash-only approval remain.
Native cleanup acceptance is separate from builds and compile-only checks.

### IntelliJ IDEA 2026.1 embedded browser cache (2026-10-14)

The exact native and engine rule `com.jetbrains.intellij.2026_1.jcef_cache.macos`
permits only `~/Library/Caches/JetBrains/IntelliJIdea2026.1/jcef_cache` under the
passwd home. [JetBrains support](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076)
identifies this macOS example and instructs users to quit the IDE and Toolbox
before removing the embedded Chromium cache. The scope is the documented default
2026.1 layout, not all JetBrains products or versions. There is no wildcard.

The App must show Review, unchecked, and disclose possible embedded-page reloads
and sign-in prompts. Projects, settings, plugins, Local History, IDE indexes,
other sibling directories, custom roots and other product/version roots are not
targets. Cache reconstruction and sign-in behavior still need owner acceptance;
build/compile evidence is not destructive runtime acceptance.

Activity is checked again at the existing prepare/approval/last-native boundaries:
`idea`, `idea64`, generic `java`, `jetbrains-toolbox` and its helpers; executable
prefixes `jcef`, `JCEF`, `cef_server`, `IntelliJ`, `JetBrains`, `jetbrains-toolbox`. Generic JVM
and helper matches may conservatively block cleanup for unrelated applications.
An incomplete process census blocks execution. Complete scan, hard-link accounting,
policy exclusions, no-follow path validation, explicit typed approval and Trash-only
execution remain unchanged. Ruleset revision is 7; wire/journal contracts are unchanged.

Launcher evidence: [JetBrains command-line support](https://intellij-support.jetbrains.com/hc/en-us/articles/360011901879-How-to-start-IDE-from-the-command-line) names `idea`; [JBCefApp source](https://github.com/JetBrains/intellij-community/blob/master/platform/ui.jcef/jcef/JBCefApp.java) names `jcef Helper`. Generic `java` and `cef_server` guards also cover standalone JVM/remote Chromium writers.

### DataGrip 2026.1 embedded browser cache (2026-10-14)

Exact rule `com.jetbrains.datagrip.2026_1.jcef_cache.macos` permits only
`~/Library/Caches/JetBrains/DataGrip2026.1/jcef_cache` under the passwd home.
[JetBrains DBE-26220](https://youtrack.jetbrains.com/issue/DBE-26220) prescribes
removing this leaf for the Geo Viewer failure in DataGrip 2026.1.3/2026.1.4.
This qualifies the default 2026.1 directory layout, not all versions/products.
[JetBrains JCEF guidance](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076)
requires quitting the IDE and Toolbox first. Embedded pages may reload or require
sign-in again; the App must present Review, unchecked.

SQL files, database connection configuration, projects, plugins, Local History,
IDE indexes, sibling directories, custom roots and other versions are excluded.
There is no wildcard or database operation. Process checks block `datagrip`,
generic `java`, `jetbrains-toolbox` and its helper; prefixes `jcef`, `JCEF`,
`cef_server`, `DataGrip`, `JetBrains`, `jetbrains-toolbox` also block. Unknown census
fails closed; generic JVM/helper matches deliberately permit false positives.
The [official launcher reference](https://www.jetbrains.com/help/datagrip/cli-commands-for-data-sources.html)
confirms `Contents/MacOS/datagrip`. Existing prepare/approval/final revalidation,
complete scan, hard-link accounting, protected paths, no-follow checks, typed
approval and Trash-only handling remain unchanged. Ruleset 8; no ABI/journal change.
Build/compile checks do not establish native cleanup or DataGrip behavior; owner
acceptance is still needed. No real cache removal is part of implementation.

### WebStorm 2026.2 embedded browser cache (#140, reviewed 2026-10-14)

Only `~/Library/Caches/JetBrains/WebStorm2026.2/jcef_cache` is added, using
`com.jetbrains.webstorm.2026_2.jcef_cache.macos` (`tool: webstorm-jcef`).
Evidence combines the [official WebStorm 2026.2 directory reference](https://www.jetbrains.com/help/webstorm/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
with [JetBrains JCEF removal guidance](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076).
The former documents the macOS system root, which also contains Local History;
the latter identifies only the jcef_cache leaf and requires exiting IDE and
Toolbox. No blanket system-root cleanup or wildcard version matching is allowed.
Other versions/products/custom roots, projects, settings, plugins, IDE indexes,
Local History and sibling directories are excluded. Embedded pages may reload or
require signing in again; this is unchecked Review, not automatic selection.

The `webstorm` launcher is documented in [JetBrains support](https://intellij-support.jetbrains.com/hc/en-us/community/posts/4408054265106-Webstorm-won-t-start-on-Mac).
Process protection blocks webstorm, generic java, jetbrains-toolbox and its helper,
and prefixes jcef, JCEF, cef_server, WebStorm, JetBrains, jetbrains-toolbox.
Unknown census blocks cleanup; generic JVM/helper matches can conservatively block
unrelated apps. Complete scan, hard-link accounting, policy/no-follow checks,
repeated execution revalidation, typed approval, Trash-only behavior and licensing
remain unchanged. No ABI/journal change. Build/compile-only evidence is not native
cleanup or subsequent WebStorm behavior acceptance; no real cache was removed.

Ruleset revision is 9. Hosts must use the exact rule ID for product-specific copy.

### PyCharm 2026.2 embedded browser cache (#140, reviewed 2026-10-15)

Exact rule `com.jetbrains.pycharm.2026_2.jcef_cache.macos` (`tool: pycharm-jcef`)
adds only `~/Library/Caches/JetBrains/PyCharm2026.2/jcef_cache`.
The [PyCharm 2026.2 directory reference](https://www.jetbrains.com/help/pycharm/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
confirms the default macOS system root; [JetBrains JCEF guidance](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076)
identifies the leaf and requires exiting the IDE and Toolbox.
[PyCharm cache invalidation documentation](https://www.jetbrains.com/help/pycharm/invalidate-caches.html)
explicitly includes embedded-browser cookies. This is unchecked Review: embedded
page preferences/cookies may reset and pages may reload or require sign-in.

No wildcard, PyCharmCE or other versions/products/custom roots. Projects, Python
environments, notebooks, settings, plugins, IDE indexes, Local History and sibling
directories are excluded. The [official launch guide](https://intellij-support.jetbrains.com/hc/en-us/articles/360011901879-How-to-start-IDE-from-the-command-line)
confirms the pycharm executable. Protection blocks pycharm, generic java,
jetbrains-toolbox and helper, plus jcef/JCEF/cef_server/PyCharm/JetBrains/
jetbrains-toolbox prefixes. Unknown census blocks cleanup; generic JVM matches
can conservatively block unrelated apps. Existing complete scan, hard-link
accounting, policy/no-follow checks, typed approval, repeated execution
revalidation, Trash-only behavior and licensing remain unchanged. No ABI/journal
change. Native cleanup/recreation still needs owner acceptance; no real cache
removal or unit/UI test execution is part of this implementation.

Ruleset revision is 10. Hosts must match the exact rule ID for specific copy.

### GoLand 2026.2 embedded browser cache (#140, reviewed 2026-10-15)

Only `~/Library/Caches/JetBrains/GoLand2026.2/jcef_cache` is added, via
`com.jetbrains.goland.2026_2.jcef_cache.macos` (`tool: goland-jcef`).
[GoLand 2026.2 directory documentation](https://www.jetbrains.com/help/go/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
confirms the default macOS root. [JetBrains JCEF removal guidance](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076)
identifies the leaf and requires quitting IDE and Toolbox.
[GoLand invalidation documentation](https://www.jetbrains.com/help/go/invalidate-caches.html)
confirms browser cookies are included. This is unchecked Review; embedded-page
cookies/preferences may reset and pages may reload or require signing in again.

Other versions/products/custom roots, projects, Go SDKs, Go module/build caches,
settings, plugins, indexes, Local History and sibling directories are not targets.
No wildcard or whole-system-directory removal is allowed.
The [official launcher guide](https://intellij-support.jetbrains.com/hc/en-us/articles/360011901879-How-to-start-IDE-from-the-command-line)
confirms goland. Activity checks block goland, generic java, Toolbox and helper,
plus jcef/JCEF/cef_server/GoLand/JetBrains/jetbrains-toolbox prefixes. Unknown census
fails closed; generic JVM/helper matches can block unrelated apps conservatively.
Complete scan, hard-link accounting, protected paths, no-follow, typed approval,
repeated revalidation, Trash-only behavior and licensing are unchanged. No
ABI/journal change. Native cleanup and subsequent GoLand behavior still require
owner acceptance. No real cache deletion or unit/UI tests are performed here.

Ruleset revision is 11; hosts must match exact rule ID for product-specific copy.

### PhpStorm 2026.2 embedded browser cache (#140, reviewed 2026-10-15)

Exact rule `com.jetbrains.phpstorm.2026_2.jcef_cache.macos` (`tool: phpstorm-jcef`)
adds only `~/Library/Caches/JetBrains/PhpStorm2026.2/jcef_cache`.
[PhpStorm 2026.2 directory documentation](https://www.jetbrains.com/help/phpstorm/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
confirms the default macOS root. [JetBrains JCEF removal guidance](https://youtrack.jetbrains.com/articles/SUPPORT-A-4076)
identifies the leaf and requires exiting IDE and Toolbox.
[PhpStorm invalidation documentation](https://www.jetbrains.com/help/phpstorm/invalidate-caches.html)
confirms embedded-browser cookies are included. Candidates stay unchecked Review;
cookies/preferences may reset and pages may reload or require sign-in.

No wildcard, other versions/products/custom roots, whole system directory,
projects, Composer dependencies/cache, PHP environments, settings, plugins, IDE
indexes, Local History or sibling directories. The
[official support response](https://intellij-support.jetbrains.com/hc/en-us/community/posts/7305600447890-Downloaded-PhpStorm-on-Mac-but-doesn-t-want-to-open)
identifies the phpstorm executable. Activity checks block phpstorm, generic java,
Toolbox and helper, plus jcef/JCEF/cef_server/PhpStorm/JetBrains/jetbrains-toolbox
prefixes. Unknown census fails closed; generic JVM/helper matches may block
unrelated apps conservatively. Full scan, hardlinks, policy/no-follow checks,
typed approval, repeated revalidation, Trash-only handling and licensing remain
unchanged. No ABI/journal change. Native cleanup and PhpStorm restart behavior
still require owner acceptance. No real cache deletion or unit/UI tests are run.

Ruleset revision is 12. Hosts must match exact rule ID for specific copy.
