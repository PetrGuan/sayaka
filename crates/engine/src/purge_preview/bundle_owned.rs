// SPDX-License-Identifier: MPL-2.0
//! Retained, independently revalidated ownership evidence. No filesystem effects.
use super::*;
use crate::app_inventory::{StringState, read_bundle_identifier_with_digest};
use sayaka_platform_macos::related::{self, PathWitness};
use std::sync::Arc;
use std::time::Instant;

pub const RULE_ID: &str = "org.sayaka.bundle_owned_cache.v1";
const NAMESPACES: &[&str] = &[
    "com.apple",
    "group",
    "com.crowdstrike",
    "com.sentinelone",
    "com.sentinel-labs",
    "com.eset",
    "com.jamf",
    "com.jamfsoftware",
    "com.paloaltonetworks",
    "com.1password",
    "com.agilebits",
    "com.lastpass",
    "com.dashlane",
    "com.bitwarden",
    "com.keepassx",
    "org.keepassx",
    "org.keepassxc",
    "com.authy",
    "com.yubico",
    "com.nordvpn",
    "com.expressvpn",
    "com.protonvpn",
    "net.protonvpn",
    "com.tunnelbear",
    "com.surfshark",
    "net.ivpn",
    "net.mullvad",
    "com.wireguard",
    "net.tunnelblick",
    "net.openvpn",
    "com.openvpn",
    "io.tailscale",
    "com.dropbox",
    "com.getdropbox",
    "com.google.googledrive",
    "com.microsoft.syncreporter",
    "com.backblaze",
    "com.spotify",
    "com.adobe",
    "com.ollama",
    "ai.ollama",
    "com.lmstudio",
    "ai.lmstudio",
    "page.jan",
    "com.drawthings",
    "com.divamgupta.diffusionbee",
    "com.utmapp",
    "com.parallels",
    "com.vmware",
    "dev.orbstack",
    "com.orbstack",
    "com.docker",
    "org.virtualbox",
];
const PREFIXES: &[&str] = &[
    "com.cisco.anyconnect",
    "com.cisco.secureclient",
    "com.microsoft.onedrive",
    "com.box.desktop",
];
fn denied(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    NAMESPACES.iter().any(|n| {
        lower == *n
            || lower
                .strip_prefix(n)
                .is_some_and(|tail| tail.starts_with('.'))
    }) || PREFIXES.iter().any(|p| lower.starts_with(p))
}
fn eligible_id<'a>(path: &'a Path, home: &Path) -> Option<&'a str> {
    let id = crate::app_orphans::cache_bundle_id(path, &home.join("Library/Caches"))?;
    (id.len() <= 255
        && !denied(id)
        && !sayaka_platform_macos::cache_locations::permitted_cache_location(path))
    .then_some(id)
}

struct Owner {
    physical: PathBuf,
    bundle: PathWitness,
    manifest: PathWitness,
}
pub struct Proof {
    id: String,
    cache: PathWitness,
    owners: Vec<Owner>,
    digest: [u8; 32],
    policy: CachePolicy,
}
impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleOwnedProof")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl Proof {
    pub(super) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub(super) fn display(&self) -> Vec<CacheOwner> {
        self.owners
            .iter()
            .map(|o| CacheOwner {
                display_name: o
                    .bundle
                    .path()
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                bundle_path: o.bundle.path().to_owned(),
            })
            .collect()
    }
    pub(crate) fn revalidate(&self, path: &Path, home: &Path) -> Result<(), String> {
        if self.cache.path() != path || eligible_id(path, home) != Some(self.id.as_str()) {
            return Err("resource_changed: cache ownership shape".into());
        }
        self.cache
            .revalidate()
            .map_err(|_| "resource_changed: cache identity".to_owned())?;
        for owner in &self.owners {
            owner
                .bundle
                .revalidate()
                .map_err(|_| "resource_changed: owner bundle".to_owned())?;
            owner
                .manifest
                .revalidate()
                .map_err(|_| "resource_changed: owner manifest".to_owned())?;
        }
        crate::clean_policy::guard_all(&self.policy.config, &self.policy.snapshot)
            .map_err(|e| e.to_string())?;
        if self.policy.excludes(path) {
            return Err("cache is protected by policy".into());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let fresh = capture(path, home, &self.policy, deadline)?
            .ok_or("resource_changed: owner removed")?;
        if fresh.digest != self.digest {
            return Err("resource_changed: owner evidence".into());
        }
        if fresh.idle(deadline)? {
            Ok(())
        } else {
            Err("owner application is running".into())
        }
    }
    fn idle(&self, deadline: Instant) -> Result<bool, String> {
        if Instant::now() >= deadline {
            return Err("owner activity budget exhausted".into());
        }
        if related::bundle_id_running(&self.id)
            .map_err(|e| format!("owner activity unknown: {e}"))?
        {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            return Err("owner activity budget exhausted".into());
        }
        let paths =
            related::executable_paths().map_err(|e| format!("owner activity unknown: {e}"))?;
        if Instant::now() >= deadline {
            return Err("owner activity budget exhausted".into());
        }
        if paths.iter().any(|p| {
            self.owners.iter().any(|o| {
                p.starts_with(o.bundle.path()) || live_path(p).starts_with(live_path(&o.physical))
            })
        }) {
            return Ok(false);
        }
        Ok(true)
    }
}
fn forbidden_bundle(path: &Path) -> bool {
    !path.is_absolute()
        || path.extension().is_none_or(|e| e != "app")
        || path.parent() == Some(Path::new("/"))
        || path.starts_with("/System")
        || path
            .components()
            .any(|p| matches!(p.as_os_str().to_str(), Some(".Trash" | ".Trashes")))
}
fn live_path(physical: &Path) -> PathBuf {
    physical
        .strip_prefix("/System/Volumes/Data")
        .map(|p| Path::new("/").join(p))
        .unwrap_or_else(|_| physical.to_owned())
}
/// Both lexical and no-follow physical aliases participate in protection.
pub fn ensure_disjoint(target: &Path, protected: &Path) -> Result<(), String> {
    if paths_are_related(target, protected) {
        return Err("cache overlaps protected state or policy".into());
    }
    let a = crate::related_uninstall::physical_location(target).map_err(|e| e.to_string())?;
    let b = crate::related_uninstall::physical_location(protected).map_err(|e| e.to_string())?;
    if paths_are_related(&a, &b) {
        return Err("cache physically overlaps protected state or policy".into());
    }
    Ok(())
}
fn policy_guard(path: &Path, policy: &CachePolicy) -> Result<(), String> {
    crate::clean_policy::guard_all(&policy.config, &policy.snapshot).map_err(|e| e.to_string())?;
    ensure_disjoint(path, &policy.config.directory)?;
    for excluded in &policy.snapshot.effective_exclusions {
        ensure_disjoint(path, excluded)?;
    }
    ensure_disjoint(
        path,
        &crate::journal::default_directory().map_err(|e| e.to_string())?,
    )?;
    Ok(())
}

fn capture(
    path: &Path,
    home: &Path,
    policy: &CachePolicy,
    deadline: Instant,
) -> Result<Option<Arc<Proof>>, String> {
    if Instant::now() >= deadline {
        return Err("owner discovery budget exhausted".into());
    }
    policy_guard(path, policy)?;
    let id = eligible_id(path, home)
        .ok_or("protected cache shape")?
        .to_owned();
    let cache = PathWitness::capture(path).map_err(|e| e.to_string())?;
    if !cache.is_directory() {
        return Err("cache is not a real directory".into());
    }
    let roots = crate::app_observation::roots(home, &[]).map_err(|e| e.to_string())?;
    let remaining = std::cell::Cell::new(10_000);
    let inventory = crate::app_observation::inventory(&roots, deadline, &remaining).map_err(|e| e.to_string())?;
    let observed = crate::app_observation::copies(&id, &inventory, deadline, &remaining).map_err(|e| e.to_string())?;
    let mut paths = observed.paths;
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Ok(None);
    }
    if paths.len() > 8 {
        return Err("owner count exceeds eight".into());
    }
    let mut owners = Vec::new();
    let mut hash = Sha256::new();
    hash.update(id.as_bytes());
    hash.update(cache.identity().0.to_le_bytes());
    hash.update(cache.identity().1.to_le_bytes());
    for path in paths {
        if forbidden_bundle(&path) || Instant::now() >= deadline {
            return Err("owner path or discovery budget refused".into());
        }
        let bundle = PathWitness::capture(&path).map_err(|e| e.to_string())?;
        if !bundle.is_directory()
            || forbidden_bundle(&live_path(
                &bundle.physical_path().map_err(|e| e.to_string())?,
            ))
        {
            return Err("owner is not an eligible app directory".into());
        }
        let manifest =
            PathWitness::capture(&path.join("Contents/Info.plist")).map_err(|e| e.to_string())?;
        let (field, digest, dev, ino) =
            read_bundle_identifier_with_digest(&path).map_err(str::to_owned)?;
        if field.state != StringState::Present
            || field.value.as_deref() != Some(&id)
            || manifest.identity() != (dev, ino)
        {
            return Err("owner manifest identity mismatch".into());
        }
        bundle.revalidate().map_err(|e| e.to_string())?;
        manifest.revalidate().map_err(|e| e.to_string())?;
        hash_path(&mut hash, &path);
        for (a, b) in [bundle.identity(), manifest.identity()] {
            hash.update(a.to_le_bytes());
            hash.update(b.to_le_bytes());
        }
        hash.update(digest);
        let physical = bundle.physical_path().map_err(|e| e.to_string())?;
        hash_path(&mut hash, &physical);
        owners.push(Owner {
            bundle,
            manifest,
            physical,
        });
    }
    if Instant::now() >= deadline {
        return Err("owner discovery budget exhausted".into());
    }
    cache.revalidate().map_err(|e| e.to_string())?;
    Ok(Some(Arc::new(Proof {
        id,
        cache,
        owners,
        digest: hash.finalize().into(),
        policy: policy.clone(),
    })))
}

pub(super) fn append(
    index: &ScanTree,
    home: &Path,
    policy: Option<&CachePolicy>,
    deadline: Option<Instant>,
    candidates: &mut Vec<DeveloperCacheCandidate>,
) -> Result<Vec<crate::scan::ScanIssue>, String> {
    let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
    let mut issues = Vec::new();
    let issue = |path: &Path, message: String| crate::scan::ScanIssue {
        path: Some(path.to_owned()),
        code: crate::scan::ScanCode::InvalidRoot,
        message,
        os_code: None,
    };
    let default;
    let policy = match policy {
        Some(p) => p,
        None => {
            default = CachePolicy::capture(
                crate::clean_policy::resolve_config_path(None).map_err(|e| e.to_string())?,
            )?;
            &default
        }
    };
    for entry in &index.report().entries {
        if entry.kind != ResourceKind::Directory
            || entry.dataless
            || policy.excludes(&entry.path)
            || eligible_id(&entry.path, home).is_none()
        {
            continue;
        }
        if Instant::now() >= deadline || candidates.len() >= 256 {
            issues.push(issue(
                &entry.path,
                "bundle-owned discovery budget exhausted".into(),
            ));
            break;
        }
        let proof = match capture(&entry.path, home, policy, deadline) {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(e) => {
                issues.push(issue(&entry.path, e));
                if issues.len() >= 128 {
                    break;
                }
                continue;
            }
        };
        if entry.identity
            != (FileIdentity::Unix {
                device: proof.cache.identity().0,
                inode: proof.cache.identity().1,
            })
        {
            issues.push(issue(
                &entry.path,
                "cache resource_changed during ownership discovery".into(),
            ));
            continue;
        }
        let idle = match proof.idle(deadline) {
            Ok(idle) => idle,
            Err(e) => {
                issues.push(issue(&entry.path, e));
                false
            }
        };
        let owner_app = proof.display();
        candidates.push(DeveloperCacheCandidate {
            tool:"bundle-owned", rule_id:RULE_ID, rule_version:1, ruleset_revision:DEVELOPER_CACHE_RULESET_REVISION,
            rule_kind:"bundle_owned", owner_app, owner_proof:Some(proof),
            links_not_followed:0, title:"Installed application cache", path:entry.path.clone(), location:"~/Library/Caches/<bundle-id>", location_kind:"directory", kind:"directory",
            rebuildability_note:"Ownership is inferred from installed applications, not exclusive use. Clearing may require downloads or sign-in and may lose offline or uncommitted contents. Other-user/root writers and external helpers are outside the activity proof.",
            user_product:false, cleanup_supported:idle, unsupported_reason:if idle {None} else {Some("owner application is running or activity is unknown")},
            logical_bytes:None, allocated_bytes:None, complete:index.summary(entry.id).is_some_and(|s|s.complete), modified_unix_ms:None, identity:entry.identity,
            activity:if idle {DeveloperCacheActivity::NotDetected} else {DeveloperCacheActivity::ApplicationActiveOrUnknown}, evidence:&[EvidenceSource {
                title: "Apple Library/Caches convention; installed ownership is an inference",
                url: "https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html",
                reviewed_utc: "2026-10-11", license_note: "Apple archived developer documentation; ownership separately verified from installed manifests",
            }],
        });
    }
    if Instant::now() >= deadline {
        issues.push(issue(
            &home.join("Library/Caches"),
            "bundle-owned discovery budget exhausted".into(),
        ));
    }
    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_volume_owner_alias_preserves_live_system_boundary() {
        assert!(!forbidden_bundle(&live_path(Path::new(
            "/System/Volumes/Data/Applications/Foo.app"
        ))));
        assert!(forbidden_bundle(&live_path(Path::new(
            "/System/Applications/Foo.app"
        ))));
        assert!(forbidden_bundle(&live_path(Path::new(
            "/System/Volumes/Data/Users/me/.Trash/Foo.app"
        ))));
        assert!(
            ensure_disjoint(
                Path::new("/Users/me/Library/Caches/com.example.App"),
                Path::new("/Users/me/Library/Caches/com.example.App/journal")
            )
            .is_err()
        );
    }
    #[test]
    fn protection_is_namespace_based_and_case_insensitive() {
        for id in [
            "com.apple.foo",
            "COM.SPOTIFY.CLIENT",
            "com.1password.desktop",
            "com.microsoft.OneDrive-mac",
            "ai.ollama.desktop",
            "org.virtualbox.app",
            "group.example.app",
        ] {
            assert!(denied(id));
        }
        assert!(!denied("com.example.spotify"));
        assert!(!denied("com.spotifyness.app"));
    }
    #[test]
    fn exact_rule_shapes_never_fall_back_to_generic() {
        let home = Path::new("/Users/fixture");
        for name in [
            "com.microsoft.teams",
            "com.apple.dt.Xcode",
            "com.example_bad.app",
            "com.two",
            "group.example.app",
        ] {
            assert!(eligible_id(&home.join("Library/Caches").join(name), home).is_none());
        }
        assert_eq!(
            eligible_id(
                Path::new("/Users/fixture/Library/Caches/com.example.App"),
                home
            ),
            Some("com.example.App")
        );
        assert!(forbidden_bundle(Path::new("/System/Applications/Foo.app")));
        assert!(forbidden_bundle(Path::new("/Users/me/.Trash/Foo.app")));
        assert!(!forbidden_bundle(Path::new("/Applications/Foo.app")));
    }
}
