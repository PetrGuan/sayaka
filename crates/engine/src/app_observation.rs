// SPDX-License-Identifier: MPL-2.0
//! Shared bounded copy observations for installed-cache and orphan contracts.
use crate::{
    app_inventory::{StringState, read_bundle_identifier_diagnostic},
    related_uninstall::absent_without_links,
};
use sayaka_platform_macos::{
    self as platform, orphans,
    related::{self, PathWitness},
};
use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    time::Instant,
};
mod diagnostics;
pub(crate) mod owner_budget;

// Large SDK/documentation trees still receive complete alias inspection.
pub(crate) const CACHE_INVENTORY_ENTRY_LIMIT: usize = 100_000;

fn error(s: impl ToString) -> io::Error {
    io::Error::other(s.to_string())
}
pub struct Bundle {
    pub path: PathBuf,
    pub id: String,
    pub bundle: PathWitness,
    pub manifest: PathWitness,
    pub digest: [u8; 32],
    system_safari: Option<platform::system_safari::Observation>,
    application_link: Option<platform::application_link::Link>,
}
impl Bundle {
    pub fn capture(path: &Path) -> io::Result<Self> {
        Self::capture_inner(path, None).map_err(|e| error(format!("application path={path:?}: {e}")))
    }
    fn capture_observed(path: &Path, control: &owner_budget::Control) -> io::Result<Self> {
        Self::capture_inner(path, Some(control))
            .map_err(|e| error(format!("application path={path:?}: {e}")))
    }
    fn capture_inner(path: &Path, control: Option<&owner_budget::Control>) -> io::Result<Self> {
        if path.extension().is_none_or(|e| e != "app") {
            return Err(error("copies_unknown: not an app"));
        }
        let bundle = bundle_operation(control, "bundle_witness", path, || orphans::exact(path))?;
        if !bundle.is_directory() {
            return Err(error("copies_unknown: not a directory"));
        }
        let manifest_path = path.join("Contents/Info.plist");
        let manifest = bundle_operation(control, "manifest_witness", &manifest_path, || orphans::exact(&manifest_path))?;
        let (id, digest, dev, ino) = bundle_operation(control, "manifest_read", &manifest_path,
            || read_bundle_identifier_diagnostic(path).map_err(error))?;
        let id = id
            .value
            .filter(|_| id.state == StringState::Present)
            .filter(|s| related::valid_bundle_id(s))
            .ok_or_else(|| error("copies_unknown: invalid manifest"))?;
        if manifest.identity() != (dev, ino) {
            return Err(error("resource_changed"));
        }
        bundle_operation(control, "bundle_revalidate", path, || bundle.revalidate())?;
        bundle_operation(control, "manifest_revalidate", &manifest_path, || manifest.revalidate())?;
        Ok(Self {
            path: path.to_owned(),
            id,
            bundle,
            manifest,
            digest,
            system_safari: None,
            application_link: None,
        })
    }
    fn capture_system_safari() -> io::Result<Self> {
        // Capture the manifest inside the retained Safari chain, then validate
        // its signature once. Later revalidation still performs the full check.
        let (observation, mut bundle) = platform::system_safari::Observation::capture_with(|path| {
            let bundle = Self::capture(path)?;
            if bundle.id != "com.apple.Safari" { return Err(error("copies_unknown: system Safari identity")); }
            Ok(bundle)
        })?;
        bundle.revalidate()?;
        bundle.system_safari = Some(observation);
        Ok(bundle)
    }
    fn capture_application_link(path: &Path, roots: &[Root]) -> io::Result<Self> {
        let link = platform::application_link::Link::capture(path).map_err(|e|
            error(format!("copies_unknown: application link source={path:?} target=unavailable: {e}")))?;
        let target = application_link_target(path, link.target());
        let result = (|| {
            let target = target.as_ref().map_err(error)?;
            let root = roots.iter().find(|r| !r.absent && target != &r.path && target.starts_with(&r.path))
                .ok_or_else(|| error("target outside application roots"))?;
            root.revalidate()?;
            // Bundle::capture refuses ALL further links, including ancestors.
            let bundle = Self::capture(target)?;
            link.revalidate()?;
            root.revalidate()?;
            bundle.revalidate()?;
            Ok(bundle)
        })();
        let mut bundle: Self = result.map_err(|e: io::Error| error(format!(
            "copies_unknown: application link source={path:?} target={:?} resolved={target:?}: {e}", link.target())))?;
        bundle.application_link = Some(link);
        Ok(bundle)
    }
    pub fn has_indirection(&self) -> bool {
        self.is_system_safari() || self.application_link.is_some()
    }
    pub fn is_system_safari(&self) -> bool { self.system_safari.is_some() }
    pub fn revalidate(&self) -> io::Result<()> {
        if let Some(observation) = &self.system_safari { observation.revalidate()?; }
        if let Some(link) = &self.application_link { link.revalidate()?; }
        self.bundle.revalidate()?;
        self.manifest.revalidate()?;
        let (id, digest, dev, ino) =
            read_bundle_identifier_diagnostic(&self.path).map_err(error)?;
        if id.state != StringState::Present
            || id.value.as_deref() != Some(&self.id)
            || digest != self.digest
            || (dev, ino) != self.manifest.identity()
        {
            return Err(error("resource_changed"));
        }
        if let Some(link) = &self.application_link { link.revalidate()?; }
        Ok(())
    }
}
fn bundle_operation<T>(
    control: Option<&owner_budget::Control>, operation: &'static str, path: &Path,
    action: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    match control {
        Some(control) => control.run(operation, path, action),
        None => action(),
    }
}

/// Lexical single-hop target only; filesystem resolution remains no-follow.
fn application_link_target(source: &Path, raw: &Path) -> io::Result<PathBuf> {
    use std::{os::unix::ffi::OsStrExt, path::Component};
    if raw.as_os_str().is_empty() || raw.as_os_str().as_bytes().len() >= 4096 {
        return Err(error("invalid link target"));
    }
    let joined = if raw.is_absolute() { raw.to_owned() } else {
        source.parent().ok_or_else(|| error("invalid link parent"))?.join(raw)
    };
    let mut target = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::RootDir => target.push("/"),
            Component::Normal(p) => target.push(p),
            Component::CurDir => (),
            // Refuse ambiguous traversal through a link before '..'. Supporting
            // sibling/child shortcuts needs no parent traversal on this path.
            Component::ParentDir | Component::Prefix(_) => return Err(error("unsupported parent traversal")),
        }
    }
    if !target.is_absolute() || target.as_os_str().as_bytes().len() >= 4096 {
        return Err(error("invalid resolved target"));
    }
    Ok(target)
}

pub struct Root {
    pub path: PathBuf,
    pub witness: PathWitness,
    pub absent: bool,
}
impl Root {
    pub fn capture(path: PathBuf, optional: bool) -> io::Result<Self> {
        if optional && absent_without_links(&path)? {
            let parent = path.parent().ok_or_else(|| error("invalid_root"))?;
            return Ok(Self {
                witness: orphans::exact(parent)?,
                path,
                absent: true,
            });
        }
        let witness = orphans::exact(&path)?;
        if !witness.is_directory() {
            return Err(error("invalid_app_root"));
        }
        Ok(Self {
            path,
            witness,
            absent: false,
        })
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.witness.revalidate()?;
        if self.absent && !absent_without_links(&self.path)? {
            return Err(error("resource_changed: root appeared"));
        }
        Ok(())
    }
}
pub fn roots(home: &Path, extra: &[PathBuf]) -> io::Result<Vec<Root>> {
    if extra.len() > 8 {
        return Err(error("too_many_app_roots"));
    }
    let mut paths = BTreeSet::from([PathBuf::from("/Applications"), home.join("Applications")]);
    paths.extend(extra.iter().cloned());
    paths
        .into_iter()
        .map(|p| {
            let optional = p == home.join("Applications");
            Root::capture(p, optional)
        })
        .collect()
}
pub fn inventory(
    roots: &[Root],
    deadline: Instant,
    remaining: &std::cell::Cell<usize>,
) -> io::Result<Vec<Bundle>> {
    inventory_observed(roots, deadline, remaining, &mut |_| Ok(()), false)
}

/// Called before traversal and after each captured application. Zero total is
/// intentional: enumeration has not yet established a trustworthy denominator.
pub(crate) fn inventory_with_progress(
    roots: &[Root], deadline: Instant, remaining: &std::cell::Cell<usize>,
    progress: &mut impl FnMut(usize) -> io::Result<()>,
) -> io::Result<Vec<Bundle>> {
    inventory_observed(roots, deadline, remaining, progress, true)
}
fn inventory_observed(
    roots: &[Root], deadline: Instant, remaining: &std::cell::Cell<usize>,
    progress: &mut impl FnMut(usize) -> io::Result<()>, allow_application_links: bool,
) -> io::Result<Vec<Bundle>> {
    let mut diagnostics = diagnostics::Diagnostics::new(deadline, if allow_application_links { CACHE_INVENTORY_ENTRY_LIMIT } else { 10_000 });
    progress(0)?;
    let mut result = Vec::new();
    for root in roots {
        diagnostics.run("root_revalidate", &root.path, || root.revalidate())?;
        if root.absent { continue; }
        let mut stack = vec![(root.path.clone(), 0, None)];
        diagnostics.queued_paths = 1;
        diagnostics.queued_bytes = root.path.as_os_str().len();
        while let Some((p, depth, discovered)) = stack.pop() {
            diagnostics.queued_paths -= 1;
            diagnostics.queued_bytes -= p.as_os_str().len();
            diagnostics.apps = result.len();
            progress(result.len())?;
            diagnostics.budget(&p, depth, None)?;
            if p.extension().is_some_and(|e| e == "app") {
                result.push(diagnostics.run("bundle_capture", &p, || Bundle::capture(&p))?);
                diagnostics.apps = result.len();
                progress(result.len())?;
                continue;
            }
            diagnostics.directories += 1;
            let mut directory = diagnostics.run("directory_capture", &p, || match discovered {
                Some(child) => platform::application_directory::Observation::capture_discovered(child),
                None => platform::application_directory::Observation::capture(&p),
            })?;
            while let Some(entry) = diagnostics.run("read_entry", &p, || directory.next_entry())? {
                let path = entry.path();
                diagnostics.entries += 1;
                diagnostics.budget(&path, depth, Some(remaining.get()))?;
                consume(remaining)?;
                if diagnostics.entries.is_multiple_of(128) { progress(result.len())?; }
                let ty = diagnostics.run("file_type", &path, || entry.file_type())?;
                if ty.is_symlink() {
                    if path == Path::new(platform::system_safari::ENTRY) {
                        result.push(diagnostics.run("system_safari", &path, Bundle::capture_system_safari)?);
                    } else if allow_application_links {
                        result.push(diagnostics.run("application_link", &path, || Bundle::capture_application_link(&path, roots))?);
                    } else {
                        return Err(error(format!("copies_unknown: symlink source={path:?} target={:?}", std::fs::read_link(&path))));
                    }
                    diagnostics.apps = result.len();
                    progress(result.len())?;
                    continue;
                }
                if !ty.is_dir()
                    && (!ty.is_file() || path.extension().is_some_and(|e| e == "app")
                        || diagnostics.run("finder_alias", &path, || directory.is_finder_alias_during_enumeration(&entry))?)
                {
                    return Err(error(format!("copies_unknown: alias or unsupported entry path={path:?}")));
                }
                if ty.is_dir() && (path.extension().is_some_and(|e| e == "app")
                    || !diagnostics.run("package_check", &path, || platform::is_package(&path))?) {
                    diagnostics.queued_paths += 1;
                    diagnostics.queued_bytes += path.as_os_str().len();
                    diagnostics.budget(&path, depth + 1, None)?;
                    let discovered = if path.extension().is_some_and(|e| e == "app") { None } else {
                        Some(diagnostics.run("directory_child", &path, || directory.discovered_directory(&entry))?)
                    };
                    stack.push((path, depth + 1, discovered));
                }
            }
            diagnostics.run("directory_revalidate", &p, || directory.finish())?;
        }
        diagnostics.run("root_revalidate", &root.path, || root.revalidate())?;
    }
    if let Some(root) = roots.last() { diagnostics.budget(&root.path, 0, None)?; }
    diagnostics.complete();
    Ok(result)
}

pub struct Copies {
    pub paths: Vec<PathBuf>,
    pub spotlight: Vec<PathBuf>,
    pub stale: Vec<PathBuf>,
}
/// Identical mandatory sources for both contracts; callers classify verified Trash.
pub fn copies(
    id: &str,
    inventory: &[Bundle],
    deadline: Instant,
    remaining: &std::cell::Cell<usize>,
) -> io::Result<Copies> {
    for bundle in inventory {
        if Instant::now() >= deadline { return Err(error("copies_unknown: deadline")); }
        bundle.revalidate()?;
    }
    copies_from_snapshot(id, inventory, deadline, remaining)
}

/// Preview-only use of an inventory captured in this same classification.
/// Matching owners are still captured/revalidated by the caller; execution
/// always rebuilds the inventory through the ordinary capture path.
pub(crate) fn copies_from_snapshot(
    id: &str, inventory: &[Bundle], deadline: Instant,
    remaining: &std::cell::Cell<usize>,
) -> io::Result<Copies> {
    let control = owner_budget::Control::new(deadline, Path::new(id), Default::default());
    copies_observed(id, inventory, remaining, &control, 256)
}

/// A lower limit may only reject an owner; it never permits an incomplete proof.
pub(crate) fn copies_observed(
    id: &str, inventory: &[Bundle], remaining: &std::cell::Cell<usize>,
    control: &owner_budget::Control, max_copies: usize,
) -> io::Result<Copies> {
    let mut paths = BTreeSet::new();
    let mut stale = Vec::new();
    for b in inventory {
        control.check()?;
        if b.id == id { insert_copy(&mut paths, b.path.clone(), max_copies)?; }
    }
    let registered = control.run("registry", Path::new(id), || related::registered_applications(id))?;
    // Preflight registration paths before expensive bundle capture. More than
    // eight distinct present candidates cannot be established within the cache
    // owner limit. This is a refusal only: their bundle IDs remain UNVERIFIED.
    // Stale paths and duplicates do not consume this candidate allowance.
    let mut candidates = paths.clone();
    let mut present = Vec::new();
    for p in registered {
        consume(remaining)?;
        let normalized = control.run("registry_link", &p, || observed_application_path(&p, id, inventory))?;
        if control.run("registry_presence", &normalized, || absent_without_links(&normalized))? {
            stale.push(normalized);
            continue;
        }
        if max_copies == 8 { insert_registered_candidate(&mut candidates, &normalized, max_copies)?; }
        present.push(normalized);
    }
    for normalized in present {
        // Every admitted candidate still receives fresh manifest and identity
        // validation; preflight is never evidence that an owner is valid.
        let bundle = control.run("registry_bundle", &normalized, || Bundle::capture_observed(&normalized, control))?;
        if bundle.id != id { return Err(error("copies_unknown: registry identity mismatch")); }
        insert_copy(&mut paths, normalized, max_copies)?;
    }
    let spotlight = control.run("spotlight", Path::new(id), || orphans::spotlight(id, control.deadline))?;
    for p in &spotlight {
        consume(remaining)?;
        let normalized = control.run("spotlight_link", p, || observed_application_path(p, id, inventory))?;
        insert_copy(&mut paths, normalized, max_copies)?;
    }
    control.check()?;
    Ok(Copies { paths: paths.into_iter().collect(), spotlight, stale })
}
fn insert_registered_candidate(paths: &mut BTreeSet<PathBuf>, path: &Path, limit: usize) -> io::Result<()> {
    paths.insert(path.to_owned());
    if paths.len() > limit {
        return Err(error("copies_unknown: registered candidate limit exceeded; bundle identities unverified"));
    }
    Ok(())
}
fn insert_copy(paths: &mut BTreeSet<PathBuf>, path: PathBuf, limit: usize) -> io::Result<()> {
    paths.insert(path);
    if paths.len() > limit {
        return Err(error(if limit == 8 { "owner count exceeds eight" } else { "copies_unknown: limit" }));
    }
    Ok(())
}

/// Normalize only links already verified in this same inventory; a registry
/// or Spotlight result alone never grants permission to follow a new link.
fn observed_application_path(path: &Path, id: &str, inventory: &[Bundle]) -> io::Result<PathBuf> {
    if let Some(bundle) = inventory.iter().find(|b| b.application_link.as_ref().is_some_and(|l| l.path() == path)) {
        bundle.revalidate()?;
        if bundle.id != id { return Err(error("copies_unknown: linked application identity mismatch")); }
        return Ok(bundle.path.clone());
    }
    Ok(path.to_owned())
}
pub fn live_path(path: &Path) -> PathBuf {
    path.strip_prefix("/System/Volumes/Data")
        .map(|p| Path::new("/").join(p))
        .unwrap_or_else(|_| path.to_owned())
}

pub fn consume(remaining: &std::cell::Cell<usize>) -> io::Result<()> {
    let next = remaining
        .get()
        .checked_sub(1)
        .ok_or_else(|| error("discovery_entry_budget_exhausted"))?;
    remaining.set(next);
    Ok(())
}


#[cfg(test)]
mod progress_tests {
    use super::*;
    #[test]
    fn registered_candidate_limit_is_a_refusal_not_a_copy_proof() {
        let mut candidates = BTreeSet::from([PathBuf::from("/Applications/Installed.app")]);
        insert_registered_candidate(&mut candidates, Path::new("/Applications/Installed.app"), 8).unwrap();
        for i in 0..7 {
            insert_registered_candidate(&mut candidates, &PathBuf::from(format!("/Build/{i}.app")), 8).unwrap();
        }
        assert_eq!(candidates.len(), 8);
        let err = insert_registered_candidate(&mut candidates, Path::new("/Build/Ninth.app"), 8).unwrap_err();
        assert!(err.to_string().contains("copies_unknown"));
        assert!(err.to_string().contains("identities unverified"));
    }
    #[test]
    fn observed_bundle_capture_binds_identity_and_obeys_expired_budget() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let app = base.join("Sample.app");
        std::fs::create_dir_all(app.join("Contents")).unwrap();
        std::fs::write(app.join("Contents/Info.plist"),
            b"<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.sample</string></dict></plist>").unwrap();
        let control = owner_budget::Control::new(Instant::now() + std::time::Duration::from_secs(5), &app, Default::default());
        let bundle = Bundle::capture_observed(&app, &control).unwrap();
        assert_eq!(bundle.id, "com.example.sample");
        bundle.revalidate().unwrap();
        std::fs::write(app.join("Contents/Info.plist"), b"changed").unwrap();
        assert!(bundle.revalidate().is_err());
        let expired = owner_budget::Control::new(Instant::now(), &app, Default::default());
        assert!(Bundle::capture_observed(&app, &expired).err().unwrap().to_string().contains("deadline"));
    }
    #[test]
    fn owner_limit_counts_unique_paths_and_rejects_ninth() {
        let mut paths = BTreeSet::new();
        for i in 0..8 { insert_copy(&mut paths, PathBuf::from(format!("/Applications/{i}.app")), 8).unwrap(); }
        insert_copy(&mut paths, PathBuf::from("/Applications/0.app"), 8).unwrap();
        assert_eq!(paths.len(), 8);
        assert!(insert_copy(&mut paths, PathBuf::from("/Applications/8.app"), 8).unwrap_err().to_string().contains("owner count exceeds eight"));
    }
    #[test]
    fn inventory_keeps_deep_apps_beneath_sdk_directories() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let deep = base.join("SDK/BuildTools/Emscripten/python/lib/Nested.app/Contents");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("Info.plist"), b"<plist><dict><key>CFBundleIdentifier</key><string>org.example.deep</string></dict></plist>").unwrap();
        let roots = vec![Root::capture(base.clone(), false).unwrap()];
        let observed = inventory_with_progress(&roots, Instant::now() + std::time::Duration::from_secs(10),
            &std::cell::Cell::new(100), &mut |_| Ok(())).unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].id, "org.example.deep");
    }
    #[test]
    fn inventory_progress_counts_captured_apps_and_obeys_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let bundle = base.join("Sample.app/Contents");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("Info.plist"), b"<plist><dict><key>CFBundleIdentifier</key><string>org.example.sample</string></dict></plist>").unwrap();
        let roots = vec![Root::capture(base, false).unwrap()];
        let mut seen = Vec::new();
        let inventory = inventory_with_progress(&roots, Instant::now() + std::time::Duration::from_secs(5),
            &std::cell::Cell::new(100), &mut |n| { seen.push(n); Ok(()) }).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(seen.first(), Some(&0));
        assert_eq!(seen.last(), Some(&1));
        let error = inventory_with_progress(&roots, Instant::now() + std::time::Duration::from_secs(5),
            &std::cell::Cell::new(100), &mut |_| Err(io::Error::other("cancelled"))).err().unwrap();
        assert_eq!(error.to_string(), "cancelled");
    }
}

#[cfg(test)]
mod application_link_tests {
    use super::*;
    use std::{cell::Cell, os::unix::fs::symlink, time::Duration};
    fn app(base: &Path, name: &str) -> PathBuf {
        let p = base.join(name);
        std::fs::create_dir_all(p.join("Contents")).unwrap();
        std::fs::write(p.join("Contents/Info.plist"), b"<plist><dict><key>CFBundleIdentifier</key><string>org.example.fixture</string></dict></plist>").unwrap();
        p
    }
    fn observed(roots: &[Root]) -> io::Result<Vec<Bundle>> {
        inventory_with_progress(roots, Instant::now() + Duration::from_secs(10), &Cell::new(100), &mut |_| Ok(()))
    }
    #[test]
    fn accepts_absolute_and_relative_helper_shortcuts_but_not_orphan_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let target = app(&base, "Main.app/Contents/Helpers/Helper.app");
        app(&base, "Main.app");
        symlink("Main.app/Contents/Helpers/Helper.app", base.join("Helper.app")).unwrap();
        symlink(&target, base.join("Uninstall helper")).unwrap();
        let roots = vec![Root::capture(base.clone(), false).unwrap()];
        let bundles = observed(&roots).unwrap();
        assert_eq!(bundles.iter().filter(|b| b.application_link.is_some()).count(), 2);
        assert_eq!(observed_application_path(&base.join("Helper.app"), "org.example.fixture", &bundles).unwrap(), target);
        assert!(observed_application_path(&base.join("Helper.app"), "org.example.other", &bundles).is_err());
        assert!(inventory(&roots, Instant::now() + Duration::from_secs(10), &Cell::new(100)).is_err());
    }
    #[test]
    fn replacing_a_link_invalidates_retained_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        app(&base, "First.app"); app(&base, "Other.app");
        let source = base.join("Shortcut.app");
        symlink("First.app", &source).unwrap();
        let roots = vec![Root::capture(base, false).unwrap()];
        let bundle = Bundle::capture_application_link(&source, &roots).unwrap();
        std::fs::remove_file(&source).unwrap();
        symlink("Other.app", &source).unwrap();
        assert!(bundle.revalidate().is_err());
    }
    #[test]
    fn unsupported_targets_remain_unknown_with_source_and_target_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let external = app(&std::fs::canonicalize(outside.path()).unwrap(), "External.app");
        app(&base, "Real.app");
        std::fs::create_dir(base.join("Folder")).unwrap();
        symlink("Real.app", base.join("Chain.app")).unwrap();
        let roots = vec![Root::capture(base.clone(), false).unwrap()];
        let source = base.join("Shortcut.app");
        for target in [PathBuf::from("Missing.app"), PathBuf::from("Folder"), PathBuf::from("Chain.app"), PathBuf::from("Shortcut.app"), PathBuf::from("../External.app"), external] {
            symlink(&target, &source).unwrap();
            let message = Bundle::capture_application_link(&source, &roots).err().unwrap().to_string();
            assert!(message.contains("copies_unknown"));
            assert!(message.contains("Shortcut.app"));
            assert!(message.contains(&format!("target={target:?}")));
            assert!(message.contains("resolved="));
            std::fs::remove_file(&source).unwrap();
        }
    }
}

/// One terminal classification record even when individual owners are unknown.
pub(crate) fn classification_summary(completed: u64, total: u64, issues: usize, elapsed_us: u128) {
    diagnostics::debug_line(format_args!("event=classification_summary completed={completed} total={total} issues={issues} elapsed_us={elapsed_us}"));
}
