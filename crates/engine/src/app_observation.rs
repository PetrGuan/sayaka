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
}
impl Bundle {
    pub fn capture(path: &Path) -> io::Result<Self> {
        if path.extension().is_none_or(|e| e != "app") {
            return Err(error("copies_unknown: not an app"));
        }
        let bundle = orphans::exact(path)?;
        if !bundle.is_directory() {
            return Err(error("copies_unknown: not a directory"));
        }
        let manifest = orphans::exact(&path.join("Contents/Info.plist"))?;
        let (id, digest, dev, ino) = read_bundle_identifier_diagnostic(path).map_err(error)?;
        let id = id
            .value
            .filter(|_| id.state == StringState::Present)
            .filter(|s| related::valid_bundle_id(s))
            .ok_or_else(|| error("copies_unknown: invalid manifest"))?;
        if manifest.identity() != (dev, ino) {
            return Err(error("resource_changed"));
        }
        bundle.revalidate()?;
        manifest.revalidate()?;
        Ok(Self {
            path: path.to_owned(),
            id,
            bundle,
            manifest,
            digest,
            system_safari: None,
        })
    }
    fn capture_system_safari() -> io::Result<Self> {
        let observation = platform::system_safari::Observation::capture()?;
        let mut bundle = Self::capture(observation.path())?;
        if bundle.id != "com.apple.Safari" { return Err(error("copies_unknown: system Safari identity")); }
        bundle.system_safari = Some(observation);
        bundle.revalidate()?;
        Ok(bundle)
    }
    pub fn is_system_safari(&self) -> bool { self.system_safari.is_some() }
    pub fn revalidate(&self) -> io::Result<()> {
        if let Some(observation) = &self.system_safari { observation.revalidate()?; }
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
        Ok(())
    }
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
    inventory_with_progress(roots, deadline, remaining, &mut |_| Ok(()))
}

/// Called before traversal and after each captured application. Zero total is
/// intentional: enumeration has not yet established a trustworthy denominator.
pub(crate) fn inventory_with_progress(
    roots: &[Root], deadline: Instant, remaining: &std::cell::Cell<usize>,
    progress: &mut impl FnMut(usize) -> io::Result<()>,
) -> io::Result<Vec<Bundle>> {
    progress(0)?;
    let mut result = Vec::new();
    let mut count = 0;
    for root in roots {
        root.revalidate()?;
        if root.absent {
            continue;
        }
        let mut stack = vec![(root.path.clone(), 0)];
        while let Some((p, depth)) = stack.pop() {
            progress(result.len())?;
            if Instant::now() >= deadline || depth > 32 {
                return Err(error("copies_unknown: budget"));
            }
            let w = orphans::exact(&p)?;
            if p.extension().is_some_and(|e| e == "app") {
                result.push(Bundle::capture(&p)?);
                progress(result.len())?;
                continue;
            }
            for entry in std::fs::read_dir(&p)? {
                count += 1;
                consume(remaining)?;
                if count > 10_000 || Instant::now() >= deadline {
                    return Err(error("copies_unknown: budget"));
                }
                let entry = entry?;
                let ty = entry.file_type()?;
                if ty.is_symlink() {
                    if entry.path() == Path::new(platform::system_safari::ENTRY) {
                        result.push(Bundle::capture_system_safari()?);
                        progress(result.len())?;
                        continue;
                    }
                    return Err(error("copies_unknown: symlink"));
                }
                if !ty.is_dir()
                    && (!ty.is_file()
                        || entry.path().extension().is_some_and(|e| e == "app")
                        || orphans::is_finder_alias(&entry.path())?)
                {
                    return Err(error("copies_unknown: alias or unsupported entry"));
                }
                if ty.is_dir() {
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e == "app") || !platform::is_package(&p)? {
                        stack.push((p, depth + 1));
                    }
                }
            }
            w.revalidate()?;
        }
        root.revalidate()?;
    }
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
    let mut paths = BTreeSet::new();
    let mut stale = Vec::new();
    for b in inventory {
        if Instant::now() >= deadline {
            return Err(error("copies_unknown: deadline"));
        }
        if b.id == id {
            paths.insert(b.path.clone());
        }
    }
    for p in related::registered_applications(id)? {
        consume(remaining)?;
        if Instant::now() >= deadline {
            return Err(error("copies_unknown: deadline"));
        }
        if absent_without_links(&p)? {
            stale.push(p);
            continue;
        }
        let bundle = Bundle::capture(&p)?;
        if bundle.id != id {
            return Err(error("copies_unknown: registry identity mismatch"));
        }
        paths.insert(p);
    }
    let spotlight = orphans::spotlight(id, deadline)?;
    for _ in &spotlight {
        consume(remaining)?;
    }
    paths.extend(spotlight.iter().cloned());
    if paths.len() > 256 || Instant::now() >= deadline {
        return Err(error("copies_unknown: limit"));
    }
    Ok(Copies {
        paths: paths.into_iter().collect(),
        spotlight,
        stale,
    })
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
