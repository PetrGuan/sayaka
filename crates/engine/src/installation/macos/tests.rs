// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::installation::{InstallPlan, RecoverPlan, RemovePlan, UpdatePlan, UpdatePolicy};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

struct Fixture {
    base: PathBuf,
    registered: BTreeMap<PathBuf, (u64, u64, bool)>,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap()
            .join(format!(
                "sayaka-installation-fixture-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_NAME.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let mut fixture = Self {
            base,
            registered: BTreeMap::new(),
        };
        fixture.register(fixture.base.clone());
        fixture.write(
            "owner-marker",
            b"sayaka-t12-installation-native-fixture",
            0o600,
        );
        fixture.write(
            "source",
            b"#!/bin/sh\nprintf 'installation fixture\\n'\n",
            0o700,
        );
        fixture.write(
            "history",
            b"unrelated operation history; must survive",
            0o600,
        );
        fixture
    }

    fn prefix(&self) -> PathBuf {
        self.base.join("package")
    }
    fn source(&self) -> PathBuf {
        self.base.join("source")
    }

    fn set_source(&mut self, contents: &[u8]) {
        std::fs::write(self.source(), contents).unwrap();
        std::fs::set_permissions(self.source(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn register(&mut self, path: PathBuf) {
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(m.uid(), rustix::process::geteuid().as_raw());
        self.registered.insert(path, (m.dev(), m.ino(), m.is_dir()));
    }

    fn write(&mut self, relative: &str, contents: &[u8], mode: u32) {
        let path = self.base.join(relative);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        self.register(path);
    }

    // Only fixed artifacts of the exact operation path just created by this test.
    fn register_layout(&mut self, root: &Path) {
        for relative in ["", "bin", "bin/sayaka", LOCK, MANIFEST, UPDATE_GUARD] {
            let path = root.join(relative);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => self.register(path),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => panic!("fixture registration failed: {e}"),
            }
        }
    }

    fn register_dynamic_installation_artifacts(&mut self) {
        let entries = std::fs::read_dir(&self.base).unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            if (name.contains(".sayaka-lifecycle-v1.json") || name.starts_with(".sayaka-update-"))
                && path.exists()
            {
                self.register(path);
            }
        }
    }

    fn install_with(&mut self, version: &str) {
        let plan = InstallPlan::prepare(&self.prefix(), &self.source(), version).unwrap();
        let result = plan.execute(&Cancellation::default()).unwrap();
        assert_eq!(result.status, OutcomeState::Installed, "{result:?}");
        self.register_layout(&self.prefix());
    }

    fn install(&mut self) {
        self.install_with("1.2.3");
    }

    fn cleanup(self) {
        assert_eq!(
            std::fs::read(self.base.join("owner-marker")).unwrap(),
            b"sayaka-t12-installation-native-fixture"
        );
        assert_eq!(
            std::fs::read(self.base.join("history")).unwrap(),
            b"unrelated operation history; must survive"
        );
        let mut entries: Vec<_> = self.registered.into_iter().collect();
        entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, expected) in entries {
            let m = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => panic!("fixture cleanup inspection failed: {e}"),
            };
            assert_eq!(
                (m.dev(), m.ino(), m.is_dir()),
                expected,
                "fixture identity changed: {path:?}"
            );
            if m.is_dir() {
                std::fs::remove_dir(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
        }
        assert!(
            !self.base.exists(),
            "fixture cleanup must be explicit and complete"
        );
    }
}

fn fail() -> io::Error {
    io::Error::other("injected boundary failure")
}

fn recovery(result: &Outcome) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    assert_eq!(result.recovery_paths.len(), 1);
    PathBuf::from(OsString::from_vec(result.recovery_paths[0].bytes.clone()))
}

fn digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}

fn manifest_contains_version(prefix: &Path, version: &str) -> bool {
    std::fs::read_to_string(prefix.join(MANIFEST))
        .unwrap()
        .contains(&format!("\"version\":\"{version}\""))
}

fn lifecycle_path(prefix: &Path) -> PathBuf {
    let parent = Parent::open(prefix).unwrap();
    parent.path.join(parent.lifecycle_name())
}

fn lifecycle_next_path(prefix: &Path) -> PathBuf {
    let path = lifecycle_path(prefix);
    let name = path.file_name().unwrap().to_string_lossy().to_string() + ".next";
    path.parent().unwrap().join(name)
}

fn synthetic_macho(tag: u8) -> Vec<u8> {
    let cputype: i32 = match std::env::consts::ARCH {
        "aarch64" => 0x0100_000c,
        "x86_64" => 0x0100_0007,
        other => panic!("unsupported test arch for synthetic Mach-O fixture: {other}"),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes.extend_from_slice(&cputype.to_le_bytes());
    bytes.extend_from_slice(&3i32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x32u32.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x000d_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x000d_0000u32.to_le_bytes());
    bytes.extend_from_slice(b"sayaka-native-update-fixture");
    bytes.push(tag);
    bytes
}

#[test]
fn preview_is_read_only_and_copy_hash_footprint_remove_are_real() {
    let mut f = Fixture::new();
    let before: Vec<_> = std::fs::read_dir(&f.base)
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect();
    let plan = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    assert!(!f.prefix().exists());
    let after: Vec<_> = std::fs::read_dir(&f.base)
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    let source = std::fs::read(f.source()).unwrap();
    assert_eq!(
        plan.preview().sha256,
        format!("{:x}", Sha256::digest(&source))
    );
    let result = plan.execute(&Cancellation::default()).unwrap();
    assert_eq!(result.status, OutcomeState::Installed, "{result:?}");
    assert_eq!(result.exit_code(), 0);
    f.register_layout(&f.prefix());
    assert_eq!(
        std::fs::read(f.prefix().join("bin/sayaka")).unwrap(),
        source
    );
    let mut logical = 0;
    let mut allocated = 0;
    for name in ["bin/sayaka", MANIFEST, LOCK] {
        let metadata = std::fs::metadata(f.prefix().join(name)).unwrap();
        logical += metadata.len();
        allocated += metadata.blocks() * 512;
    }
    assert_eq!(result.logical_bytes, Some(logical));
    assert_eq!(result.allocated_bytes, Some(allocated));
    let plan = RemovePlan::prepare(&f.prefix()).unwrap();
    assert!(f.prefix().join("bin/sayaka").exists());
    assert_eq!(plan.preview().action, Action::Remove);
    let result = plan.execute(&Cancellation::default()).unwrap();
    assert_eq!(result.status, OutcomeState::Removed, "{result:?}");
    assert_eq!(result.logical_bytes, Some(logical));
    assert!(!f.prefix().exists());
    f.cleanup();
}

#[test]
fn owned_same_image_is_idempotent_without_metadata_writes() {
    let mut f = Fixture::new();
    f.install();
    let manifest = File::open(f.prefix().join(MANIFEST)).unwrap();
    let before = Snapshot::of(&manifest).unwrap();
    let plan = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    assert!(plan.preview().already_installed);
    assert_eq!(
        plan.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::AlreadyInstalled
    );
    assert_eq!(Snapshot::of(&manifest).unwrap(), before);
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "different").is_err());
    f.cleanup();
}

#[test]
fn published_incomplete_install_requires_explicit_successful_durability_retry() {
    let barriers = [
        Point::SyncExecutable,
        Point::SyncManifest,
        Point::SyncLock,
        Point::SyncBin,
        Point::SyncRoot,
        Point::SyncParent,
        Point::FinalFullSync,
    ];
    fn snapshots(prefix: &Path) -> Vec<Snapshot> {
        ["", "bin", "bin/sayaka", MANIFEST, LOCK]
            .into_iter()
            .map(|name| Snapshot::of(&File::open(prefix.join(name)).unwrap()).unwrap())
            .collect()
    }
    for publication_failure in [Point::SyncParent, Point::FinalFullSync] {
        let mut f = Fixture::new();
        let prefix = f.prefix();
        let (plan, preview) = Install::prepare(&prefix, &f.source(), "1.2.3").unwrap();
        let published = plan
            .execute_with(preview, &Cancellation::default(), |point, path| {
                if point == Point::Published {
                    f.register_layout(path);
                }
                if point == publication_failure {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(published.status, OutcomeState::Incomplete);
        assert_eq!(recovery(&published), prefix);
        let original = snapshots(&prefix);

        let preview_only = InstallPlan::prepare(&prefix, &f.source(), "1.2.3").unwrap();
        assert!(preview_only.preview().already_installed);
        drop(preview_only);
        assert_eq!(snapshots(&prefix), original);

        for (index, failed_barrier) in barriers.iter().enumerate() {
            let (plan, preview) = Install::prepare(&prefix, &f.source(), "1.2.3").unwrap();
            let mut visited = Vec::new();
            let result = plan
                .execute_with(preview, &Cancellation::default(), |point, path| {
                    assert_eq!(path, prefix);
                    visited.push(point);
                    if point == *failed_barrier {
                        return Err(fail());
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(visited, barriers[..=index]);
            assert_eq!(
                result.status,
                OutcomeState::Incomplete,
                "{failed_barrier:?}"
            );
            assert_eq!(result.exit_code(), 1);
            assert_eq!(recovery(&result), prefix);
            assert!(result.error.unwrap().contains("injected boundary failure"));
            assert!(result.logical_bytes.is_none());
            assert!(result.allocated_bytes.is_none());
            assert_eq!(snapshots(&prefix), original);
        }

        let (plan, preview) = Install::prepare(&prefix, &f.source(), "1.2.3").unwrap();
        let mut visited = Vec::new();
        let result = plan
            .execute_with(preview, &Cancellation::default(), |point, path| {
                assert_eq!(path, prefix);
                visited.push(point);
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, barriers);
        assert_eq!(result.status, OutcomeState::AlreadyInstalled);
        assert_eq!(result.exit_code(), 0);
        assert!(result.recovery_paths.is_empty());
        assert!(result.error.is_none());
        assert!(result.logical_bytes.is_some());
        assert!(result.allocated_bytes.is_some());
        assert_eq!(snapshots(&prefix), original);
        f.cleanup();
    }
}

#[test]
fn existing_unknown_prefix_and_extra_files_are_never_overwritten_or_moved() {
    let mut f = Fixture::new();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(f.prefix())
        .unwrap();
    f.register(f.prefix());
    f.write("package/user-data", b"not ours", 0o600);
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").is_err());
    assert!(RemovePlan::prepare(&f.prefix()).is_err());
    assert_eq!(
        std::fs::read(f.prefix().join("user-data")).unwrap(),
        b"not ours"
    );
    f.cleanup();

    let mut f = Fixture::new();
    f.install();
    f.write("package/bin/extra", b"not ours", 0o600);
    assert!(RemovePlan::prepare(&f.prefix()).is_err());
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").is_err());
    assert!(f.prefix().join("bin/sayaka").exists());
    f.cleanup();
}

#[test]
fn competing_publication_is_no_replace_and_reports_exact_staging() {
    let mut f = Fixture::new();
    let (plan, preview) = Install::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    let prefix = f.prefix();
    let result = plan
        .execute_with(preview, &Cancellation::default(), |point, stage| {
            if point == Point::BeforePublish {
                f.register_layout(stage);
                std::fs::DirBuilder::new().mode(0o700).create(&prefix)?;
                f.register(prefix.clone());
                f.write("package/user-file", b"race winner", 0o600);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(recovery(&result).join(MANIFEST).exists());
    assert_eq!(
        std::fs::read(prefix.join("user-file")).unwrap(),
        b"race winner"
    );
    f.cleanup();
}

#[test]
fn modified_hardlinked_symlinked_and_public_payloads_are_refused() {
    for mutation in 0..4 {
        let mut f = Fixture::new();
        f.install();
        let payload = f.prefix().join("bin/sayaka");
        match mutation {
            0 => {
                std::fs::write(&payload, b"changed").unwrap();
            }
            1 => {
                let link = f.base.join("hardlink");
                std::fs::hard_link(&payload, &link).unwrap();
                f.register(link);
            }
            2 => {
                std::fs::remove_file(&payload).unwrap();
                symlink(f.source(), &payload).unwrap();
                f.register(payload.clone());
            }
            3 => {
                std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            RemovePlan::prepare(&f.prefix()).is_err(),
            "mutation {mutation}"
        );
        assert!(f.prefix().exists());
        f.cleanup();
    }
}

#[test]
fn all_managed_identity_mode_and_acl_checks_are_enforced() {
    for relative in ["", "bin", MANIFEST, LOCK] {
        let mut f = Fixture::new();
        f.install();
        let path = f.prefix().join(relative);
        let mode = if path.is_dir() { 0o755 } else { 0o644 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(RemovePlan::prepare(&f.prefix()).is_err(), "{relative}");
        f.cleanup();
    }
    let mut f = Fixture::new();
    f.install();
    let prefix = f.prefix();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(&prefix)
        .status()
        .unwrap();
    assert!(status.success(), "native ACL fixture setup must succeed");
    assert!(sayaka_platform_macos::has_extended_acl(&File::open(&prefix).unwrap()).unwrap());
    assert!(RemovePlan::prepare(&prefix).is_err());
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&prefix)
            .status()
            .unwrap()
            .success()
    );
    f.cleanup();
}

#[test]
fn malformed_receipt_replacement_and_missing_artifacts_refuse_without_effects() {
    for mutation in 0..4 {
        let mut f = Fixture::new();
        f.install();
        match mutation {
            0 => {
                std::fs::write(f.prefix().join(MANIFEST), b"{}").unwrap();
            }
            1 => {
                let payload = f.prefix().join("bin/sayaka");
                std::fs::remove_file(&payload).unwrap();
                f.write(
                    "package/bin/sayaka",
                    b"#!/bin/sh\nprintf 'installation fixture\\n'\n",
                    0o700,
                );
            }
            2 => {
                std::fs::remove_file(f.prefix().join(LOCK)).unwrap();
            }
            3 => {
                std::fs::write(f.prefix().join(LOCK), b"unexpected").unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            RemovePlan::prepare(&f.prefix()).is_err(),
            "mutation {mutation}"
        );
        assert!(f.prefix().exists());
        f.cleanup();
    }
}

#[test]
fn physical_existing_parent_and_single_link_safe_source_are_required() {
    let mut f = Fixture::new();
    assert!(InstallPlan::prepare(&f.base.join("missing/package"), &f.source(), "1").is_err());
    assert!(!f.base.join("missing").exists());
    let link = f.base.join("parent-link");
    symlink(&f.base, &link).unwrap();
    f.register(link.clone());
    assert!(InstallPlan::prepare(&link.join("package"), &f.source(), "1").is_err());
    let source_link = f.base.join("source-link");
    symlink(f.source(), &source_link).unwrap();
    f.register(source_link.clone());
    assert!(InstallPlan::prepare(&f.prefix(), &source_link, "1").is_err());
    std::fs::set_permissions(f.source(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1").is_err());
    std::fs::set_permissions(f.source(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source_hardlink = f.base.join("source-hardlink");
    std::fs::hard_link(f.source(), &source_hardlink).unwrap();
    f.register(source_hardlink);
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1").is_err());
    f.cleanup();
}

#[test]
fn source_changed_after_preview_refuses_before_effects_and_size_is_bounded() {
    let f = Fixture::new();
    let plan = InstallPlan::prepare(&f.prefix(), &f.source(), "1").unwrap();
    std::fs::write(f.source(), b"new executable").unwrap();
    assert!(plan.execute(&Cancellation::default()).is_err());
    assert!(!f.prefix().exists());
    let source = std::fs::OpenOptions::new()
        .write(true)
        .open(f.source())
        .unwrap();
    source.set_len(MAX_BINARY + 1).unwrap();
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1").is_err());
    source.set_len(0).unwrap();
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1").is_err());
    f.cleanup();
}

#[test]
fn cancellation_before_effects_and_during_staging_removal_is_honest() {
    let mut f = Fixture::new();
    let c = Cancellation::default();
    let plan = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    c.cancel();
    let result = plan.execute(&c).unwrap();
    assert_eq!(result.status, OutcomeState::Cancelled);
    assert_eq!(result.exit_code(), 130);
    assert!(result.recovery_paths.is_empty());
    assert!(!f.prefix().exists());
    let c = Cancellation::default();
    let (plan, preview) = Install::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    let result = plan
        .execute_with(preview, &c, |point, path| {
            if point == Point::Copied {
                f.register_layout(path);
                c.cancel();
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(result.error.as_ref().unwrap().contains("cancelled"));
    assert!(recovery(&result).join("bin/sayaka").exists());
    f.install();
    let c = Cancellation::default();
    let plan = RemovePlan::prepare(&f.prefix()).unwrap();
    c.cancel();
    assert_eq!(plan.execute(&c).unwrap().status, OutcomeState::Cancelled);
    assert!(f.prefix().exists());
    let c = Cancellation::default();
    let (plan, preview) = Remove::prepare(&f.prefix()).unwrap();
    let result = plan
        .execute_with(preview, &c, |point, path| {
            if point == Point::Detached {
                f.register_layout(path);
                c.cancel();
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(!f.prefix().exists());
    assert!(recovery(&result).join("bin/sayaka").exists());
    f.cleanup();
}

#[test]
fn installation_fault_boundaries_retain_the_actual_recovery_path() {
    for point in [
        Point::StageCreated,
        Point::Copied,
        Point::BeforePublish,
        Point::Published,
    ] {
        let mut f = Fixture::new();
        let (plan, preview) = Install::prepare(&f.prefix(), &f.source(), "1").unwrap();
        let result = plan
            .execute_with(preview, &Cancellation::default(), |p, path| {
                if p == point {
                    f.register_layout(path);
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(result.status, OutcomeState::Incomplete, "{point:?}");
        assert_eq!(result.exit_code(), 1);
        assert!(result.logical_bytes.is_none());
        let path = recovery(&result);
        assert!(path.exists());
        assert_eq!(f.prefix().exists(), point == Point::Published);
        if point == Point::Published {
            assert_eq!(path, f.prefix());
            assert!(RemovePlan::prepare(&path).is_ok());
        }
        f.cleanup();
    }
}

#[test]
fn removal_faults_preserve_exact_progress_without_success_fallback() {
    for point in [
        Point::Detached,
        Point::PayloadRemoved,
        Point::BinRemoved,
        Point::LockRemoved,
        Point::ManifestRemoved,
        Point::RootRemoved,
    ] {
        let mut f = Fixture::new();
        f.install();
        let (plan, preview) = Remove::prepare(&f.prefix()).unwrap();
        let result = plan
            .execute_with(preview, &Cancellation::default(), |p, path| {
                if p == Point::Detached {
                    f.register_layout(path);
                }
                if p == point {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(result.status, OutcomeState::Incomplete, "{point:?}");
        assert!(!f.prefix().exists());
        assert!(result.error.is_some());
        assert!(result.allocated_bytes.is_none());
        let path = recovery(&result);
        assert_eq!(path.exists(), point != Point::RootRemoved);
        if point != Point::Detached {
            assert!(!path.join("bin/sayaka").exists());
        }
        if point != Point::Detached && point != Point::RootRemoved {
            assert!(RemovePlan::prepare(&path).is_err());
        }
        f.cleanup();
    }
}

#[test]
fn execution_rechecks_extras_and_missing_files_at_every_removal_boundary() {
    let mut f = Fixture::new();
    f.install();
    let plan = RemovePlan::prepare(&f.prefix()).unwrap();
    f.write("package/extra", b"arrived after preview", 0o600);
    assert!(plan.execute(&Cancellation::default()).is_err());
    assert!(f.prefix().join("bin/sayaka").exists());
    f.cleanup();

    let mut f = Fixture::new();
    f.install();
    let (plan, preview) = Remove::prepare(&f.prefix()).unwrap();
    let result = plan
        .execute_with(preview, &Cancellation::default(), |point, path| {
            if point == Point::Detached {
                f.register_layout(path);
            }
            if point == Point::PayloadRemoved {
                std::fs::remove_file(path.join(LOCK))?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(recovery(&result).join(MANIFEST).exists());
    assert!(recovery(&result).join("bin").exists());
    assert!(result.error.unwrap().contains("missing"));
    f.cleanup();
}

#[test]
fn lock_is_exclusive_for_cooperating_previews_and_operations() {
    let mut f = Fixture::new();
    f.install();
    let plan = RemovePlan::prepare(&f.prefix()).unwrap();
    assert!(
        matches!(RemovePlan::prepare(&f.prefix()), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").is_err());
    drop(plan);
    assert!(RemovePlan::prepare(&f.prefix()).is_ok());
    f.cleanup();
}

#[test]
fn multichunk_copy_and_native_file_acl_refusal() {
    let mut f = Fixture::new();
    let contents: Vec<_> = (0..CHUNK * 3 + 19).map(|n| (n % 251) as u8).collect();
    f.write("source", &contents, 0o700);
    f.install();
    assert_eq!(
        std::fs::read(f.prefix().join("bin/sayaka")).unwrap(),
        contents
    );
    for path in [
        f.source(),
        f.prefix().join("bin"),
        f.prefix().join("bin/sayaka"),
        f.prefix().join(MANIFEST),
        f.prefix().join(LOCK),
    ] {
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(sayaka_platform_macos::has_extended_acl(&File::open(&path).unwrap()).unwrap());
        if path == f.source() {
            assert!(InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").is_err());
        } else {
            assert!(RemovePlan::prepare(&f.prefix()).is_err());
        }
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
    }
    f.cleanup();
}

#[test]
fn cancellation_is_observed_while_copying_real_chunks() {
    let mut f = Fixture::new();
    f.write("source", &vec![0x5a; CHUNK * 128], 0o700);
    let cancellation = Cancellation::default();
    let (plan, preview) = Install::prepare(&f.prefix(), &f.source(), "1").unwrap();
    let mut worker = None;
    let result = plan
        .execute_with(preview, &cancellation, |point, path| {
            if point == Point::StageCreated {
                let path = path.join("bin/sayaka");
                let cancel = cancellation.clone();
                worker = Some(std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                    while std::time::Instant::now() < deadline {
                        if std::fs::metadata(&path).is_ok_and(|m| m.len() > 0) {
                            cancel.cancel();
                            return true;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    false
                }));
            }
            Ok(())
        })
        .unwrap();
    assert!(
        worker.unwrap().join().unwrap(),
        "copy cancellation observer timed out"
    );
    assert_eq!(result.status, OutcomeState::Incomplete, "{result:?}");
    let path = recovery(&result);
    f.register_layout(&path);
    let length = std::fs::metadata(path.join("bin/sayaka")).unwrap().len();
    assert!(length > 0 && length < CHUNK as u64 * 128);
    assert!(!f.prefix().exists());
    f.cleanup();
}

#[test]
fn atomic_no_replace_primitive_cannot_replace_even_an_empty_directory() {
    let mut f = Fixture::new();
    let parent = Parent::open(&f.prefix()).unwrap();
    let staging = OsStr::new("atomic-stage");
    let root = create_directory(&parent.file, staging).unwrap();
    f.register(f.base.join(staging));
    create_file(&root, "witness", 0o600).unwrap();
    f.register(f.base.join(staging).join("witness"));
    create_directory(&parent.file, &parent.name).unwrap();
    f.register(f.prefix());
    let expected = Identity::of(&open_at(&parent.file, &parent.name, true).unwrap()).unwrap();
    assert_eq!(
        fs::renameat_with(
            &parent.file,
            staging,
            &parent.file,
            &parent.name,
            RenameFlags::NOREPLACE
        ),
        Err(rustix::io::Errno::EXIST)
    );
    assert_eq!(
        Identity::of(&open_at(&parent.file, &parent.name, true).unwrap()).unwrap(),
        expected
    );
    assert!(f.base.join(staging).join("witness").exists());
    f.cleanup();
}

#[test]
fn copied_payload_change_is_detected_before_atomic_publication() {
    let mut f = Fixture::new();
    let (plan, preview) = Install::prepare(&f.prefix(), &f.source(), "1").unwrap();
    let result = plan
        .execute_with(preview, &Cancellation::default(), |point, path| {
            if point == Point::BeforePublish {
                f.register_layout(path);
                std::fs::write(path.join("bin/sayaka"), b"tampered staged bytes")?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(!f.prefix().exists());
    assert!(recovery(&result).join(MANIFEST).exists());
    f.cleanup();
}

#[test]
fn detached_extra_is_retained_and_stops_further_cleanup() {
    let mut f = Fixture::new();
    f.install();
    let (plan, preview) = Remove::prepare(&f.prefix()).unwrap();
    let result = plan
        .execute_with(preview, &Cancellation::default(), |point, path| {
            if point == Point::Detached {
                f.register_layout(path);
            }
            if point == Point::PayloadRemoved {
                let extra = path.join("unowned-arrival");
                std::fs::write(&extra, b"never delete me")?;
                f.register(extra);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    let path = recovery(&result);
    assert_eq!(
        std::fs::read(path.join("unowned-arrival")).unwrap(),
        b"never delete me"
    );
    assert!(path.join(MANIFEST).exists());
    assert!(path.join("bin").exists());
    f.cleanup();
}

#[test]
fn consumed_public_plans_can_move_to_an_owned_worker() {
    fn assert_send<T: Send>() {}
    assert_send::<InstallPlan>();
    assert_send::<UpdatePlan>();
    assert_send::<RecoverPlan>();
    assert_send::<RemovePlan>();
}

#[test]
fn local_update_with_changed_candidate_commits_new_bytes_and_preserves_lock_identity() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(1));
    f.install_with("1.2.3");
    let lock_before = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
    let old_hash = digest(&f.prefix().join("bin/sayaka"));
    let old_manifest = std::fs::read(f.prefix().join(MANIFEST)).unwrap();
    f.set_source(&synthetic_macho(2));
    let update =
        UpdatePlan::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
    assert_eq!(update.preview().action, Action::Update);
    assert!(!update.preview().already_installed);
    assert!(update.preview().can_execute);
    assert_eq!(
        update.preview().decision.as_deref(),
        Some("candidate is newer and compatible")
    );
    let result = update.execute(&Cancellation::default()).unwrap();
    assert_eq!(result.status, OutcomeState::Updated, "{result:?}");
    assert_eq!(
        digest(&f.prefix().join("bin/sayaka")),
        digest(&f.source()),
        "installed executable must match candidate bytes"
    );
    assert_ne!(digest(&f.prefix().join("bin/sayaka")), old_hash);
    let manifest = std::fs::read_to_string(f.prefix().join(MANIFEST)).unwrap();
    assert!(manifest.contains("\"version\":\"1.2.4\""), "{manifest}");
    assert_ne!(manifest.as_bytes(), old_manifest);
    let lock_after = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
    assert_eq!(
        lock_after, lock_before,
        "update must preserve lock identity"
    );
    let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
    assert!(recover.preview().can_execute);
    assert_eq!(
        recover.preview().decision.as_deref(),
        Some("lifecycle outcome already recorded; no further recovery action")
    );
    let recovered = recover.execute(&Cancellation::default()).unwrap();
    assert_eq!(recovered.status, OutcomeState::Recovered, "{recovered:?}");
    f.register_layout(&f.prefix());
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
fn local_update_recovery_finalizes_binary_committed_windows_without_permissive_statuses() {
    for point in [Point::UpdateAfterBinaryRename, Point::UpdateAfterBinarySync] {
        let mut f = Fixture::new();
        f.set_source(&synthetic_macho(3));
        f.install_with("1.2.3");
        f.set_source(&synthetic_macho(4));
        let (plan, preview) =
            Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
        let result = plan
            .execute_with(preview, &Cancellation::default(), |current, _| {
                if current == point {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(result.status, OutcomeState::Incomplete, "{point:?}");
        let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
        assert!(
            recover.preview().can_execute,
            "{:?}",
            recover.preview().decision
        );
        assert_eq!(
            recover.preview().decision.as_deref(),
            Some("binary publish committed before lifecycle marker; recover can finalize manifest")
        );
        let recovered = recover.execute(&Cancellation::default()).unwrap();
        assert_eq!(recovered.status, OutcomeState::Recovered, "{recovered:?}");
        assert_eq!(digest(&f.prefix().join("bin/sayaka")), digest(&f.source()));
        let manifest = std::fs::read_to_string(f.prefix().join(MANIFEST)).unwrap();
        assert!(manifest.contains("\"version\":\"1.2.4\""), "{manifest}");
        f.register_layout(&f.prefix());
        f.register_dynamic_installation_artifacts();
        f.cleanup();
    }
}

#[test]
fn local_update_recovery_revalidates_staged_identities_before_any_unlink_or_publish() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(5));
    f.install_with("1.2.3");
    let original_bytes = std::fs::read(f.prefix().join("bin/sayaka")).unwrap();
    f.set_source(&synthetic_macho(6));
    let (plan, preview) =
        Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
    let result = plan
        .execute_with(preview, &Cancellation::default(), |point, _| {
            if point == Point::UpdateAfterManifestSync {
                return Err(fail());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
    assert!(recover.preview().can_execute);
    std::fs::write(f.prefix().join("bin/sayaka"), original_bytes).unwrap();
    std::fs::set_permissions(
        f.prefix().join("bin/sayaka"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let recovered = recover.execute(&Cancellation::default()).unwrap();
    assert_eq!(recovered.status, OutcomeState::Refused, "{recovered:?}");
    let manifest = std::fs::read_to_string(f.prefix().join(MANIFEST)).unwrap();
    assert!(manifest.contains("\"version\":\"1.2.4\""), "{manifest}");
    f.register_layout(&f.prefix());
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
fn local_update_recovery_confirms_manifest_committed_windows() {
    for point in [
        Point::UpdateAfterManifestRename,
        Point::UpdateAfterManifestSync,
    ] {
        let mut f = Fixture::new();
        f.set_source(&synthetic_macho(8));
        f.install_with("1.2.3");
        f.set_source(&synthetic_macho(9));
        let (plan, preview) =
            Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
        let result = plan
            .execute_with(preview, &Cancellation::default(), |current, _| {
                if current == point {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(result.status, OutcomeState::Incomplete, "{point:?}");
        let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
        assert!(recover.preview().can_execute);
        assert_eq!(
            recover.preview().decision.as_deref(),
            Some("manifest already reflects candidate; recover can confirm outcome")
        );
        let recovered = recover.execute(&Cancellation::default()).unwrap();
        assert_eq!(recovered.status, OutcomeState::Recovered, "{recovered:?}");
        assert_eq!(digest(&f.prefix().join("bin/sayaka")), digest(&f.source()));
        f.register_layout(&f.prefix());
        f.register_dynamic_installation_artifacts();
        f.cleanup();
    }
}

#[test]
fn local_recover_abandon_is_repeatable_after_success_and_partial_unlinks() {
    for point in [
        None,
        Some(Point::RecoverAfterExecutableUnlink),
        Some(Point::RecoverAfterManifestUnlink),
    ] {
        let mut f = Fixture::new();
        f.set_source(&synthetic_macho(10));
        f.install_with("1.2.3");
        let lock_before = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
        let current_hash = digest(&f.prefix().join("bin/sayaka"));
        f.set_source(&synthetic_macho(11));
        let (update, update_preview) =
            Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
        let update_result = update
            .execute_with(update_preview, &Cancellation::default(), |p, _| {
                if p == Point::UpdateStagedRecorded {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(update_result.status, OutcomeState::Incomplete);

        let (recover, preview) = Recover::prepare(&f.prefix()).unwrap();
        assert!(preview.can_execute);
        let first = recover
            .execute_with(preview, &Cancellation::default(), |p, _| {
                if Some(p) == point {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        if point.is_none() {
            assert_eq!(first.status, OutcomeState::Recovered, "{first:?}");
        } else {
            assert_eq!(first.status, OutcomeState::Incomplete, "{first:?}");
        }
        let repeat = RecoverPlan::prepare(&f.prefix()).unwrap();
        assert!(
            repeat.preview().can_execute,
            "{:?}",
            repeat.preview().decision
        );
        let second = repeat.execute(&Cancellation::default()).unwrap();
        assert_eq!(second.status, OutcomeState::Recovered, "{second:?}");
        assert!(manifest_contains_version(&f.prefix(), "1.2.3"));
        assert_eq!(digest(&f.prefix().join("bin/sayaka")), current_hash);
        let lock_after = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
        assert_eq!(lock_after, lock_before);
        let third = RecoverPlan::prepare(&f.prefix()).unwrap();
        assert_eq!(
            third.preview().decision.as_deref(),
            Some("lifecycle abandon outcome already recorded; no further recovery action")
        );
        assert_eq!(
            third.execute(&Cancellation::default()).unwrap().status,
            OutcomeState::Recovered
        );
        f.register_layout(&f.prefix());
        f.register_dynamic_installation_artifacts();
        f.cleanup();
    }
}

#[test]
fn local_recover_finalize_is_repeatable_after_rename_sync_and_outcome_windows() {
    for point in [
        Some(Point::RecoverAfterManifestRename),
        Some(Point::RecoverAfterManifestSync),
        Some(Point::RecoverBeforeOutcomeRecord),
        Some(Point::RecoverAfterOutcomeRecord),
        None,
    ] {
        let mut f = Fixture::new();
        f.set_source(&synthetic_macho(12));
        f.install_with("1.2.3");
        let lock_before = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
        f.set_source(&synthetic_macho(13));
        let candidate_hash = digest(&f.source());
        let (update, update_preview) =
            Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
        let update_result = update
            .execute_with(update_preview, &Cancellation::default(), |p, _| {
                if p == Point::UpdateAfterBinaryRename {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(update_result.status, OutcomeState::Incomplete);

        let (recover, preview) = Recover::prepare(&f.prefix()).unwrap();
        assert!(preview.can_execute);
        let first = recover
            .execute_with(preview, &Cancellation::default(), |p, _| {
                if Some(p) == point {
                    return Err(fail());
                }
                Ok(())
            })
            .unwrap();
        if point.is_none() {
            assert_eq!(first.status, OutcomeState::Recovered, "{first:?}");
        } else {
            assert_eq!(first.status, OutcomeState::Incomplete, "{first:?}");
        }
        let repeat = RecoverPlan::prepare(&f.prefix()).unwrap();
        assert!(
            repeat.preview().can_execute,
            "{:?}",
            repeat.preview().decision
        );
        let second = repeat.execute(&Cancellation::default()).unwrap();
        assert_eq!(second.status, OutcomeState::Recovered, "{second:?}");
        assert!(manifest_contains_version(&f.prefix(), "1.2.4"));
        assert_eq!(digest(&f.prefix().join("bin/sayaka")), candidate_hash);
        let lock_after = Identity::of(&File::open(f.prefix().join(LOCK)).unwrap()).unwrap();
        assert_eq!(lock_after, lock_before);
        f.register_layout(&f.prefix());
        f.register_dynamic_installation_artifacts();
        f.cleanup();
    }
}

#[test]
fn pending_lifecycle_record_blocks_remove_and_install_until_explicit_recovery() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(14));
    f.install_with("1.2.3");
    let current_hash = digest(&f.prefix().join("bin/sayaka"));
    f.set_source(&synthetic_macho(15));
    let (update, preview) =
        Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
    let update_result = update
        .execute_with(preview, &Cancellation::default(), |point, _| {
            if point == Point::UpdateStagedRecorded {
                return Err(fail());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(update_result.status, OutcomeState::Incomplete);
    let recovery_path = lifecycle_path(&f.prefix());
    assert!(recovery_path.exists());

    f.set_source(&synthetic_macho(14));
    let install = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    assert!(!install.preview().can_execute);
    let install_result = install.execute(&Cancellation::default()).unwrap();
    assert_eq!(install_result.status, OutcomeState::Refused);
    assert_eq!(recovery(&install_result), recovery_path);
    assert_eq!(digest(&f.prefix().join("bin/sayaka")), current_hash);

    let remove = RemovePlan::prepare(&f.prefix()).unwrap();
    assert!(!remove.preview().can_execute);
    let remove_result = remove.execute(&Cancellation::default()).unwrap();
    assert_eq!(remove_result.status, OutcomeState::Refused);
    assert_eq!(recovery(&remove_result), recovery_path);
    assert!(f.prefix().exists());

    let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
    assert!(recover.preview().can_execute);
    assert_eq!(
        recover.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Recovered
    );

    f.set_source(&synthetic_macho(15));
    let updated = UpdatePlan::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default())
        .unwrap()
        .execute(&Cancellation::default())
        .unwrap();
    assert_eq!(updated.status, OutcomeState::Updated);
    let removed = RemovePlan::prepare(&f.prefix())
        .unwrap()
        .execute(&Cancellation::default())
        .unwrap();
    assert_eq!(removed.status, OutcomeState::Removed);
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
fn stale_pending_lifecycle_blocks_absent_prefix_install_but_completed_record_does_not() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(16));
    f.install_with("1.2.3");
    f.set_source(&synthetic_macho(17));
    let (update, preview) =
        Update::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default()).unwrap();
    let pending = update
        .execute_with(preview, &Cancellation::default(), |point, _| {
            if point == Point::UpdateStagedRecorded {
                return Err(fail());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(pending.status, OutcomeState::Incomplete);
    let blocked_path = lifecycle_path(&f.prefix());
    assert!(blocked_path.exists());

    std::fs::remove_file(f.prefix().join("bin/sayaka")).unwrap();
    std::fs::remove_dir(f.prefix().join("bin")).unwrap();
    std::fs::remove_file(f.prefix().join(UPDATE_GUARD)).unwrap();
    std::fs::remove_file(f.prefix().join(MANIFEST)).unwrap();
    std::fs::remove_file(f.prefix().join(LOCK)).unwrap();
    std::fs::remove_dir(f.prefix()).unwrap();

    let install = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.4").unwrap();
    assert!(!install.preview().can_execute);
    let refused = install.execute(&Cancellation::default()).unwrap();
    assert_eq!(refused.status, OutcomeState::Refused);
    assert_eq!(recovery(&refused), blocked_path);
    assert!(!f.prefix().exists());

    std::fs::remove_file(&blocked_path).unwrap();
    let install_ok = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.4").unwrap();
    assert!(install_ok.preview().can_execute);
    assert_eq!(
        install_ok.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Installed
    );

    let removed = RemovePlan::prepare(&f.prefix())
        .unwrap()
        .execute(&Cancellation::default())
        .unwrap();
    assert_eq!(removed.status, OutcomeState::Removed);
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
fn lifecycle_record_replaced_after_preview_refuses_before_mutation() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(18));
    f.install_with("1.2.3");
    let remove = RemovePlan::prepare(&f.prefix()).unwrap();
    assert!(remove.preview().can_execute);
    let next = lifecycle_next_path(&f.prefix());
    std::fs::write(&next, b"pending").unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
    f.register(next.clone());
    let remove_result = remove.execute(&Cancellation::default()).unwrap();
    assert_eq!(remove_result.status, OutcomeState::Refused);
    assert_eq!(recovery(&remove_result), lifecycle_path(&f.prefix()));
    assert!(f.prefix().exists());

    let mut g = Fixture::new();
    g.set_source(&synthetic_macho(19));
    let install = InstallPlan::prepare(&g.prefix(), &g.source(), "1.2.3").unwrap();
    assert!(install.preview().can_execute);
    let install_next = lifecycle_next_path(&g.prefix());
    std::fs::write(&install_next, b"pending").unwrap();
    std::fs::set_permissions(&install_next, std::fs::Permissions::from_mode(0o600)).unwrap();
    g.register(install_next.clone());
    let install_result = install.execute(&Cancellation::default()).unwrap();
    assert_eq!(install_result.status, OutcomeState::Refused);
    assert_eq!(recovery(&install_result), lifecycle_path(&g.prefix()));
    assert!(!g.prefix().exists());
    g.cleanup();
    f.cleanup();
}

#[test]
fn guard_created_before_record_crash_refuses_without_cleanup() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(20));
    f.install_with("1.2.3");
    let before_hash = digest(&f.prefix().join("bin/sayaka"));
    f.set_source(&synthetic_macho(21));
    let (update, preview) = Update::prepare(
        &f.prefix(),
        &f.source(),
        "1.2.4",
        UpdatePolicy {
            allow_same_version_replace: true,
            ..UpdatePolicy::default()
        },
    )
    .unwrap();
    let result = update
        .execute_with(preview, &Cancellation::default(), |point, _| {
            if point == Point::UpdateGuardCreated {
                return Err(fail());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(result.status, OutcomeState::Incomplete);
    assert!(f.prefix().join(UPDATE_GUARD).exists());
    assert!(!lifecycle_path(&f.prefix()).exists());
    let remove = RemovePlan::prepare(&f.prefix()).unwrap();
    assert!(!remove.preview().can_execute);
    assert_eq!(
        remove.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Refused
    );
    f.set_source(&synthetic_macho(20));
    let install = InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.3").unwrap();
    assert!(!install.preview().can_execute);
    assert_eq!(
        install.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Refused
    );
    let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
    assert!(!recover.preview().can_execute);
    assert_eq!(
        recover.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Refused
    );
    assert_eq!(digest(&f.prefix().join("bin/sayaka")), before_hash);
    f.register_layout(&f.prefix());
    f.register(f.prefix().join(UPDATE_GUARD));
    f.cleanup();
}

#[test]
fn completed_historical_sidecar_does_not_poison_recover_after_reinstall() {
    let mut f = Fixture::new();
    f.set_source(&synthetic_macho(22));
    f.install_with("1.2.3");
    f.set_source(&synthetic_macho(23));
    assert_eq!(
        UpdatePlan::prepare(&f.prefix(), &f.source(), "1.2.4", UpdatePolicy::default())
            .unwrap()
            .execute(&Cancellation::default())
            .unwrap()
            .status,
        OutcomeState::Updated
    );
    assert_eq!(
        RemovePlan::prepare(&f.prefix())
            .unwrap()
            .execute(&Cancellation::default())
            .unwrap()
            .status,
        OutcomeState::Removed
    );
    f.set_source(&synthetic_macho(24));
    assert_eq!(
        InstallPlan::prepare(&f.prefix(), &f.source(), "1.2.5")
            .unwrap()
            .execute(&Cancellation::default())
            .unwrap()
            .status,
        OutcomeState::Installed
    );
    let recover = RecoverPlan::prepare(&f.prefix()).unwrap();
    assert_eq!(
        recover.preview().decision.as_deref(),
        Some("historical lifecycle outcome is not applicable to the current package")
    );
    assert_eq!(
        recover.execute(&Cancellation::default()).unwrap().status,
        OutcomeState::Recovered
    );
    assert_eq!(
        UpdatePlan::prepare(
            &f.prefix(),
            &f.source(),
            "1.2.5",
            UpdatePolicy {
                allow_same_version_replace: true,
                ..UpdatePolicy::default()
            }
        )
        .unwrap()
        .execute(&Cancellation::default())
        .unwrap()
        .status,
        OutcomeState::AlreadyInstalled
    );
    f.register_layout(&f.prefix());
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
#[ignore = "requires explicitly built baseline binary via SAYAKA_TEST_BASELINE_BINARY"]
fn baseline_v1_remove_refuses_pending_guarded_update_state_opt_in() {
    let baseline = PathBuf::from(
        std::env::var_os("SAYAKA_TEST_BASELINE_BINARY")
            .expect("SAYAKA_TEST_BASELINE_BINARY must be set for baseline-v1 interop test"),
    );
    let metadata = std::fs::metadata(&baseline)
        .expect("SAYAKA_TEST_BASELINE_BINARY must point to an existing file");
    assert!(
        metadata.is_file(),
        "SAYAKA_TEST_BASELINE_BINARY must point to a regular file"
    );
    let mut f = Fixture::new();
    let install = std::process::Command::new(&baseline)
        .args(["install", "--execute", "--json", "--prefix"])
        .arg(f.prefix())
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "baseline install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );
    let original_hash = digest(&f.prefix().join("bin/sayaka"));
    f.set_source(&synthetic_macho(25));
    let (update, preview) = Update::prepare(
        &f.prefix(),
        &f.source(),
        "0.1.0",
        UpdatePolicy {
            allow_same_version_replace: true,
            ..UpdatePolicy::default()
        },
    )
    .unwrap();
    let pending = update
        .execute_with(preview, &Cancellation::default(), |point, _| {
            if point == Point::UpdateStagedRecorded {
                return Err(fail());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(pending.status, OutcomeState::Incomplete);
    assert!(f.prefix().join(UPDATE_GUARD).exists());
    let old_remove = std::process::Command::new(&baseline)
        .args(["remove", "--execute", "--json", "--prefix"])
        .arg(f.prefix())
        .output()
        .unwrap();
    assert!(
        !old_remove.status.success(),
        "old v1 remove unexpectedly succeeded: {} {}",
        String::from_utf8_lossy(&old_remove.stdout),
        String::from_utf8_lossy(&old_remove.stderr)
    );
    assert!(f.prefix().exists());
    assert_eq!(digest(&f.prefix().join("bin/sayaka")), original_hash);
    assert!(f.prefix().join(UPDATE_GUARD).exists());
    f.register_layout(&f.prefix());
    f.register(f.prefix().join(UPDATE_GUARD));
    f.register_dynamic_installation_artifacts();
    f.cleanup();
}

#[test]
fn execution_and_benign_extended_metadata_do_not_invalidate_historical_ownership() {
    let mut f = Fixture::new();
    f.install();
    let executable = f.prefix().join("bin/sayaka");
    let output = std::process::Command::new(&executable).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"installation fixture\n");
    assert!(
        std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "com.sayaka.installation-fixture", "benign metadata"])
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let result = RemovePlan::prepare(&f.prefix())
        .unwrap()
        .execute(&Cancellation::default())
        .unwrap();
    assert_eq!(result.status, OutcomeState::Removed, "{result:?}");
    f.cleanup();
}
