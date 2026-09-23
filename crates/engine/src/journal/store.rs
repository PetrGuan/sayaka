// SPDX-License-Identifier: MPL-2.0

use super::*;
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const NOFOLLOW_ANY: OFlags = OFlags::from_bits_retain(0x2000_0000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishPoint {
    AfterRenameDirectorySync,
    FinalFileSync,
    MarkerRemoval,
    MarkerDirectorySync,
}

pub struct Store {
    directory: OwnedFd,
    _lock: OwnedFd,
    path: PathBuf,
}

impl Store {
    /// Create only the final private directory; its parent must already exist.
    /// Readers take the same lock, so Started cannot be called interrupted while
    /// another Sayaka process still owns the execution session.
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        validate_state_directory_path(path)?;
        if create {
            let parent = path
                .parent()
                .ok_or_else(|| invalid("state directory has no parent"))?;
            let name = path
                .file_name()
                .ok_or_else(|| invalid("state directory has no name"))?;
            let fd = fs::open(
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | NOFOLLOW_ANY,
                Mode::empty(),
            )?;
            match fs::mkdirat(&fd, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    fs::fsync(&fd)?;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | NOFOLLOW_ANY,
            Mode::empty(),
        )?;
        let stat = fs::fstat(&directory)?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(invalid(
                "state directory must be owned by this user with mode 0700",
            ));
        }
        check_acl(&directory)?;
        let volume = fs::fstatfs(&directory)?;
        if volume.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(invalid("journal requires a local filesystem"));
        }
        let flags = OFlags::RDWR
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if create {
                OFlags::CREATE
            } else {
                OFlags::empty()
            };
        let lock = fs::openat(&directory, ".lock", flags, Mode::from_raw_mode(0o600))?;
        check_file(&lock)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("state directory is busy or cannot be locked: {error}"),
            )
        })?;
        let named = fs::statat(&directory, ".lock", AtFlags::SYMLINK_NOFOLLOW)?;
        let held = fs::fstat(&lock)?;
        if named.st_ino != held.st_ino || named.st_dev != held.st_dev {
            return Err(invalid("journal lock changed"));
        }
        fs::fsync(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
            path: path.to_owned(),
        })
    }

    fn unchanged(&self) -> io::Result<()> {
        let current = fs::open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | NOFOLLOW_ANY,
            Mode::empty(),
        )?;
        let old = fs::fstat(&self.directory)?;
        let new = fs::fstat(&current)?;
        if old.st_dev != new.st_dev
            || old.st_ino != new.st_ino
            || new.st_uid != rustix::process::geteuid().as_raw()
            || new.st_mode & 0o077 != 0
        {
            return Err(invalid("journal directory identity or permissions changed"));
        }
        check_acl(&current)?;
        Ok(())
    }

    pub(crate) fn new_id(&self) -> io::Result<String> {
        let snapshot = self.records()?;
        if !snapshot.uncommitted_snapshots.is_empty() {
            return Err(invalid(
                "uncommitted journal snapshots exist; inspect receipts and archive state before a new operation",
            ));
        }
        if snapshot.records.len() >= MAX_RECORDS {
            return Err(invalid(
                "journal record limit reached; export and explicitly archive completed records",
            ));
        }
        let counter = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Ok(format!(
            "{:x}-{:x}-{:x}",
            std::process::id(),
            now_ms()?,
            counter
        ))
    }

    pub(crate) fn publish(&self, record: &Record, initial: bool) -> io::Result<Publication> {
        self.publish_with(record, initial, |_| Ok(()))
    }

    fn publish_with(
        &self,
        record: &Record,
        initial: bool,
        mut checkpoint: impl FnMut(PublishPoint) -> io::Result<()>,
    ) -> io::Result<Publication> {
        record.validate()?;
        self.unchanged()?;
        let name = format!("{}.json", record.operation_id);
        let marker = format!("{}.pending", record.operation_id);
        let stage = format!("{}.next", record.operation_id);
        let previous = if initial {
            match fs::statat(&self.directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(_) => return Err(invalid("journal operation identifier already exists")),
                Err(error) => return Err(error.into()),
            }
            None
        } else {
            Some(self.read_record(&name)?.0)
        };
        let mut fallback = record.clone();
        for (index, item) in fallback.items.iter_mut().enumerate() {
            let old = previous.as_ref().and_then(|old| old.items.get(index));
            if matches!(item.state, ItemState::Succeeded | ItemState::Failed)
                && old.is_none_or(|old| old.state != item.state)
            {
                item.state = ItemState::Unknown;
                item.reason = Some("outcome_publication_not_confirmed".into());
            }
        }
        // Keep a durably named conservative receipt until the final receipt has
        // passed every durability barrier. Rename must not consume this marker.
        let marker_file = self.write_snapshot(&marker, &fallback)?;
        fs::fsync(&self.directory)?;
        sayaka_platform_macos::full_sync(&marker_file)?;
        let file = self.write_snapshot(&stage, record)?;
        self.unchanged()?;
        fs::renameat(&self.directory, &stage, &self.directory, &name)?;
        checkpoint(PublishPoint::AfterRenameDirectorySync)?;
        fs::fsync(&self.directory)?;
        checkpoint(PublishPoint::FinalFileSync)?;
        sayaka_platform_macos::full_sync(&file)?;

        // The receipt is already durable. Cleanup failure stops the caller but
        // must not be confused with failure to commit the native outcome.
        let cleanup = (|| {
            self.unchanged()?;
            checkpoint(PublishPoint::MarkerRemoval)?;
            fs::unlinkat(&self.directory, &marker, AtFlags::empty())?;
            checkpoint(PublishPoint::MarkerDirectorySync)?;
            fs::fsync(&self.directory)?;
            Ok::<(), io::Error>(())
        })();
        Ok(Publication {
            cleanup_error: cleanup.err().map(|error| {
                io::Error::new(
                    error.kind(),
                    format!("receipt is durable; publication marker cleanup failed: {error}"),
                )
            }),
        })
    }

    fn write_snapshot(&self, name: &str, record: &Record) -> io::Result<File> {
        record.validate()?;
        let bytes = serde_json::to_vec(record)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("journal record exceeds byte budget"));
        }
        let fd = fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        check_file(&fd)?;
        let mut file = File::from(fd);
        file.write_all(&bytes)?;
        sayaka_platform_macos::full_sync(&file)?;
        Ok(file)
    }

    fn read_record(&self, name: &str) -> io::Result<(Record, usize)> {
        let fd = fs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        check_file(&fd)?;
        let mut data = Vec::new();
        File::from(fd)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut data)?;
        if data.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("journal record exceeds byte budget"));
        }
        let record: Record = serde_json::from_slice(&data)?;
        record.validate()?;
        if name
            .strip_suffix(".json")
            .or_else(|| name.strip_suffix(".pending"))
            != Some(record.operation_id.as_str())
        {
            return Err(invalid("journal filename and record identity disagree"));
        }
        Ok((record, data.len()))
    }

    pub fn records(&self) -> io::Result<JournalRead> {
        self.unchanged()?;
        let mut records = Vec::new();
        let mut uncommitted_snapshots = Vec::new();
        let mut total_bytes = 0;
        let mut names = std::collections::BTreeMap::<String, (bool, bool)>::new();
        let fd = fs::openat(
            &self.directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut entries = fs::Dir::new(fd)?;
        while let Some(entry) = entries.read() {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." || bytes == b".lock" {
                continue;
            }
            let name =
                std::str::from_utf8(bytes).map_err(|_| invalid("unrecognized journal entry"))?;
            let (id, pending, next) = if let Some(id) = name.strip_suffix(".pending") {
                (id, true, false)
            } else if let Some(id) = name.strip_suffix(".next") {
                (id, false, true)
            } else if let Some(id) = name.strip_suffix(".json") {
                (id, false, false)
            } else {
                return Err(invalid("unrecognized journal entry"));
            };
            if !valid_id(id) {
                return Err(invalid("invalid journal filename"));
            }
            if pending || next {
                uncommitted_snapshots.push(name.to_owned());
            }
            let entry = names.entry(id.to_owned()).or_default();
            if !next {
                if pending {
                    entry.1 = true;
                } else {
                    entry.0 = true;
                }
            }
            if names.len() > MAX_RECORDS {
                return Err(invalid("journal record count exceeds budget"));
            }
        }
        for (id, (committed, pending)) in names {
            if !committed && !pending {
                return Err(invalid("orphaned journal staging snapshot"));
            }
            let suffix = if pending { "pending" } else { "json" };
            let (record, length) = self.read_record(&format!("{id}.{suffix}"))?;
            total_bytes += length;
            if total_bytes > MAX_READ_BYTES {
                return Err(invalid("journal read exceeds total byte budget"));
            }
            records.push(record.reconciled());
        }
        records.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        uncommitted_snapshots.sort();
        Ok(JournalRead {
            records,
            uncommitted_snapshots,
        })
    }
}

fn check_file(fd: &OwnedFd) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(invalid(
            "journal files must be private, singly linked, user-owned regular files",
        ));
    }

    check_acl(fd)
}

fn check_acl(fd: &OwnedFd) -> io::Result<()> {
    let file = File::from(fd.try_clone()?);
    if sayaka_platform_macos::has_extended_acl(&file)? {
        return Err(invalid(
            "journal storage must not have extended ACL entries",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix(".sayaka-journal-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::write(
            directory.path().join("owner-marker"),
            b"sayaka-m3-journal-fixture",
        )
        .unwrap();
        directory
    }

    fn sample() -> Record {
        Record {
            schema_version: 1,
            plan_schema_version: 2,
            engine_version: 2,
            rules_version: 1,
            operation_id: "a-1".into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::from_path(Path::new("/fixture")),
            clean_policy: None,
            created_unix_ms: 1,
            items: vec![ItemRecord {
                path: NativePath::from_path(Path::new("/fixture/file")),
                device: 1,
                inode: 2,
                logical_bytes: 10,
                state: ItemState::Planned,
                reason: None,
                destination: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: 1,
            }],
        }
    }

    #[test]
    fn persisted_intent_reopens_as_unknown_and_lock_is_exclusive() {
        let fixture = fixture();
        let state = fixture.path().canonicalize().unwrap().join("state");
        let store = Store::open(&state, true).unwrap();
        assert!(Store::open(&state, true).is_err());
        let mut record = sample();
        store.publish(&record, true).unwrap();
        record.items[0].state = ItemState::Started;
        store.publish(&record, false).unwrap();
        drop(store);
        let reopened = Store::open(&state, false).unwrap();
        assert_eq!(
            reopened.records().unwrap().records[0].items[0].state,
            ItemState::Unknown
        );
        drop(reopened);
        fixture.close().unwrap();
    }

    #[test]
    fn symlink_or_public_state_is_refused() {
        let fixture = fixture();
        let root = fixture.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("public")).unwrap();
        std::fs::set_permissions(root.join("public"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(Store::open(&root.join("public"), true).is_err());
        symlink(root.join("public"), root.join("alias")).unwrap();
        assert!(Store::open(&root.join("alias"), true).is_err());
        assert!(Store::open(&root.join("alias/new"), true).is_err());
        assert!(!root.join("public/new").exists());
        fixture.close().unwrap();
    }

    #[test]
    fn pending_snapshot_is_visible_without_hiding_committed_intent() {
        let fixture = fixture();
        let state = fixture.path().canonicalize().unwrap().join("state");
        let store = Store::open(&state, true).unwrap();
        let mut record = sample();
        record.items[0].state = ItemState::Started;
        store.publish(&record, true).unwrap();
        store.write_snapshot("a-1.pending", &record).unwrap();
        let read = store.records().unwrap();
        assert_eq!(read.records[0].items[0].state, ItemState::Unknown);
        assert_eq!(read.uncommitted_snapshots, ["a-1.pending"]);
        assert!(store.new_id().is_err());
        drop(store);
        fixture.close().unwrap();
    }

    #[test]
    fn corruption_and_unsafe_record_files_are_errors() {
        let fixture = fixture();
        let root = fixture.path().canonicalize().unwrap();
        let store = Store::open(&root.join("state"), true).unwrap();
        store.publish(&sample(), true).unwrap();
        let path = root.join("state/a-1.json");
        std::fs::write(&path, b"{").unwrap();
        assert!(store.records().is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(root.join("owner-marker"), &path).unwrap();
        assert!(store.records().is_err());
        drop(store);
        fixture.close().unwrap();
    }

    #[test]
    fn post_rename_sync_failures_cannot_reopen_as_success() {
        for point in [
            PublishPoint::AfterRenameDirectorySync,
            PublishPoint::FinalFileSync,
        ] {
            let fixture = fixture();
            let state = fixture.path().canonicalize().unwrap().join("state");
            let store = Store::open(&state, true).unwrap();
            let mut record = sample();
            record.items[0].state = ItemState::Succeeded;
            record.items[0].destination =
                Some(NativePath::from_path(Path::new("/fixture-trash/first")));
            let mut second = sample().items.remove(0);
            second.path = NativePath::from_path(Path::new("/fixture/second"));
            second.inode = 3;
            second.state = ItemState::Started;
            record.items.push(second);
            store
                .publish(&record, true)
                .unwrap()
                .require_clean()
                .unwrap();
            record.items[1].state = ItemState::Succeeded;
            record.items[1].destination =
                Some(NativePath::from_path(Path::new("/fixture-trash/second")));
            let result = store.publish_with(&record, false, |current| {
                if current == point {
                    Err(io::Error::other("injected post-rename sync failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            assert_eq!(
                store.read_record("a-1.json").unwrap().0.items[1].state,
                ItemState::Succeeded
            );
            drop(store);
            let reopened = Store::open(&state, false).unwrap();
            let read = reopened.records().unwrap();
            assert_eq!(read.records[0].items[0].state, ItemState::Succeeded);
            assert_eq!(read.records[0].items[1].state, ItemState::Unknown);
            assert_eq!(read.uncommitted_snapshots, ["a-1.pending"]);
            assert!(reopened.new_id().is_err());
            drop(reopened);
            fixture.close().unwrap();
        }
    }

    #[test]
    fn marker_cleanup_failures_are_distinct_from_outcome_commit_failures() {
        for point in [
            PublishPoint::MarkerRemoval,
            PublishPoint::MarkerDirectorySync,
        ] {
            let fixture = fixture();
            let state = fixture.path().canonicalize().unwrap().join("state");
            let store = Store::open(&state, true).unwrap();
            let mut record = sample();
            record.items[0].state = ItemState::Started;
            store
                .publish(&record, true)
                .unwrap()
                .require_clean()
                .unwrap();
            record.items[0].state = ItemState::Succeeded;
            record.items[0].destination =
                Some(NativePath::from_path(Path::new("/fixture-trash/file")));
            let publication = store
                .publish_with(&record, false, |current| {
                    if current == point {
                        Err(io::Error::other("injected marker cleanup failure"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap();
            assert!(
                publication
                    .cleanup_error
                    .unwrap()
                    .to_string()
                    .contains("receipt is durable")
            );
            let read = store.records().unwrap();
            assert_eq!(
                read.records[0].items[0].state,
                if point == PublishPoint::MarkerRemoval {
                    ItemState::Unknown
                } else {
                    ItemState::Succeeded
                }
            );
            drop(store);
            fixture.close().unwrap();
        }
    }

    #[test]
    fn corrupt_pending_receipt_does_not_expose_committed_success() {
        let fixture = fixture();
        let state = fixture.path().canonicalize().unwrap().join("state");
        let store = Store::open(&state, true).unwrap();
        let mut record = sample();
        record.items[0].state = ItemState::Succeeded;
        record.items[0].destination = Some(NativePath::from_path(Path::new("/fixture-trash/file")));
        store
            .publish(&record, true)
            .unwrap()
            .require_clean()
            .unwrap();
        std::fs::write(state.join("a-1.pending"), b"{").unwrap();
        assert!(store.records().is_err());
        drop(store);
        fixture.close().unwrap();
    }

    #[test]
    fn owned_child_crash_preserves_unknown_without_replay() {
        const CHILD_ROOT: &str = "SAYAKA_M3_JOURNAL_CHILD_ROOT";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(path);
            let parent = Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .unwrap();
            assert_eq!(root.parent(), Some(parent.as_path()));
            assert!(
                root.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".sayaka-journal-")
            );
            assert_eq!(
                std::fs::read(root.join("owner-marker")).unwrap(),
                b"sayaka-m3-journal-fixture"
            );
            let store = Store::open(&root.join("state"), true).unwrap();
            let mut record = sample();
            record.items[0].state = ItemState::Started;
            store.publish(&record, true).unwrap();
            if std::env::var_os("SAYAKA_M3_AFTER_EFFECT").is_some() {
                std::fs::write(root.join("synthetic-effect"), b"once").unwrap();
            }
            std::process::exit(73);
        }
        for after_effect in [false, true] {
            let fixture = fixture();
            let root = fixture.path().canonicalize().unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "journal::store::tests::owned_child_crash_preserves_unknown_without_replay",
                    "--nocapture",
                ])
                .env(CHILD_ROOT, &root)
                .env_remove("SAYAKA_M3_AFTER_EFFECT")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            if after_effect {
                command.env("SAYAKA_M3_AFTER_EFFECT", "1");
            }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("owned journal child timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(73));
            let store = Store::open(&root.join("state"), false).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    store.records().unwrap().records[0].items[0].state,
                    ItemState::Unknown
                );
                assert_eq!(root.join("synthetic-effect").exists(), after_effect);
            }
            drop(store);
            fixture.close().unwrap();
        }
    }
}
