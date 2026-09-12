// SPDX-License-Identifier: MPL-2.0

use super::{Action, NativePath, Outcome, OutcomeState, Preview};
use crate::model::Cancellation;
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST: &str = "ownership-v1.json";
const LOCK: &str = ".lock";
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024;
const CHUNK: usize = 64 * 1024;
// Darwin O_NOFOLLOW_ANY: refuse symlinks in every component, not just the leaf.
const NOFOLLOW_ANY: OFlags = OFlags::from_bits_retain(0x2000_0000);
static NEXT_NAME: AtomicU64 = AtomicU64::new(1);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn cancelled(cancellation: &Cancellation) -> io::Result<()> {
    if cancellation.is_cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "operation cancelled",
        ))
    } else {
        Ok(())
    }
}

fn physical_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        || path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|p| p == b".")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use an absolute physical path without '.' or '..'",
        ));
    }
    Ok(())
}

fn open_at(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    Ok(File::from(fs::openat(
        parent,
        name,
        OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            },
        Mode::empty(),
    )?))
}

fn acl(file: &File) -> io::Result<()> {
    if sayaka_platform_macos::has_extended_acl(file)? {
        return Err(invalid(
            "extended ACLs are not permitted on managed artifacts or source",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Identity {
    fn of(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self::from_metadata(&m))
    }

    fn from_metadata(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    identity: Identity,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Snapshot {
    fn of(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            identity: Identity::from_metadata(&m),
            links: m.nlink(),
            bytes: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        })
    }
}

fn check(file: &File, directory: bool, mode: u32) -> io::Result<Identity> {
    let m = file.metadata()?;
    if m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != mode
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(invalid(format!(
            "artifact must be user-owned, {} with mode {mode:04o}",
            if directory {
                "a physical directory"
            } else {
                "a singly linked regular file"
            }
        )));
    }
    acl(file)?;
    Identity::of(file)
}

fn named(parent: &File, name: &OsStr, file: &File) -> io::Result<()> {
    let s = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let m = file.metadata()?;
    if s.st_dev as u64 != m.dev() || s.st_ino != m.ino() || u32::from(s.st_mode) != m.mode() {
        return Err(invalid(
            "named artifact no longer matches its held descriptor",
        ));
    }
    Ok(())
}

fn inventory(directory: &File, expected: &[&str]) -> io::Result<()> {
    let fd = fs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut entries = fs::Dir::new(fd)?;
    let mut seen = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if seen.len() >= expected.len() || !expected.iter().any(|p| p.as_bytes() == name) {
            return Err(invalid(
                "unknown or extra artifact in dedicated installation",
            ));
        }
        seen.push(name.to_vec());
    }
    if seen.len() != expected.len() {
        return Err(invalid(
            "managed inventory is incomplete; an expected artifact is missing",
        ));
    }
    Ok(())
}

struct Parent {
    file: File,
    path: PathBuf,
    name: OsString,
    identity: Identity,
}

impl Parent {
    fn open(prefix: &Path) -> io::Result<Self> {
        physical_absolute(prefix)?;
        if rustix::process::geteuid().as_raw() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "privileged installation/removal is not supported",
            ));
        }
        let path = prefix
            .parent()
            .ok_or_else(|| invalid("prefix needs a dedicated leaf name"))?;
        let name = prefix
            .file_name()
            .ok_or_else(|| invalid("prefix needs a dedicated leaf name"))?;
        let file = File::from(fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | NOFOLLOW_ANY, Mode::empty())
            .map_err(|e| io::Error::new(io::Error::from(e).kind(), format!("prefix parent must already exist physically; choose or explicitly prepare a parent: {e}")))?);
        if fs::fstatfs(&file)?.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(invalid(
                "dedicated installations require a local filesystem",
            ));
        }
        let identity = Identity::of(&file)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            name: name.to_owned(),
            identity,
        })
    }

    fn unchanged(&self) -> io::Result<()> {
        let current = File::from(fs::open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | NOFOLLOW_ANY,
            Mode::empty(),
        )?);
        if Identity::of(&current)? != self.identity || Identity::of(&self.file)? != self.identity {
            return Err(invalid("prefix parent changed since preparation"));
        }
        Ok(())
    }

    fn absent(&self, name: &OsStr) -> io::Result<()> {
        match fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "prefix or recovery location already exists; never overwritten",
            )),
            Err(e) => Err(e.into()),
        }
    }

    fn recovery_name(&self, purpose: &str) -> OsString {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            ".sayaka-{purpose}-{}-{nonce:x}-{}",
            std::process::id(),
            NEXT_NAME.fetch_add(1, Ordering::Relaxed)
        )
        .into()
    }
}

fn version_valid(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
}

struct Source {
    file: File,
    snapshot: Snapshot,
    digest: String,
}

impl Source {
    fn open(path: &Path) -> io::Result<Self> {
        physical_absolute(path)?;
        let mut file = File::from(fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | NOFOLLOW_ANY | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o7022 != 0
            || m.mode() & 0o500 != 0o500
            || m.len() == 0
            || m.len() > MAX_BINARY
        {
            return Err(invalid(
                "source must be a nonempty, bounded, user-owned, singly linked executable without special bits or group/other write permission",
            ));
        }
        acl(&file)?;
        let snapshot = Snapshot::of(&file)?;
        let digest = stream(&mut file, None, snapshot.bytes, &Cancellation::default())?;
        if Snapshot::of(&file)? != snapshot {
            return Err(invalid("source metadata changed while hashing"));
        }
        Ok(Self {
            file,
            snapshot,
            digest,
        })
    }

    fn copy(
        &mut self,
        destination: Option<&mut File>,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        if Snapshot::of(&self.file)? != self.snapshot {
            return Err(invalid("source identity or metadata changed since preview"));
        }
        acl(&self.file)?;
        let digest = stream(
            &mut self.file,
            destination,
            self.snapshot.bytes,
            cancellation,
        )?;
        if digest != self.digest || Snapshot::of(&self.file)? != self.snapshot {
            return Err(invalid("source content or metadata changed during copy"));
        }
        Ok(())
    }
}

fn stream(
    source: &mut File,
    mut destination: Option<&mut File>,
    length: u64,
    cancellation: &Cancellation,
) -> io::Result<String> {
    if length == 0 || length > MAX_BINARY {
        return Err(invalid("executable exceeds supported size bounds"));
    }
    source.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; CHUNK];
    loop {
        cancelled(cancellation)?;
        // Read at most the advertised length plus one byte to detect growth.
        let budget = ((length - total).saturating_add(1)).min(CHUNK as u64) as usize;
        let count = source.read(&mut buffer[..budget])?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > length {
            return Err(invalid("executable grew during bounded read"));
        }
        hash.update(&buffer[..count]);
        if let Some(output) = destination.as_mut() {
            output.write_all(&buffer[..count])?;
        }
    }
    cancelled(cancellation)?;
    if total != length {
        return Err(invalid("executable length changed during read"));
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    profile: String,
    version: String,
    sha256: String,
    executable_bytes: u64,
    prefix: Identity,
    bin: Identity,
    executable: Identity,
    manifest: Identity,
    lock: Identity,
}

impl Receipt {
    fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1
            || self.profile != "dedicated-macos-v1"
            || !version_valid(&self.version)
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.executable_bytes == 0
            || self.executable_bytes > MAX_BINARY
        {
            return Err(invalid("unsupported or malformed ownership manifest"));
        }
        Ok(())
    }

    fn preview(&self, prefix: &Path, action: Action) -> Preview {
        Preview {
            action,
            prefix: NativePath::from_path(prefix),
            executable: NativePath::from_path(&prefix.join("bin/sayaka")),
            version: self.version.clone(),
            sha256: self.sha256.clone(),
            executable_bytes: self.executable_bytes,
            already_installed: false,
        }
    }
}

struct Package {
    root: File,
    bin: File,
    executable: File,
    manifest: File,
    lock: File,
    receipt: Receipt,
    snapshots: [Snapshot; 3],
}

impl Package {
    fn open(parent: &Parent, name: &OsStr) -> io::Result<Self> {
        let root = open_at(&parent.file, name, true)?;
        check(&root, true, 0o700)?;
        inventory(&root, &["bin", MANIFEST, LOCK])?;
        let lock = open_at(&root, OsStr::new(LOCK), false)?;
        check(&lock, false, 0o600)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("installation is busy or cannot be locked: {e}"),
            )
        })?;
        let bin = open_at(&root, OsStr::new("bin"), true)?;
        check(&bin, true, 0o700)?;
        let executable = open_at(&bin, OsStr::new("sayaka"), false)?;
        check(&executable, false, 0o700)?;
        let mut manifest = open_at(&root, OsStr::new(MANIFEST), false)?;
        check(&manifest, false, 0o600)?;
        let before = Snapshot::of(&manifest)?;
        if before.bytes > MAX_MANIFEST {
            return Err(invalid("ownership manifest exceeds size bound"));
        }
        let mut bytes = Vec::new();
        (&mut manifest)
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST || Snapshot::of(&manifest)? != before {
            return Err(invalid("ownership manifest changed during read"));
        }
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        receipt.validate()?;
        let snapshots = [Snapshot::of(&executable)?, before, Snapshot::of(&lock)?];
        let mut package = Self {
            root,
            bin,
            executable,
            manifest,
            lock,
            receipt,
            snapshots,
        };
        package.verify(parent, name, 0, &Cancellation::default())?;
        Ok(package)
    }

    // `removed` is progress in the fixed payload/bin/lock/manifest/root order.
    // Missing objects are accepted only after this operation removed them.
    fn verify(
        &mut self,
        parent: &Parent,
        name: &OsStr,
        removed: usize,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        cancelled(cancellation)?;
        parent.unchanged()?;
        named(&parent.file, name, &self.root)?;
        if check(&self.root, true, 0o700)? != self.receipt.prefix {
            return Err(invalid("prefix identity changed"));
        }
        let expected: &[&str] = match removed {
            0 | 1 => &["bin", MANIFEST, LOCK],
            2 => &[MANIFEST, LOCK],
            3 => &[MANIFEST],
            4 => &[],
            _ => return Err(invalid("invalid removal progress")),
        };
        inventory(&self.root, expected)?;
        if removed < 2 {
            named(&self.root, OsStr::new("bin"), &self.bin)?;
            if check(&self.bin, true, 0o700)? != self.receipt.bin {
                return Err(invalid("bin identity changed"));
            }
            inventory(&self.bin, if removed == 0 { &["sayaka"] } else { &[] })?;
        }
        for (file, container, name, identity, snapshot, present, mode) in [
            (
                &self.executable,
                &self.bin,
                "sayaka",
                &self.receipt.executable,
                &self.snapshots[0],
                removed == 0,
                0o700,
            ),
            (
                &self.manifest,
                &self.root,
                MANIFEST,
                &self.receipt.manifest,
                &self.snapshots[1],
                removed < 4,
                0o600,
            ),
            (
                &self.lock,
                &self.root,
                LOCK,
                &self.receipt.lock,
                &self.snapshots[2],
                removed < 3,
                0o600,
            ),
        ] {
            if !present {
                continue;
            }
            named(container, OsStr::new(name), file)?;
            if check(file, false, mode)? != *identity || Snapshot::of(file)? != *snapshot {
                return Err(invalid(format!(
                    "managed {name} identity or metadata changed"
                )));
            }
        }
        if removed == 0
            && (self.snapshots[0].bytes != self.receipt.executable_bytes
                || stream(
                    &mut self.executable,
                    None,
                    self.receipt.executable_bytes,
                    cancellation,
                )? != self.receipt.sha256
                || Snapshot::of(&self.executable)? != self.snapshots[0])
        {
            return Err(invalid(
                "installed executable does not match ownership digest",
            ));
        }
        if removed < 3 && self.lock.metadata()?.len() != 0 {
            return Err(invalid("managed lock must be empty"));
        }
        cancelled(cancellation)
    }

    fn footprint(&self) -> io::Result<(u64, u64)> {
        let mut logical = 0u64;
        let mut allocated = 0u64;
        for file in [&self.executable, &self.manifest, &self.lock] {
            let m = file.metadata()?;
            logical = logical
                .checked_add(m.len())
                .ok_or_else(|| invalid("logical footprint overflow"))?;
            allocated = allocated
                .checked_add(
                    m.blocks()
                        .checked_mul(512)
                        .ok_or_else(|| invalid("allocated footprint overflow"))?,
                )
                .ok_or_else(|| invalid("allocated footprint overflow"))?;
        }
        Ok((logical, allocated))
    }

    fn sync_published(
        &self,
        parent: &Parent,
        cancellation: &Cancellation,
        hook: &mut impl FnMut(Point, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let prefix = parent.path.join(&parent.name);
        // A visible receipt does not prove that a previous publisher completed
        // its barriers. Explicit execution must establish durability afresh.
        for (point, file) in [
            (Point::SyncExecutable, &self.executable),
            (Point::SyncManifest, &self.manifest),
            (Point::SyncLock, &self.lock),
        ] {
            cancelled(cancellation)?;
            hook(point, &prefix)?;
            sayaka_platform_macos::full_sync(file)?;
        }
        for (point, directory) in [
            (Point::SyncBin, &self.bin),
            (Point::SyncRoot, &self.root),
            (Point::SyncParent, &parent.file),
        ] {
            cancelled(cancellation)?;
            hook(point, &prefix)?;
            fs::fsync(directory)?;
        }
        cancelled(cancellation)?;
        hook(Point::FinalFullSync, &prefix)?;
        sayaka_platform_macos::full_sync(&self.manifest)
    }
}

fn outcome(
    preview: Preview,
    status: OutcomeState,
    footprint: Option<(u64, u64)>,
    recovery: Option<&Path>,
    error: Option<io::Error>,
) -> Outcome {
    Outcome {
        status,
        preview,
        logical_bytes: footprint.map(|p| p.0),
        allocated_bytes: footprint.map(|p| p.1),
        recovery_paths: recovery.into_iter().map(NativePath::from_path).collect(),
        error: error.map(|e| e.to_string()),
    }
}

fn create_file(parent: &File, name: &str, mode: u32) -> io::Result<File> {
    let file = File::from(fs::openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode as u16),
    )?);
    check(&file, false, mode)?;
    Ok(file)
}

fn create_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    fs::mkdirat(parent, name, Mode::from_raw_mode(0o700))?;
    let file = open_at(parent, name, true)?;
    check(&file, true, 0o700)?;
    Ok(file)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    StageCreated,
    Copied,
    BeforePublish,
    Published,
    SyncExecutable,
    SyncManifest,
    SyncLock,
    SyncBin,
    SyncRoot,
    SyncParent,
    FinalFullSync,
    Detached,
    PayloadRemoved,
    BinRemoved,
    LockRemoved,
    ManifestRemoved,
    RootRemoved,
}

pub(super) struct Install {
    parent: Parent,
    source: Source,
    existing: Option<Package>,
}

impl Install {
    pub(super) fn prepare(
        prefix: &Path,
        source: &Path,
        version: &str,
    ) -> io::Result<(Self, Preview)> {
        if !version_valid(version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded installation version",
            ));
        }
        let parent = Parent::open(prefix)?;
        let source = Source::open(source)?;
        let existing = match parent.absent(&parent.name) {
            Ok(()) => None,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let package = Package::open(&parent, &parent.name)?;
                if package.receipt.sha256 != source.digest
                    || package.receipt.executable_bytes != source.snapshot.bytes
                    || package.receipt.version != version
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "verified prefix contains a different image or version; no local update fallback",
                    ));
                }
                Some(package)
            }
            Err(e) => return Err(e),
        };
        let preview = Preview {
            action: Action::Install,
            prefix: NativePath::from_path(prefix),
            executable: NativePath::from_path(&prefix.join("bin/sayaka")),
            version: version.to_owned(),
            sha256: source.digest.clone(),
            executable_bytes: source.snapshot.bytes,
            already_installed: existing.is_some(),
        };
        Ok((
            Self {
                parent,
                source,
                existing,
            },
            preview,
        ))
    }

    pub(super) fn execute(
        self,
        preview: Preview,
        cancellation: &Cancellation,
    ) -> io::Result<Outcome> {
        self.execute_with(preview, cancellation, |_, _| Ok(()))
    }

    fn execute_with(
        mut self,
        preview: Preview,
        cancellation: &Cancellation,
        mut hook: impl FnMut(Point, &Path) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        self.parent.unchanged()?;
        self.source.copy(None, cancellation)?;
        if let Some(mut package) = self.existing {
            package.verify(&self.parent, &self.parent.name, 0, cancellation)?;
            let recovery = self.parent.path.join(&self.parent.name);
            let result = (|| {
                package.sync_published(&self.parent, cancellation, &mut hook)?;
                package.verify(&self.parent, &self.parent.name, 0, cancellation)?;
                package.footprint()
            })();
            return Ok(match result {
                Ok(bytes) => outcome(
                    preview,
                    OutcomeState::AlreadyInstalled,
                    Some(bytes),
                    None,
                    None,
                ),
                Err(e) => outcome(
                    preview,
                    OutcomeState::Incomplete,
                    None,
                    Some(&recovery),
                    Some(e),
                ),
            });
        }
        self.parent.absent(&self.parent.name)?;
        cancelled(cancellation)?;
        let staging = self.parent.recovery_name("stage");
        let mut recovery = self.parent.path.join(&staging);
        // Once mkdir succeeds every subsequent error must carry this exact path.
        fs::mkdirat(&self.parent.file, &staging, Mode::from_raw_mode(0o700))?;
        let result = (|| {
            hook(Point::StageCreated, &recovery)?;
            cancelled(cancellation)?;
            self.parent.unchanged()?;
            let root = open_at(&self.parent.file, &staging, true)?;
            let root_id = check(&root, true, 0o700)?;
            inventory(&root, &[])?;
            let lock = create_file(&root, LOCK, 0o600)?;
            fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
            let bin = create_directory(&root, OsStr::new("bin"))?;
            let mut executable = create_file(&bin, "sayaka", 0o700)?;
            self.source.copy(Some(&mut executable), cancellation)?;
            hook(Point::Copied, &recovery)?;
            cancelled(cancellation)?;
            let mut manifest = create_file(&root, MANIFEST, 0o600)?;
            let receipt = Receipt {
                schema_version: 1,
                profile: "dedicated-macos-v1".into(),
                version: preview.version.clone(),
                sha256: preview.sha256.clone(),
                executable_bytes: preview.executable_bytes,
                prefix: root_id,
                bin: Identity::of(&bin)?,
                executable: Identity::of(&executable)?,
                manifest: Identity::of(&manifest)?,
                lock: Identity::of(&lock)?,
            };
            let bytes = serde_json::to_vec(&receipt)?;
            if bytes.len() as u64 > MAX_MANIFEST {
                return Err(invalid("generated manifest exceeds size bound"));
            }
            manifest.write_all(&bytes)?;
            for file in [&executable, &manifest, &lock] {
                sayaka_platform_macos::full_sync(file)?;
            }
            fs::fsync(&bin)?;
            fs::fsync(&root)?;
            fs::fsync(&self.parent.file)?;
            let snapshots = [
                Snapshot::of(&executable)?,
                Snapshot::of(&manifest)?,
                Snapshot::of(&lock)?,
            ];
            let mut package = Package {
                root,
                bin,
                executable,
                manifest,
                lock,
                receipt,
                snapshots,
            };
            hook(Point::BeforePublish, &recovery)?;
            package.verify(&self.parent, &staging, 0, cancellation)?;
            self.parent.absent(&self.parent.name)?;
            fs::renameat_with(
                &self.parent.file,
                &staging,
                &self.parent.file,
                &self.parent.name,
                RenameFlags::NOREPLACE,
            )?;
            recovery = self.parent.path.join(&self.parent.name);
            hook(Point::Published, &recovery)?;
            package.sync_published(&self.parent, cancellation, &mut hook)?;
            package.verify(&self.parent, &self.parent.name, 0, cancellation)?;
            package.footprint()
        })();
        Ok(match result {
            Ok(bytes) => outcome(preview, OutcomeState::Installed, Some(bytes), None, None),
            Err(e) => outcome(
                preview,
                OutcomeState::Incomplete,
                None,
                Some(&recovery),
                Some(e),
            ),
        })
    }
}

pub(super) struct Remove {
    parent: Parent,
    package: Package,
}

impl Remove {
    pub(super) fn prepare(prefix: &Path) -> io::Result<(Self, Preview)> {
        let parent = Parent::open(prefix)?;
        let package = Package::open(&parent, &parent.name)?;
        let preview = package.receipt.preview(prefix, Action::Remove);
        Ok((Self { parent, package }, preview))
    }

    pub(super) fn execute(
        self,
        preview: Preview,
        cancellation: &Cancellation,
    ) -> io::Result<Outcome> {
        self.execute_with(preview, cancellation, |_, _| Ok(()))
    }

    fn execute_with(
        mut self,
        preview: Preview,
        cancellation: &Cancellation,
        mut hook: impl FnMut(Point, &Path) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        self.package
            .verify(&self.parent, &self.parent.name, 0, cancellation)?;
        let bytes = self.package.footprint()?;
        let detached = self.parent.recovery_name("remove");
        self.parent.absent(&detached)?;
        cancelled(cancellation)?;
        // Only the fully verified, locked inventory is moved. Never user extras.
        fs::renameat_with(
            &self.parent.file,
            &self.parent.name,
            &self.parent.file,
            &detached,
            RenameFlags::NOREPLACE,
        )?;
        let recovery = self.parent.path.join(&detached);
        let result = (|| {
            hook(Point::Detached, &recovery)?;
            fs::fsync(&self.parent.file)?;
            self.package
                .verify(&self.parent, &detached, 0, cancellation)?;
            fs::unlinkat(&self.package.bin, "sayaka", AtFlags::empty())?;
            hook(Point::PayloadRemoved, &recovery)?;
            fs::fsync(&self.package.bin)?;
            self.package
                .verify(&self.parent, &detached, 1, cancellation)?;
            fs::unlinkat(&self.package.root, "bin", AtFlags::REMOVEDIR)?;
            hook(Point::BinRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 2, cancellation)?;
            fs::unlinkat(&self.package.root, LOCK, AtFlags::empty())?;
            hook(Point::LockRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 3, cancellation)?;
            fs::unlinkat(&self.package.root, MANIFEST, AtFlags::empty())?;
            hook(Point::ManifestRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 4, cancellation)?;
            fs::unlinkat(&self.parent.file, &detached, AtFlags::REMOVEDIR)?;
            hook(Point::RootRemoved, &recovery)?;
            fs::fsync(&self.parent.file)?;
            // A final full sync is issued on a still-held regular descriptor.
            sayaka_platform_macos::full_sync(&self.package.manifest)?;
            Ok(())
        })();
        Ok(match result {
            Ok(()) => outcome(preview, OutcomeState::Removed, Some(bytes), None, None),
            Err(e) => outcome(
                preview,
                OutcomeState::Incomplete,
                None,
                Some(&recovery),
                Some(e),
            ),
        })
    }
}

#[cfg(test)]
mod tests;
