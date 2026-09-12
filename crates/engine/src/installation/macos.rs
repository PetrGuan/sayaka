// SPDX-License-Identifier: MPL-2.0

use super::{Action, ArtifactMetadata, NativePath, Outcome, OutcomeState, Preview, UpdatePolicy};
use crate::model::Cancellation;
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use semver::Version;
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
const LIFECYCLE_SUFFIX: &str = ".sayaka-lifecycle-v1.json";
const UPDATE_GUARD: &str = ".sayaka-update-guard-v1";
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024;
const MAX_LIFECYCLE: u64 = 64 * 1024;
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

    fn lifecycle_name(&self) -> OsString {
        let mut encoded = String::new();
        for b in self.name.as_encoded_bytes() {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "{b:02x}");
        }
        format!(".{encoded}{LIFECYCLE_SUFFIX}").into()
    }
}

fn version_valid(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetMetadata {
    target_os: String,
    target_arch: String,
    min_macos: Option<String>,
    verified_macho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionOrder {
    Newer,
    Equal,
    Older,
    Unknown,
}

fn compare_versions(current: &str, candidate: &str) -> VersionOrder {
    match (Version::parse(current), Version::parse(candidate)) {
        (Ok(a), Ok(b)) if b > a => VersionOrder::Newer,
        (Ok(a), Ok(b)) if b == a => VersionOrder::Equal,
        (Ok(_), Ok(_)) => VersionOrder::Older,
        _ => VersionOrder::Unknown,
    }
}

fn decode_version(raw: u32) -> String {
    format!("{}.{}.{}", raw >> 16, (raw >> 8) & 0xff, raw & 0xff)
}

fn compiled_target_metadata() -> TargetMetadata {
    let min = option_env!("MACOSX_DEPLOYMENT_TARGET")
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    TargetMetadata {
        target_os: std::env::consts::OS.to_owned(),
        target_arch: std::env::consts::ARCH.to_owned(),
        min_macos: min,
        verified_macho: false,
    }
}

fn detect_target_metadata(path: &Path) -> io::Result<TargetMetadata> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header)?;
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if matches!(magic, 0xcafebabe | 0xbebafeca | 0xcafebabf | 0xbfbafeca) {
        return Err(invalid(
            "universal/fat Mach-O binaries are unsupported for local update",
        ));
    }
    let le_magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if !matches!(le_magic, 0xfeedface | 0xfeedfacf) {
        return Ok(compiled_target_metadata());
    }
    let cputype = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let ncmds = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let sizeofcmds = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    if sizeofcmds > 1024 * 1024 {
        return Err(invalid("Mach-O load commands exceed supported bounds"));
    }
    let mut commands = vec![0u8; sizeofcmds as usize];
    file.read_exact(&mut commands)?;
    let mut offset = 0usize;
    let mut min = None;
    for _ in 0..ncmds {
        if offset + 8 > commands.len() {
            return Err(invalid("truncated Mach-O load command header"));
        }
        let cmd = u32::from_le_bytes(commands[offset..offset + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(commands[offset + 4..offset + 8].try_into().unwrap());
        if cmdsize < 8 || offset + cmdsize as usize > commands.len() {
            return Err(invalid("invalid Mach-O load command size"));
        }
        if cmd == 0x32 && cmdsize >= 16 {
            let raw = u32::from_le_bytes(commands[offset + 12..offset + 16].try_into().unwrap());
            min = Some(decode_version(raw));
        } else if cmd == 0x24 && cmdsize >= 16 {
            let raw = u32::from_le_bytes(commands[offset + 8..offset + 12].try_into().unwrap());
            min = Some(decode_version(raw));
        }
        offset += cmdsize as usize;
    }
    let target_arch = match cputype {
        0x0100_0007 => "x86_64",
        0x0100_000c => "aarch64",
        _ => return Err(invalid("unsupported Mach-O architecture")),
    };
    Ok(TargetMetadata {
        target_os: "macos".into(),
        target_arch: target_arch.into(),
        min_macos: min.or_else(|| compiled_target_metadata().min_macos),
        verified_macho: true,
    })
}

struct Source {
    file: File,
    path: PathBuf,
    snapshot: Snapshot,
    digest: String,
    target: TargetMetadata,
}

impl Source {
    fn open(path: &Path) -> io::Result<Self> {
        physical_absolute(path)?;
        let target = detect_target_metadata(path)?;
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
            path: path.to_path_buf(),
            snapshot,
            digest,
            target,
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

    fn metadata(&self, version: &str) -> ArtifactMetadata {
        ArtifactMetadata {
            version: version.to_owned(),
            sha256: self.digest.clone(),
            executable_bytes: self.snapshot.bytes,
            target_os: self.target.target_os.clone(),
            target_arch: self.target.target_arch.clone(),
            min_macos: self.target.min_macos.clone(),
            ownership_layout: "dedicated-macos-v2".into(),
            lifecycle_contract: "local-update-recover-v1".into(),
            source_trust: format!(
                "local running executable copied from {}",
                self.path.display()
            ),
        }
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
    target_os: Option<String>,
    target_arch: Option<String>,
    min_macos: Option<String>,
    ownership_layout: Option<String>,
    lifecycle_contract: Option<String>,
}

impl Receipt {
    fn validate(&self) -> io::Result<()> {
        let common = version_valid(&self.version)
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.executable_bytes != 0
            && self.executable_bytes <= MAX_BINARY;
        let schema_ok = match self.schema_version {
            1 => self.profile == "dedicated-macos-v1",
            2 => {
                self.profile == "dedicated-macos-v2"
                    && self.target_os.as_deref() == Some("macos")
                    && self.target_arch.is_some()
                    && self.min_macos.is_some()
                    && self.ownership_layout.as_deref() == Some("dedicated-macos-v2")
                    && self.lifecycle_contract.as_deref() == Some("local-update-recover-v1")
            }
            _ => false,
        };
        if !common || !schema_ok {
            return Err(invalid("unsupported or malformed ownership manifest"));
        }
        Ok(())
    }

    fn preview(&self, prefix: &Path, action: Action) -> Preview {
        let current = Some(self.metadata("owned installed manifest"));
        Preview {
            action,
            prefix: NativePath::from_path(prefix),
            executable: NativePath::from_path(&prefix.join("bin/sayaka")),
            version: self.version.clone(),
            sha256: self.sha256.clone(),
            executable_bytes: self.executable_bytes,
            already_installed: false,
            current,
            candidate: None,
            can_execute: true,
            decision: None,
        }
    }

    fn metadata(&self, source_trust: &str) -> ArtifactMetadata {
        ArtifactMetadata {
            version: self.version.clone(),
            sha256: self.sha256.clone(),
            executable_bytes: self.executable_bytes,
            target_os: self.target_os.clone().unwrap_or_else(|| "macos".into()),
            target_arch: self
                .target_arch
                .clone()
                .unwrap_or_else(|| std::env::consts::ARCH.to_owned()),
            min_macos: self.min_macos.clone(),
            ownership_layout: self
                .ownership_layout
                .clone()
                .unwrap_or_else(|| "dedicated-macos-v1".into()),
            lifecycle_contract: self
                .lifecycle_contract
                .clone()
                .unwrap_or_else(|| "local-install-v1".into()),
            source_trust: source_trust.to_owned(),
        }
    }
}

struct Package {
    root: File,
    bin: File,
    executable: File,
    manifest: File,
    lock: File,
    guard: Option<File>,
    receipt: Receipt,
    snapshots: [Snapshot; 3],
    guard_snapshot: Option<Snapshot>,
}

impl Package {
    fn open(parent: &Parent, name: &OsStr) -> io::Result<Self> {
        Self::open_with(parent, name, true)
    }

    fn open_relaxed(parent: &Parent, name: &OsStr) -> io::Result<Self> {
        Self::open_with(parent, name, false)
    }

    fn open_with(parent: &Parent, name: &OsStr, require_payload_match: bool) -> io::Result<Self> {
        let root = open_at(&parent.file, name, true)?;
        check(&root, true, 0o700)?;
        let has_guard = guard_presence(&root)? == StagedPresence::Present;
        inventory(
            &root,
            if has_guard {
                &["bin", MANIFEST, LOCK, UPDATE_GUARD]
            } else {
                &["bin", MANIFEST, LOCK]
            },
        )?;
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
        let guard = match open_at(&root, OsStr::new(UPDATE_GUARD), false) {
            Ok(guard) => {
                check(&guard, false, 0o600)?;
                Some(guard)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
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
        let guard_snapshot = guard.as_ref().map(Snapshot::of).transpose()?;
        let snapshots = [Snapshot::of(&executable)?, before, Snapshot::of(&lock)?];
        let mut package = Self {
            root,
            bin,
            executable,
            manifest,
            lock,
            guard,
            receipt,
            snapshots,
            guard_snapshot,
        };
        package.verify(
            parent,
            name,
            0,
            &Cancellation::default(),
            require_payload_match,
        )?;
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
        require_payload_match: bool,
    ) -> io::Result<()> {
        cancelled(cancellation)?;
        parent.unchanged()?;
        named(&parent.file, name, &self.root)?;
        if check(&self.root, true, 0o700)? != self.receipt.prefix {
            return Err(invalid("prefix identity changed"));
        }
        let expected_with_guard: &[&str] = &["bin", MANIFEST, LOCK, UPDATE_GUARD];
        let expected_without_guard: &[&str] = &["bin", MANIFEST, LOCK];
        let expected: &[&str] = match removed {
            0 | 1 if self.guard.is_some() => expected_with_guard,
            0 | 1 => expected_without_guard,
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
        for (file, container, name, identity, snapshot, present, mode, strict_identity) in [
            (
                &self.executable,
                &self.bin,
                "sayaka",
                &self.receipt.executable,
                &self.snapshots[0],
                removed == 0,
                0o700,
                require_payload_match,
            ),
            (
                &self.manifest,
                &self.root,
                MANIFEST,
                &self.receipt.manifest,
                &self.snapshots[1],
                removed < 4,
                0o600,
                true,
            ),
            (
                &self.lock,
                &self.root,
                LOCK,
                &self.receipt.lock,
                &self.snapshots[2],
                removed < 3,
                0o600,
                true,
            ),
        ] {
            if !present {
                continue;
            }
            named(container, OsStr::new(name), file)?;
            let file_identity = check(file, false, mode)?;
            if strict_identity && (file_identity != *identity || Snapshot::of(file)? != *snapshot) {
                return Err(invalid(format!(
                    "managed {name} identity or metadata changed"
                )));
            }
        }
        if removed < 2 {
            if let Some(guard) = &self.guard {
                named(&self.root, OsStr::new(UPDATE_GUARD), guard)?;
                let identity = check(guard, false, 0o600)?;
                let snapshot = self
                    .guard_snapshot
                    .as_ref()
                    .ok_or_else(|| invalid("missing update guard snapshot"))?;
                if identity != snapshot.identity || Snapshot::of(guard)? != *snapshot {
                    return Err(invalid("managed update guard identity or metadata changed"));
                }
            } else if guard_presence(&self.root)? == StagedPresence::Present {
                return Err(invalid(
                    "unexpected update guard without tracked descriptor",
                ));
            }
        }
        if removed == 0
            && require_payload_match
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleStage {
    IntentRecorded,
    StagedRecorded,
    BinaryCommitted,
    ManifestCommitted,
    OutcomeRecorded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleOutcome {
    CandidatePublished,
    StagingAbandoned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedArtifactRecord {
    name: String,
    identity: Identity,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleRecord {
    schema_version: u32,
    action: String,
    stage: LifecycleStage,
    prefix_name: Vec<u8>,
    prefix: Identity,
    lock: Identity,
    current: ArtifactMetadata,
    candidate: ArtifactMetadata,
    guard: Option<StagedArtifactRecord>,
    staged_executable: Option<StagedArtifactRecord>,
    staged_manifest: Option<StagedArtifactRecord>,
    outcome: Option<LifecycleOutcome>,
}

impl LifecycleRecord {
    fn valid_staged_name(name: &str) -> bool {
        !name.is_empty()
            && !name.contains('/')
            && !name.contains('\0')
            && name != "."
            && name != ".."
            && name.starts_with(".sayaka-")
    }

    fn validate_shape(&self, parent: &Parent) -> io::Result<()> {
        if self.schema_version != 1
            || self.action != "update"
            || self.prefix_name != parent.name.as_encoded_bytes()
        {
            return Err(invalid("unsupported or mismatched lifecycle record"));
        }
        match (&self.staged_executable, &self.staged_manifest) {
            (Some(executable), Some(manifest))
                if Self::valid_staged_name(&executable.name)
                    && Self::valid_staged_name(&manifest.name)
                    && executable.bytes != 0
                    && executable.sha256.len() == 64
                    && manifest.bytes != 0
                    && manifest.sha256.len() == 64 => {}
            (None, None) if self.stage == LifecycleStage::IntentRecorded => {}
            _ => return Err(invalid("staged lifecycle metadata is malformed")),
        }
        if let Some(guard) = &self.guard
            && (!Self::valid_staged_name(&guard.name) || guard.sha256.len() != 64)
        {
            return Err(invalid("update guard lifecycle metadata is malformed"));
        }
        if self.stage >= LifecycleStage::StagedRecorded
            && (self.staged_executable.is_none() || self.staged_manifest.is_none())
        {
            return Err(invalid("staged lifecycle metadata is missing"));
        }
        if self.stage != LifecycleStage::OutcomeRecorded && self.guard.is_none() {
            return Err(invalid("update guard lifecycle metadata is missing"));
        }
        if self.stage == LifecycleStage::OutcomeRecorded && self.outcome.is_none() {
            return Err(invalid("lifecycle outcome is missing"));
        }
        Ok(())
    }
}

fn lifecycle_gate_decision(
    parent: &Parent,
    lifecycle_name: &OsStr,
    package: Option<&Package>,
) -> io::Result<Option<String>> {
    let next_name = format!("{}.next", lifecycle_name.to_string_lossy());
    match fs::statat(
        &parent.file,
        OsStr::new(&next_name),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => {
            return Ok(Some(
                "lifecycle next marker is pending; explicit recovery is required".into(),
            ));
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    let Some(record) = read_lifecycle(parent, lifecycle_name)? else {
        if let Some(package) = package
            && guard_presence(&package.root)? == StagedPresence::Present
        {
            return Ok(Some(
                "update guard is present without lifecycle record; explicit recovery is required"
                    .into(),
            ));
        }
        return Ok(None);
    };
    record
        .validate_shape(parent)
        .map_err(|error| invalid(format!("lifecycle evidence is malformed: {error}")))?;
    if record.stage != LifecycleStage::OutcomeRecorded {
        return Ok(Some(
            "update recovery evidence is pending; run `sayaka recover` first".into(),
        ));
    }
    if let Some(package) = package {
        let guard_state = match &record.guard {
            Some(guard) => validate_recorded_guard(package, guard)?,
            None => guard_presence(&package.root)?,
        };
        if guard_state == StagedPresence::Present {
            return Ok(Some(
                "completed lifecycle outcome still requires guard cleanup; run `sayaka recover` first"
                    .into(),
            ));
        }
    }
    Ok(None)
}

fn read_lifecycle(parent: &Parent, name: &OsStr) -> io::Result<Option<LifecycleRecord>> {
    let mut file = match open_at(&parent.file, name, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    check(&file, false, 0o600)?;
    let snapshot = Snapshot::of(&file)?;
    if snapshot.bytes > MAX_LIFECYCLE {
        return Err(invalid("lifecycle record exceeds size bound"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_LIFECYCLE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LIFECYCLE || Snapshot::of(&file)? != snapshot {
        return Err(invalid("lifecycle record changed during read"));
    }
    let value = serde_json::from_slice(&bytes)?;
    Ok(Some(value))
}

fn write_lifecycle(parent: &Parent, name: &OsStr, record: &LifecycleRecord) -> io::Result<()> {
    let mut next = name.to_os_string();
    next.push(".next");
    match fs::statat(&parent.file, &next, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            return Err(invalid(
                "lifecycle next marker already exists; explicit recovery is required",
            ));
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() as u64 > MAX_LIFECYCLE {
        return Err(invalid("lifecycle record exceeds size bound"));
    }
    let mut file = create_file(&parent.file, &next.to_string_lossy(), 0o600)?;
    file.write_all(&bytes)?;
    sayaka_platform_macos::full_sync(&file)?;
    fs::renameat_with(
        &parent.file,
        &next,
        &parent.file,
        name,
        RenameFlags::empty(),
    )?;
    fs::fsync(&parent.file)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagedPresence {
    Present,
    Missing,
}

fn guard_presence(root: &File) -> io::Result<StagedPresence> {
    match fs::statat(root, OsStr::new(UPDATE_GUARD), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(StagedPresence::Present),
        Err(rustix::io::Errno::NOENT) => Ok(StagedPresence::Missing),
        Err(error) => Err(error.into()),
    }
}

fn validate_staged_file(
    parent: &Parent,
    staged: &StagedArtifactRecord,
    mode: u32,
) -> io::Result<StagedPresence> {
    let mut file = match open_at(&parent.file, OsStr::new(&staged.name), false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(StagedPresence::Missing);
        }
        Err(error) => return Err(error),
    };
    let snapshot = Snapshot::of(&file)?;
    if snapshot.bytes != staged.bytes {
        return Err(invalid("staged artifact size changed"));
    }
    let identity = check(&file, false, mode)?;
    if identity != staged.identity {
        return Err(invalid(format!(
            "staged artifact identity changed: expected dev={} ino={} mode={:o} uid={} gid={}, observed dev={} ino={} mode={:o} uid={} gid={}",
            staged.identity.device,
            staged.identity.inode,
            staged.identity.mode,
            staged.identity.uid,
            staged.identity.gid,
            identity.device,
            identity.inode,
            identity.mode,
            identity.uid,
            identity.gid
        )));
    }
    let digest = stream(&mut file, None, snapshot.bytes, &Cancellation::default())?;
    if digest != staged.sha256 || Snapshot::of(&file)? != snapshot {
        return Err(invalid("staged artifact bytes changed"));
    }
    Ok(StagedPresence::Present)
}

fn validate_recorded_guard(
    package: &Package,
    guard: &StagedArtifactRecord,
) -> io::Result<StagedPresence> {
    let mut file = match open_at(&package.root, OsStr::new(UPDATE_GUARD), false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(StagedPresence::Missing);
        }
        Err(error) => return Err(error),
    };
    let snapshot = Snapshot::of(&file)?;
    if snapshot.bytes != guard.bytes {
        return Err(invalid("update guard size changed"));
    }
    let identity = check(&file, false, 0o600)?;
    if identity != guard.identity {
        return Err(invalid("update guard identity changed"));
    }
    let digest = if snapshot.bytes == 0 {
        format!("{:x}", Sha256::digest(b""))
    } else {
        stream(&mut file, None, snapshot.bytes, &Cancellation::default())?
    };
    if digest != guard.sha256 || Snapshot::of(&file)? != snapshot {
        return Err(invalid("update guard bytes changed"));
    }
    Ok(StagedPresence::Present)
}

fn package_executable_digest(package: &mut Package) -> io::Result<String> {
    let snapshot = Snapshot::of(&package.executable)?;
    let digest = stream(
        &mut package.executable,
        None,
        snapshot.bytes,
        &Cancellation::default(),
    )?;
    if Snapshot::of(&package.executable)? != snapshot {
        return Err(invalid(
            "installed executable changed while collecting recovery evidence",
        ));
    }
    Ok(digest)
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
    UpdateGuardCreated,
    UpdateIntentRecorded,
    UpdateStaged,
    UpdateStagedRecorded,
    UpdateAfterBinaryRename,
    UpdateAfterBinarySync,
    UpdateBinaryCommitted,
    UpdateAfterManifestRename,
    UpdateAfterManifestSync,
    UpdateManifestCommitted,
    UpdateOutcomeRecorded,
    UpdateBeforeGuardRemove,
    UpdateAfterGuardRemove,
    RecoverBeforeExecutableUnlink,
    RecoverAfterExecutableUnlink,
    RecoverBeforeManifestUnlink,
    RecoverAfterManifestUnlink,
    RecoverBeforeManifestRename,
    RecoverAfterManifestRename,
    RecoverAfterManifestSync,
    RecoverBeforeGuardRemove,
    RecoverAfterGuardRemove,
    RecoverBeforeOutcomeRecord,
    RecoverAfterOutcomeRecord,
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
    lifecycle_name: OsString,
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
        let lifecycle_name = parent.lifecycle_name();
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
        let decision = lifecycle_gate_decision(&parent, &lifecycle_name, existing.as_ref())?;
        let preview = Preview {
            action: Action::Install,
            prefix: NativePath::from_path(prefix),
            executable: NativePath::from_path(&prefix.join("bin/sayaka")),
            version: version.to_owned(),
            sha256: source.digest.clone(),
            executable_bytes: source.snapshot.bytes,
            already_installed: existing.is_some(),
            current: existing
                .as_ref()
                .map(|package| package.receipt.metadata("owned installed manifest")),
            candidate: Some(source.metadata(version)),
            can_execute: decision.is_none(),
            decision,
        };
        Ok((
            Self {
                parent,
                source,
                existing,
                lifecycle_name,
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
        let lifecycle_path = self.parent.path.join(&self.lifecycle_name);
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        if !preview.can_execute {
            let error = preview.decision.clone();
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error,
            });
        }
        if let Some(decision) =
            lifecycle_gate_decision(&self.parent, &self.lifecycle_name, self.existing.as_ref())?
        {
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error: Some(decision),
            });
        }
        self.parent.unchanged()?;
        self.source.copy(None, cancellation)?;
        if let Some(mut package) = self.existing {
            package.verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
            let recovery = self.parent.path.join(&self.parent.name);
            let result = (|| {
                package.sync_published(&self.parent, cancellation, &mut hook)?;
                package.verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
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
            let write_v2 = self.source.target.verified_macho
                && self.source.target.target_os == "macos"
                && self.source.target.target_arch == std::env::consts::ARCH
                && self.source.target.min_macos.is_some();
            let receipt = Receipt {
                schema_version: if write_v2 { 2 } else { 1 },
                profile: if write_v2 {
                    "dedicated-macos-v2".into()
                } else {
                    "dedicated-macos-v1".into()
                },
                version: preview.version.clone(),
                sha256: preview.sha256.clone(),
                executable_bytes: preview.executable_bytes,
                prefix: root_id,
                bin: Identity::of(&bin)?,
                executable: Identity::of(&executable)?,
                manifest: Identity::of(&manifest)?,
                lock: Identity::of(&lock)?,
                target_os: write_v2.then(|| self.source.target.target_os.clone()),
                target_arch: write_v2.then(|| self.source.target.target_arch.clone()),
                min_macos: write_v2
                    .then(|| self.source.target.min_macos.clone())
                    .flatten(),
                ownership_layout: write_v2.then(|| "dedicated-macos-v2".into()),
                lifecycle_contract: write_v2.then(|| "local-update-recover-v1".into()),
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
                guard: None,
                receipt,
                snapshots,
                guard_snapshot: None,
            };
            hook(Point::BeforePublish, &recovery)?;
            package.verify(&self.parent, &staging, 0, cancellation, true)?;
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
            package.verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
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

pub(super) struct Update {
    parent: Parent,
    package: Package,
    source: Source,
    policy: UpdatePolicy,
    lifecycle_name: OsString,
}

impl Update {
    pub(super) fn prepare(
        prefix: &Path,
        source: &Path,
        version: &str,
        policy: UpdatePolicy,
    ) -> io::Result<(Self, Preview)> {
        if !version_valid(version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded installation version",
            ));
        }
        let parent = Parent::open(prefix)?;
        let source = Source::open(source)?;
        let package = Package::open(&parent, &parent.name)?;
        let lifecycle_name = parent.lifecycle_name();
        let gate_decision = lifecycle_gate_decision(&parent, &lifecycle_name, Some(&package))?;
        let current = package.receipt.metadata("owned installed manifest");
        let candidate = source.metadata(version);
        let mut can_execute = gate_decision.is_none();
        let decision = if let Some(decision) = gate_decision {
            Some(decision)
        } else if !source.target.verified_macho {
            can_execute = false;
            Some("candidate Mach-O metadata is unavailable; compatibility is unproven".into())
        } else if candidate.target_os != "macos" {
            can_execute = false;
            Some("candidate target OS is not macOS".into())
        } else if candidate.target_arch != std::env::consts::ARCH {
            can_execute = false;
            Some(format!(
                "candidate arch {} does not match running arch {}",
                candidate.target_arch,
                std::env::consts::ARCH
            ))
        } else if candidate.min_macos.is_none() {
            can_execute = false;
            Some("candidate minOS metadata is unavailable; compatibility is unproven".into())
        } else if !matches!(
            current.ownership_layout.as_str(),
            "dedicated-macos-v1" | "dedicated-macos-v2"
        ) {
            can_execute = false;
            Some("current ownership layout is unsupported for local update".into())
        } else if current.sha256 == candidate.sha256 && current.version == candidate.version {
            Some(
                "candidate matches installed bytes; execute only reruns durability barriers".into(),
            )
        } else {
            match compare_versions(&current.version, &candidate.version) {
                VersionOrder::Unknown => {
                    can_execute = false;
                    Some("current/candidate versions are not SemVer-orderable".into())
                }
                VersionOrder::Older if !policy.allow_downgrade => {
                    can_execute = false;
                    Some("candidate is older; pass --allow-downgrade to execute".into())
                }
                VersionOrder::Equal
                    if current.sha256 != candidate.sha256 && !policy.allow_same_version_replace =>
                {
                    can_execute = false;
                    Some(
                        "same version has different bytes; pass --allow-same-version-replace to execute"
                            .into(),
                    )
                }
                VersionOrder::Older => Some("downgrade explicitly allowed by policy".into()),
                VersionOrder::Equal => Some("same-version replacement explicitly allowed".into()),
                VersionOrder::Newer => Some("candidate is newer and compatible".into()),
            }
        };
        let preview = Preview {
            action: Action::Update,
            prefix: NativePath::from_path(prefix),
            executable: NativePath::from_path(&prefix.join("bin/sayaka")),
            version: candidate.version.clone(),
            sha256: candidate.sha256.clone(),
            executable_bytes: candidate.executable_bytes,
            already_installed: current.sha256 == candidate.sha256
                && current.version == candidate.version,
            current: Some(current),
            candidate: Some(candidate),
            can_execute,
            decision,
        };
        Ok((
            Self {
                parent,
                package,
                source,
                policy,
                lifecycle_name,
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
        let prefix_path = self.parent.path.join(&self.parent.name);
        let lifecycle_path = self.parent.path.join(&self.lifecycle_name);
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        if !preview.can_execute {
            let error = preview.decision.clone();
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: Vec::new(),
                error,
            });
        }
        if let Some(decision) =
            lifecycle_gate_decision(&self.parent, &self.lifecycle_name, Some(&self.package))?
        {
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error: Some(decision),
            });
        }
        let _ = self.policy;
        self.parent.unchanged()?;
        self.package
            .verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
        self.source.copy(None, cancellation)?;
        if preview.already_installed {
            let result = (|| {
                self.package
                    .sync_published(&self.parent, cancellation, &mut hook)?;
                self.package
                    .verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
                self.package.footprint()
            })();
            return Ok(match result {
                Ok(bytes) => outcome(
                    preview,
                    OutcomeState::AlreadyInstalled,
                    Some(bytes),
                    None,
                    None,
                ),
                Err(error) => Outcome {
                    status: OutcomeState::Incomplete,
                    preview,
                    logical_bytes: None,
                    allocated_bytes: None,
                    recovery_paths: vec![
                        NativePath::from_path(&prefix_path),
                        NativePath::from_path(&lifecycle_path),
                    ],
                    error: Some(error.to_string()),
                },
            });
        }
        let current = preview
            .current
            .clone()
            .ok_or_else(|| invalid("missing current metadata"))?;
        let candidate = preview
            .candidate
            .clone()
            .ok_or_else(|| invalid("missing candidate metadata"))?;
        let staged_executable_name = self.parent.recovery_name("update-bin");
        let staged_manifest_name = self.parent.recovery_name("update-manifest");
        let mut record = LifecycleRecord {
            schema_version: 1,
            action: "update".into(),
            stage: LifecycleStage::IntentRecorded,
            prefix_name: self.parent.name.as_encoded_bytes().to_vec(),
            prefix: self.package.receipt.prefix.clone(),
            lock: self.package.receipt.lock.clone(),
            current,
            candidate,
            guard: None,
            staged_executable: None,
            staged_manifest: None,
            outcome: None,
        };
        let result = (|| {
            let guard = create_file(&self.package.root, UPDATE_GUARD, 0o600)?;
            sayaka_platform_macos::full_sync(&guard)?;
            fs::fsync(&self.package.root)?;
            hook(Point::UpdateGuardCreated, &lifecycle_path)?;
            let guard_snapshot = Snapshot::of(&guard)?;
            self.package.guard = Some(guard);
            self.package.guard_snapshot = Some(guard_snapshot.clone());
            record.guard = Some(StagedArtifactRecord {
                name: UPDATE_GUARD.into(),
                identity: guard_snapshot.identity.clone(),
                bytes: guard_snapshot.bytes,
                sha256: format!("{:x}", Sha256::digest(b"")),
            });
            write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
            hook(Point::UpdateIntentRecorded, &lifecycle_path)?;
            let mut staged_bin = create_file(
                &self.parent.file,
                &staged_executable_name.to_string_lossy(),
                0o700,
            )?;
            self.source.copy(Some(&mut staged_bin), cancellation)?;
            let staged_bin_identity = Identity::of(&staged_bin)?;
            let staged_bin_snapshot = Snapshot::of(&staged_bin)?;
            let mut staged_manifest_file = create_file(
                &self.parent.file,
                &staged_manifest_name.to_string_lossy(),
                0o600,
            )?;
            let next_receipt = Receipt {
                schema_version: 2,
                profile: "dedicated-macos-v2".into(),
                version: record.candidate.version.clone(),
                sha256: record.candidate.sha256.clone(),
                executable_bytes: record.candidate.executable_bytes,
                prefix: self.package.receipt.prefix.clone(),
                bin: self.package.receipt.bin.clone(),
                executable: staged_bin_identity.clone(),
                manifest: Identity::of(&staged_manifest_file)?,
                lock: self.package.receipt.lock.clone(),
                target_os: Some(record.candidate.target_os.clone()),
                target_arch: Some(record.candidate.target_arch.clone()),
                min_macos: record.candidate.min_macos.clone(),
                ownership_layout: Some("dedicated-macos-v2".into()),
                lifecycle_contract: Some("local-update-recover-v1".into()),
            };
            let manifest_bytes = serde_json::to_vec(&next_receipt)?;
            if manifest_bytes.len() as u64 > MAX_MANIFEST {
                return Err(invalid("generated update manifest exceeds size bound"));
            }
            staged_manifest_file.write_all(&manifest_bytes)?;
            sayaka_platform_macos::full_sync(&staged_bin)?;
            sayaka_platform_macos::full_sync(&staged_manifest_file)?;
            fs::fsync(&self.parent.file)?;
            hook(Point::UpdateStaged, &lifecycle_path)?;
            let staged_manifest_identity = Identity::of(&staged_manifest_file)?;
            let staged_manifest_snapshot = Snapshot::of(&staged_manifest_file)?;
            record.staged_executable = Some(StagedArtifactRecord {
                name: staged_executable_name.to_string_lossy().to_string(),
                identity: staged_bin_identity,
                bytes: staged_bin_snapshot.bytes,
                sha256: record.candidate.sha256.clone(),
            });
            record.staged_manifest = Some(StagedArtifactRecord {
                name: staged_manifest_name.to_string_lossy().to_string(),
                identity: staged_manifest_identity,
                bytes: staged_manifest_snapshot.bytes,
                sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
            });
            record.stage = LifecycleStage::StagedRecorded;
            write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
            hook(Point::UpdateStagedRecorded, &lifecycle_path)?;
            self.package
                .verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
            self.source.copy(None, cancellation)?;
            let staged_executable = record
                .staged_executable
                .as_ref()
                .ok_or_else(|| invalid("missing staged executable metadata"))?;
            fs::renameat_with(
                &self.parent.file,
                OsStr::new(&staged_executable.name),
                &self.package.bin,
                OsStr::new("sayaka"),
                RenameFlags::empty(),
            )?;
            hook(Point::UpdateAfterBinaryRename, &lifecycle_path)?;
            fs::fsync(&self.package.bin)?;
            hook(Point::UpdateAfterBinarySync, &lifecycle_path)?;
            record.stage = LifecycleStage::BinaryCommitted;
            write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
            hook(Point::UpdateBinaryCommitted, &lifecycle_path)?;
            let staged_manifest = record
                .staged_manifest
                .as_ref()
                .ok_or_else(|| invalid("missing staged manifest metadata"))?;
            fs::renameat_with(
                &self.parent.file,
                OsStr::new(&staged_manifest.name),
                &self.package.root,
                OsStr::new(MANIFEST),
                RenameFlags::empty(),
            )?;
            hook(Point::UpdateAfterManifestRename, &lifecycle_path)?;
            fs::fsync(&self.package.root)?;
            hook(Point::UpdateAfterManifestSync, &lifecycle_path)?;
            record.stage = LifecycleStage::ManifestCommitted;
            write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
            hook(Point::UpdateManifestCommitted, &lifecycle_path)?;
            drop(self.package);
            let mut updated = Package::open(&self.parent, &self.parent.name)?;
            updated.sync_published(&self.parent, cancellation, &mut hook)?;
            updated.verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
            let bytes = updated.footprint()?;
            record.stage = LifecycleStage::OutcomeRecorded;
            record.outcome = Some(LifecycleOutcome::CandidatePublished);
            write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
            hook(Point::UpdateOutcomeRecorded, &lifecycle_path)?;
            let guard = record
                .guard
                .as_ref()
                .ok_or_else(|| invalid("missing update guard metadata"))?;
            if validate_recorded_guard(&updated, guard)? == StagedPresence::Present {
                hook(Point::UpdateBeforeGuardRemove, &lifecycle_path)?;
                fs::unlinkat(&updated.root, UPDATE_GUARD, AtFlags::empty())?;
                fs::fsync(&updated.root)?;
                hook(Point::UpdateAfterGuardRemove, &lifecycle_path)?;
            }
            Ok(bytes)
        })();
        Ok(match result {
            Ok(bytes) => outcome(preview, OutcomeState::Updated, Some(bytes), None, None),
            Err(error) => Outcome {
                status: OutcomeState::Incomplete,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![
                    NativePath::from_path(&prefix_path),
                    NativePath::from_path(&lifecycle_path),
                ],
                error: Some(error.to_string()),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverMode {
    None,
    AbandonStaged,
    FinalizeManifest,
    ConfirmOutcome,
    Manual,
}

pub(super) struct Recover {
    parent: Parent,
    lifecycle_name: OsString,
}

impl Recover {
    fn classify(
        parent: &Parent,
        package: &mut Package,
        lifecycle_next_exists: bool,
        record: Option<&LifecycleRecord>,
    ) -> io::Result<(RecoverMode, bool, String)> {
        if lifecycle_next_exists {
            return Ok((
                RecoverMode::Manual,
                false,
                "record update is partially published; manual inspection required".into(),
            ));
        }
        let Some(record) = record else {
            if guard_presence(&package.root)? == StagedPresence::Present {
                return Ok((
                    RecoverMode::Manual,
                    false,
                    "update guard is present without lifecycle record; manual recovery is required"
                        .into(),
                ));
            }
            return Ok((RecoverMode::None, true, "no recovery record found".into()));
        };
        record
            .validate_shape(parent)
            .map_err(|error| invalid(format!("lifecycle evidence is malformed: {error}")))?;
        let record_matches_package =
            record.prefix == package.receipt.prefix && record.lock == package.receipt.lock;
        let old_match = package.receipt.sha256 == record.current.sha256
            && package.receipt.version == record.current.version;
        let new_match = package.receipt.sha256 == record.candidate.sha256
            && package.receipt.version == record.candidate.version;
        let executable_digest = package_executable_digest(package)?;
        let executable_is_candidate = executable_digest == record.candidate.sha256;
        let executable_is_current = executable_digest == record.current.sha256;
        let (staged_executable, staged_manifest) = (
            record.staged_executable.as_ref(),
            record.staged_manifest.as_ref(),
        );
        let staged_executable_state = if let Some(staged) = staged_executable {
            validate_staged_file(parent, staged, 0o700)?
        } else {
            StagedPresence::Missing
        };
        let staged_manifest_state = if let Some(staged) = staged_manifest {
            validate_staged_file(parent, staged, 0o600)?
        } else {
            StagedPresence::Missing
        };
        let guard_state = if let Some(guard) = &record.guard {
            validate_recorded_guard(package, guard)?
        } else {
            guard_presence(&package.root)?
        };
        if !record_matches_package {
            return Ok(
                if record.stage == LifecycleStage::OutcomeRecorded
                    && staged_executable_state == StagedPresence::Missing
                    && staged_manifest_state == StagedPresence::Missing
                    && guard_state == StagedPresence::Missing
                {
                    (
                        RecoverMode::None,
                        true,
                        "historical lifecycle outcome is not applicable to the current package"
                            .into(),
                    )
                } else {
                    (
                        RecoverMode::Manual,
                        false,
                        "recovery evidence does not match current package identity".into(),
                    )
                },
            );
        }
        let (mode, can_execute, decision) = match record.stage {
            LifecycleStage::IntentRecorded => (
                RecoverMode::Manual,
                false,
                "stage identities were not durably recorded; preserve artifacts for manual recovery"
                    .into(),
            ),
            LifecycleStage::StagedRecorded
                if old_match
                    && executable_is_current
                    && staged_manifest_state == StagedPresence::Present
                    && guard_state == StagedPresence::Present =>
            {
                (
                    RecoverMode::AbandonStaged,
                    true,
                    if staged_executable_state == StagedPresence::Present {
                        "staged update not committed; recover can abandon staged files".into()
                    } else {
                        "staged executable already consumed; recover can finish abandoning staged files"
                            .into()
                    },
                )
            }
            LifecycleStage::StagedRecorded
                if old_match
                    && executable_is_current
                    && staged_executable_state == StagedPresence::Missing
                    && staged_manifest_state == StagedPresence::Missing
                    && guard_state == StagedPresence::Present =>
            {
                (
                    RecoverMode::ConfirmOutcome,
                    true,
                    "staged files already consumed; recover can record abandoned outcome".into(),
                )
            }
            LifecycleStage::StagedRecorded
                if old_match
                    && executable_is_candidate
                    && staged_executable_state == StagedPresence::Missing
                    && staged_manifest_state == StagedPresence::Present
                    && guard_state == StagedPresence::Present =>
            {
                (
                    RecoverMode::FinalizeManifest,
                    true,
                    "binary publish committed before lifecycle marker; recover can finalize manifest"
                        .into(),
                )
            }
            LifecycleStage::StagedRecorded
                if new_match
                    && executable_is_candidate
                    && staged_executable_state == StagedPresence::Missing
                    && staged_manifest_state == StagedPresence::Missing
                    && guard_state == StagedPresence::Present =>
            {
                (
                    RecoverMode::ConfirmOutcome,
                    true,
                    "manifest already reflects candidate; recover can confirm outcome".into(),
                )
            }
            LifecycleStage::BinaryCommitted
                if executable_is_candidate
                    && (old_match || new_match)
                    && guard_state == StagedPresence::Present
                    && (staged_manifest_state == StagedPresence::Present
                        || (new_match && staged_manifest_state == StagedPresence::Missing)) =>
            {
                if old_match {
                    (
                        RecoverMode::FinalizeManifest,
                        true,
                        "binary publish committed; recover can finalize manifest".into(),
                    )
                } else {
                    (
                        RecoverMode::ConfirmOutcome,
                        true,
                        "manifest already reflects candidate; recover can confirm outcome".into(),
                    )
                }
            }
            LifecycleStage::ManifestCommitted
                if new_match
                    && executable_is_candidate
                    && staged_manifest_state == StagedPresence::Missing
                    && guard_state == StagedPresence::Present =>
            {
                (
                    RecoverMode::ConfirmOutcome,
                    true,
                    "manifest committed; recover can confirm durability outcome".into(),
                )
            }
            LifecycleStage::OutcomeRecorded => {
                match record.outcome {
                    Some(LifecycleOutcome::StagingAbandoned)
                        if old_match
                            && executable_is_current
                            && staged_executable_state == StagedPresence::Missing
                            && staged_manifest_state == StagedPresence::Missing
                            && guard_state == StagedPresence::Missing =>
                    {
                        (
                            RecoverMode::None,
                            true,
                            "lifecycle abandon outcome already recorded; no further recovery action"
                                .into(),
                        )
                    }
                    Some(LifecycleOutcome::StagingAbandoned)
                        if old_match
                            && executable_is_current
                            && staged_executable_state == StagedPresence::Missing
                            && staged_manifest_state == StagedPresence::Missing
                            && guard_state == StagedPresence::Present =>
                    {
                        (
                            RecoverMode::ConfirmOutcome,
                            true,
                            "lifecycle abandon outcome recorded; recover can remove retained guard"
                                .into(),
                        )
                    }
                    Some(LifecycleOutcome::CandidatePublished)
                        if new_match
                            && executable_is_candidate
                            && guard_state == StagedPresence::Missing =>
                    {
                        (
                            RecoverMode::None,
                            true,
                            "lifecycle outcome already recorded; no further recovery action".into(),
                        )
                    }
                    Some(LifecycleOutcome::CandidatePublished)
                        if new_match
                            && executable_is_candidate
                            && guard_state == StagedPresence::Present =>
                    {
                        (
                            RecoverMode::ConfirmOutcome,
                            true,
                            "lifecycle outcome recorded; recover can remove retained guard".into(),
                        )
                    }
                    _ => (
                        RecoverMode::Manual,
                        false,
                        "recovery evidence does not match a recognized lifecycle window".into(),
                    ),
                }
            }
            _ => (
                RecoverMode::Manual,
                false,
                "recovery evidence does not match a recognized lifecycle window".into(),
            ),
        };
        Ok((mode, can_execute, decision))
    }

    fn decide_outcome(record: &LifecycleRecord, package: &Package) -> io::Result<LifecycleOutcome> {
        if package.receipt.sha256 == record.candidate.sha256
            && package.receipt.version == record.candidate.version
        {
            return Ok(LifecycleOutcome::CandidatePublished);
        }
        if package.receipt.sha256 == record.current.sha256
            && package.receipt.version == record.current.version
        {
            return Ok(LifecycleOutcome::StagingAbandoned);
        }
        Err(invalid(
            "recovered package state matches neither current nor candidate evidence",
        ))
    }

    pub(super) fn prepare(prefix: &Path) -> io::Result<(Self, Preview)> {
        let parent = Parent::open(prefix)?;
        let mut package = Package::open_relaxed(&parent, &parent.name)?;
        let lifecycle_name = parent.lifecycle_name();
        let next_name = format!("{}.next", lifecycle_name.to_string_lossy());
        let lifecycle_next_exists = match fs::statat(
            &parent.file,
            OsStr::new(&next_name),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(error) => return Err(error.into()),
        };
        let record = read_lifecycle(&parent, &lifecycle_name)?;
        let (_selected, can_execute, decision) = Self::classify(
            &parent,
            &mut package,
            lifecycle_next_exists,
            record.as_ref(),
        )?;
        let mut preview = package.receipt.preview(prefix, Action::Recover);
        preview.current = record
            .as_ref()
            .map(|value| value.current.clone())
            .or_else(|| Some(package.receipt.metadata("owned installed manifest")));
        preview.candidate = record.as_ref().map(|value| value.candidate.clone());
        preview.can_execute = can_execute;
        preview.decision = Some(decision);
        Ok((
            Self {
                parent,
                lifecycle_name,
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
        self,
        preview: Preview,
        cancellation: &Cancellation,
        mut hook: impl FnMut(Point, &Path) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        let lifecycle_path = self.parent.path.join(&self.lifecycle_name);
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        if !preview.can_execute {
            let error = preview.decision.clone();
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error,
            });
        }
        let next_name = format!("{}.next", self.lifecycle_name.to_string_lossy());
        let lifecycle_next_exists = match fs::statat(
            &self.parent.file,
            OsStr::new(&next_name),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(error) => return Err(error.into()),
        };
        let mut package = Package::open_relaxed(&self.parent, &self.parent.name)?;
        let record = read_lifecycle(&self.parent, &self.lifecycle_name)?;
        let (mode, can_execute, decision) = Self::classify(
            &self.parent,
            &mut package,
            lifecycle_next_exists,
            record.as_ref(),
        )?;
        if !can_execute {
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error: Some(decision),
            });
        }
        if matches!(mode, RecoverMode::None) && record.is_none() {
            package.verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
            let bytes = package.footprint()?;
            return Ok(outcome(
                preview,
                OutcomeState::Recovered,
                Some(bytes),
                None,
                None,
            ));
        }
        let result = (|| {
            match mode {
                RecoverMode::None => {}
                RecoverMode::AbandonStaged => {
                    let record = record
                        .as_ref()
                        .ok_or_else(|| invalid("missing lifecycle record"))?;
                    let staged_executable = record
                        .staged_executable
                        .as_ref()
                        .ok_or_else(|| invalid("missing staged executable metadata"))?;
                    let staged_manifest = record
                        .staged_manifest
                        .as_ref()
                        .ok_or_else(|| invalid("missing staged manifest metadata"))?;
                    if validate_staged_file(&self.parent, staged_executable, 0o700)?
                        == StagedPresence::Present
                    {
                        hook(Point::RecoverBeforeExecutableUnlink, &lifecycle_path)?;
                        fs::unlinkat(
                            &self.parent.file,
                            OsStr::new(&staged_executable.name),
                            AtFlags::empty(),
                        )?;
                        hook(Point::RecoverAfterExecutableUnlink, &lifecycle_path)?;
                    } else {
                        hook(Point::RecoverBeforeExecutableUnlink, &lifecycle_path)?;
                        hook(Point::RecoverAfterExecutableUnlink, &lifecycle_path)?;
                    }
                    if validate_staged_file(&self.parent, staged_manifest, 0o600)?
                        != StagedPresence::Present
                    {
                        return Err(invalid("staged artifacts changed before recovery execute"));
                    }
                    hook(Point::RecoverBeforeManifestUnlink, &lifecycle_path)?;
                    fs::unlinkat(
                        &self.parent.file,
                        OsStr::new(&staged_manifest.name),
                        AtFlags::empty(),
                    )?;
                    hook(Point::RecoverAfterManifestUnlink, &lifecycle_path)?;
                }
                RecoverMode::FinalizeManifest => {
                    let record = record
                        .as_ref()
                        .ok_or_else(|| invalid("missing lifecycle record"))?;
                    let staged_manifest = record
                        .staged_manifest
                        .as_ref()
                        .ok_or_else(|| invalid("missing staged manifest metadata"))?;
                    if validate_staged_file(&self.parent, staged_manifest, 0o600)?
                        != StagedPresence::Present
                    {
                        return Err(invalid(
                            "staged manifest changed before recovery finalize execute",
                        ));
                    }
                    if package_executable_digest(&mut package)? != record.candidate.sha256 {
                        return Err(invalid(
                            "installed executable no longer matches candidate commit evidence",
                        ));
                    }
                    hook(Point::RecoverBeforeManifestRename, &lifecycle_path)?;
                    fs::renameat_with(
                        &self.parent.file,
                        OsStr::new(&staged_manifest.name),
                        &package.root,
                        OsStr::new(MANIFEST),
                        RenameFlags::empty(),
                    )?;
                    hook(Point::RecoverAfterManifestRename, &lifecycle_path)?;
                    fs::fsync(&package.root)?;
                    hook(Point::RecoverAfterManifestSync, &lifecycle_path)?;
                }
                RecoverMode::ConfirmOutcome => {}
                RecoverMode::Manual => {
                    return Err(io::Error::other(
                        "manual inspection required; recovery could not classify lifecycle state",
                    ));
                }
            }
            drop(package);
            let package = Package::open(&self.parent, &self.parent.name)?;
            package.sync_published(&self.parent, cancellation, &mut |_, _| Ok(()))?;
            let mut wrote_outcome = false;
            if let Some(mut record) = record.clone().filter(|record| {
                record.stage != LifecycleStage::OutcomeRecorded
                    || matches!(
                        mode,
                        RecoverMode::AbandonStaged | RecoverMode::FinalizeManifest
                    )
            }) {
                record.stage = LifecycleStage::OutcomeRecorded;
                record.outcome = Some(Self::decide_outcome(&record, &package)?);
                hook(Point::RecoverBeforeOutcomeRecord, &lifecycle_path)?;
                write_lifecycle(&self.parent, &self.lifecycle_name, &record)?;
                hook(Point::RecoverAfterOutcomeRecord, &lifecycle_path)?;
                wrote_outcome = true;
            }
            if let Some(record) = record.as_ref()
                && let Some(guard) = &record.guard
                && validate_recorded_guard(&package, guard)? == StagedPresence::Present
            {
                if !wrote_outcome && record.stage != LifecycleStage::OutcomeRecorded {
                    return Err(invalid(
                        "guard cleanup requires a completed lifecycle outcome record",
                    ));
                }
                hook(Point::RecoverBeforeGuardRemove, &lifecycle_path)?;
                fs::unlinkat(&package.root, UPDATE_GUARD, AtFlags::empty())?;
                fs::fsync(&package.root)?;
                hook(Point::RecoverAfterGuardRemove, &lifecycle_path)?;
            }
            package.footprint()
        })();
        Ok(match result {
            Ok(bytes) => outcome(preview, OutcomeState::Recovered, Some(bytes), None, None),
            Err(error) => Outcome {
                status: OutcomeState::Incomplete,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error: Some(error.to_string()),
            },
        })
    }
}

pub(super) struct Remove {
    parent: Parent,
    package: Package,
    lifecycle_name: OsString,
}

impl Remove {
    pub(super) fn prepare(prefix: &Path) -> io::Result<(Self, Preview)> {
        let parent = Parent::open(prefix)?;
        let package = Package::open(&parent, &parent.name)?;
        let lifecycle_name = parent.lifecycle_name();
        let decision = lifecycle_gate_decision(&parent, &lifecycle_name, Some(&package))?;
        let mut preview = package.receipt.preview(prefix, Action::Remove);
        preview.can_execute = decision.is_none();
        preview.decision = decision;
        Ok((
            Self {
                parent,
                package,
                lifecycle_name,
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
        let lifecycle_path = self.parent.path.join(&self.lifecycle_name);
        if cancellation.is_cancelled() {
            return Ok(outcome(preview, OutcomeState::Cancelled, None, None, None));
        }
        if !preview.can_execute {
            let error = preview.decision.clone();
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error,
            });
        }
        if let Some(decision) =
            lifecycle_gate_decision(&self.parent, &self.lifecycle_name, Some(&self.package))?
        {
            return Ok(Outcome {
                status: OutcomeState::Refused,
                preview,
                logical_bytes: None,
                allocated_bytes: None,
                recovery_paths: vec![NativePath::from_path(&lifecycle_path)],
                error: Some(decision),
            });
        }
        self.package
            .verify(&self.parent, &self.parent.name, 0, cancellation, true)?;
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
                .verify(&self.parent, &detached, 0, cancellation, true)?;
            fs::unlinkat(&self.package.bin, "sayaka", AtFlags::empty())?;
            hook(Point::PayloadRemoved, &recovery)?;
            fs::fsync(&self.package.bin)?;
            self.package
                .verify(&self.parent, &detached, 1, cancellation, true)?;
            fs::unlinkat(&self.package.root, "bin", AtFlags::REMOVEDIR)?;
            hook(Point::BinRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 2, cancellation, true)?;
            fs::unlinkat(&self.package.root, LOCK, AtFlags::empty())?;
            hook(Point::LockRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 3, cancellation, true)?;
            fs::unlinkat(&self.package.root, MANIFEST, AtFlags::empty())?;
            hook(Point::ManifestRemoved, &recovery)?;
            fs::fsync(&self.package.root)?;
            self.package
                .verify(&self.parent, &detached, 4, cancellation, true)?;
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
