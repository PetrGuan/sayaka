// SPDX-License-Identifier: MPL-2.0

use super::walk::{self, Backend, Cursor, DirItem, Metadata, ThreadPolicy};
use super::*;
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Dir, Mode, OFlags, Stat};
use sayaka_platform_macos::{ReadOnlyPolicy, VolumeInfo, volume_info};
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::time::Instant;

struct NativePolicy(ReadOnlyPolicy);
impl ThreadPolicy for NativePolicy {
    fn restore(self) -> Result<(), ScanError> {
        self.0.restore().map_err(policy_error)
    }
}

fn policy_error(error: std::io::Error) -> ScanError {
    ScanError {
        code: ScanCode::PolicyFailure,
        message: error.to_string(),
        os_code: error.raw_os_error(),
    }
}

struct MacBackend;

fn volume_allowed(info: Result<VolumeInfo, std::io::Error>) -> Result<(), ScanError> {
    let info = info.map_err(|error| ScanError::new(ScanCode::VolumeUnknown, error.to_string()))?;
    if !info.local || !info.internal || info.removable || info.ejectable {
        Err(ScanError::new(
            ScanCode::UnsupportedVolume,
            "only positively identified local internal volumes are supported",
        ))
    } else {
        Ok(())
    }
}

fn directory_flags() -> OFlags {
    // Public Darwin O_NOFOLLOW_ANY from <sys/fcntl.h>. It is mutually exclusive
    // with leaf-only NOFOLLOW. Unsupported kernels fail without a weaker retry.
    OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::CLOEXEC
        | OFlags::NONBLOCK
        | OFlags::from_bits_retain(0x2000_0000)
}

pub(super) fn verify_entry(scope: &ScanEntry, entry: &ScanEntry) -> Result<(), ScanError> {
    let policy = ReadOnlyPolicy::enter().map_err(policy_error)?;
    let result = (|| {
        let root = MacBackend.open_root(&scope.path)?;
        if root.metadata().identity != scope.identity {
            return Err(ScanError::new(
                ScanCode::ChangedEntry,
                "scope identity changed; refresh before viewing",
            ));
        }
        let current = if entry.path == scope.path {
            root.metadata()
        } else {
            let parent = entry
                .path
                .parent()
                .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "entry has no parent"))?;
            let name = entry
                .path
                .file_name()
                .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "entry has no name"))?;
            let fd = fs::open(parent, directory_flags(), Mode::empty()).map_err(native_error)?;
            let parent_info = from_stat(&fs::fstat(&fd).map_err(native_error)?);
            let FileIdentity::Unix { device, .. } = scope.identity else {
                return Err(ScanError::new(
                    ScanCode::UnsupportedPlatform,
                    "invalid native scope identity",
                ));
            };
            if !matches!(parent_info.identity, FileIdentity::Unix { device: current, .. } if current == device)
            {
                return Err(ScanError::new(
                    ScanCode::MountBoundary,
                    "entry moved to another volume",
                ));
            }
            from_stat(&fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(native_error)?)
        };
        if current.identity != entry.identity
            || current.kind != entry.kind
            || current.dataless
            || entry.dataless
            || !matches!(current.kind, ResourceKind::File | ResourceKind::Directory)
            || (entry.kind == ResourceKind::File
                && entry
                    .logical_bytes
                    .is_some_and(|size| current.logical_bytes != Some(size)))
        {
            return Err(ScanError::new(
                ScanCode::ChangedEntry,
                "entry changed or cannot be viewed without materialization; refresh first",
            ));
        }
        Ok(())
    })();
    match policy.restore() {
        Ok(()) => result,
        Err(error) => Err(ScanError::new(
            ScanCode::PolicyFailure,
            format!("view validation policy restoration failed: {error}; validation: {result:?}"),
        )),
    }
}

fn native_error(error: rustix::io::Errno) -> ScanError {
    if error == rustix::io::Errno::LOOP {
        ScanError::new(
            ScanCode::LinkSkipped,
            "symlink paths are not followed; provide a physical directory path",
        )
    } else if error == rustix::io::Errno::NOTDIR {
        ScanError::new(ScanCode::InvalidRoot, "expected a directory")
    } else {
        ScanError::io(std::io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

impl Backend for MacBackend {
    type Directory = MacDirectory;
    type Policy = NativePolicy;

    fn enter_thread(&self) -> Result<Self::Policy, ScanError> {
        ReadOnlyPolicy::enter()
            .map(NativePolicy)
            .map_err(policy_error)
    }

    fn open_root(&self, path: &Path) -> Result<Self::Directory, ScanError> {
        let fd = fs::open(path, directory_flags(), Mode::empty()).map_err(native_error)?;
        let volume = fs::fstatfs(&fd).map_err(native_error)?;
        if volume.f_flags & u32::try_from(libc::MNT_LOCAL).expect("positive MNT_LOCAL") == 0 {
            return Err(ScanError::new(
                ScanCode::UnsupportedVolume,
                "network volumes are not scanned",
            ));
        }
        let mount_bytes: Vec<u8> = volume
            .f_mntonname
            .iter()
            .map(|byte| byte.cast_unsigned())
            .collect();
        let mount = CStr::from_bytes_until_nul(&mount_bytes).map_err(|_| {
            ScanError::new(ScanCode::VolumeUnknown, "invalid native mount identity")
        })?;
        let mount = Path::new(OsStr::from_bytes(mount.to_bytes()));
        volume_allowed(volume_info(mount))?;
        MacDirectory::from_fd(fd)
    }
}

type Stamp = (i64, i64, i64, i64);

struct MacDirectory {
    stream: Dir,
    original: Metadata,
    stamp: Stamp,
}

impl MacDirectory {
    fn from_fd(fd: OwnedFd) -> Result<Self, ScanError> {
        let stat = fs::fstat(&fd).map_err(native_error)?;
        let original = from_stat(&stat);
        if original.dataless {
            return Err(ScanError::new(
                ScanCode::CloudDirectorySkipped,
                "dataless directory cannot be enumerated",
            ));
        }
        let stamp = stamp(&stat);
        let stream = Dir::new(fd).map_err(native_error)?;
        Ok(Self {
            stream,
            original,
            stamp,
        })
    }
}

impl Cursor for MacDirectory {
    fn metadata(&self) -> Metadata {
        self.original.clone()
    }

    fn next_entry(&mut self) -> Option<Result<DirItem, ScanError>> {
        loop {
            let entry = match self.stream.read()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(native_error(error))),
            };
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let metadata = self
                .stream
                .fd()
                .and_then(|fd| fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW))
                .map(|stat| from_stat(&stat))
                .map_err(native_error);
            return Some(Ok(DirItem {
                name: OsString::from_vec(name.to_bytes().to_vec()),
                metadata,
            }));
        }
    }

    fn open_child(&self, item: &DirItem) -> Result<Self, ScanError> {
        let parent = self.stream.fd().map_err(native_error)?;
        let fd = fs::openat(parent, &item.name, directory_flags(), Mode::empty())
            .map_err(native_error)?;
        Self::from_fd(fd)
    }

    fn unchanged(&self) -> Result<bool, ScanError> {
        let stat = self.stream.stat().map_err(native_error)?;
        Ok(stamp(&stat) == self.stamp && from_stat(&stat).identity == self.original.identity)
    }
}

fn stamp(stat: &Stat) -> Stamp {
    (
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    )
}

fn from_stat(stat: &Stat) -> Metadata {
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => ResourceKind::File,
        libc::S_IFDIR => ResourceKind::Directory,
        libc::S_IFLNK => ResourceKind::Link,
        _ => ResourceKind::Other,
    };
    let regular = kind == ResourceKind::File;
    Metadata {
        identity: FileIdentity::Unix {
            device: u64::from(stat.st_dev.cast_unsigned()),
            inode: stat.st_ino,
        },
        kind,
        logical_bytes: regular.then(|| u64::try_from(stat.st_size).ok()).flatten(),
        allocated_bytes: regular
            .then(|| {
                u64::try_from(stat.st_blocks)
                    .ok()
                    .and_then(|blocks| blocks.checked_mul(512))
            })
            .flatten(),
        // Public SF_DATALESS is synthetic/read-only and cannot be set by tests
        // using chflags; native cloud behavior is not inferred from fake flags.
        dataless: stat.st_flags & 0x4000_0000 != 0,
    }
}

pub(super) fn scan_native(
    roots: Vec<PathBuf>,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    task_id: ScanTaskId,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    let started = Instant::now();
    let policy = ReadOnlyPolicy::enter().map_err(policy_error)?;
    let result = walk::run(
        &MacBackend,
        roots,
        limits,
        cancellation,
        task_id,
        started,
        progress,
    );
    let restored = policy.restore().map_err(policy_error);
    match (result, restored) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(ScanError::new(
            ScanCode::PolicyFailure,
            format!("{first}; {second}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_classification_never_defaults_unknown_to_internal() {
        let internal = VolumeInfo {
            local: true,
            internal: true,
            removable: false,
            ejectable: false,
        };
        assert!(volume_allowed(Ok(internal)).is_ok());
        for rejected in [
            VolumeInfo {
                local: false,
                ..internal
            },
            VolumeInfo {
                internal: false,
                ..internal
            },
            VolumeInfo {
                removable: true,
                ..internal
            },
            VolumeInfo {
                ejectable: true,
                ..internal
            },
        ] {
            assert_eq!(
                volume_allowed(Ok(rejected)).unwrap_err().code,
                ScanCode::UnsupportedVolume
            );
        }
        assert_eq!(
            volume_allowed(Err(std::io::Error::other("unknown property")))
                .unwrap_err()
                .code,
            ScanCode::VolumeUnknown
        );
    }
}
