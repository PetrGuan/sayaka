// SPDX-License-Identifier: MPL-2.0

use cap_std::{ambient_authority, fs::Dir};
use same_file::Handle;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MARKER: &str = ".sayaka-owned-root";

pub struct OwnedTempDir {
    cleanup_pending: bool,
    parent: Dir,
    directory: Option<Dir>,
    identity: Option<Handle>,
    path: PathBuf,
    marker: Vec<u8>,
}

impl OwnedTempDir {
    /// Creates, never adopts, a fixture in a quiescent namespace. The caller must
    /// exclude concurrent replacement of the parent, child, and ancestors during
    /// creation and cleanup. Exclusive mkdir and no-follow open are separate
    /// operations, not a universal atomic ownership guarantee.
    /// Initialization errors preserve the created directory without cleanup.
    pub fn new(parent_path: &Path, prefix: &str) -> io::Result<Self> {
        if prefix.is_empty()
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixture prefix",
            ));
        }
        let parent_path = parent_path.canonicalize()?;
        let parent = Dir::open_ambient_dir(&parent_path, ambient_authority())?;
        let created = tempfile::Builder::new()
            .prefix(prefix)
            .rand_bytes(16)
            .disable_cleanup(true)
            .make_in(&parent_path, |path| {
                Self::create_named(parent.try_clone()?, path.to_path_buf(), |_| Ok(()))
            })?;
        Ok(created.into_file())
    }

    fn create_named(
        parent: Dir,
        path: PathBuf,
        initialize: impl FnOnce(&Dir) -> io::Result<()>,
    ) -> io::Result<Self> {
        let name = path.file_name().ok_or_else(refused)?.to_os_string();
        let parent_file = parent.try_clone()?.into_std_file();
        parent.create_dir(&name)?;
        (|| {
        let directory = Dir::from_std_file(cap_primitives::fs::open_dir_nofollow(
            &parent_file,
            Path::new(&name),
        )?);
        let identity = Handle::from_file(directory.try_clone()?.into_std_file())?;
        initialize(&directory)?;
        let marker = name.as_encoded_bytes().to_vec();
        directory
            .open_with(
                MARKER,
                cap_std::fs::OpenOptions::new().write(true).create_new(true),
            )?
            .write_all(&marker)?;
        Ok(Self {
            cleanup_pending: true,
            parent,
            directory: Some(directory),
            identity: Some(identity),
            path,
            marker,
        })
        })()
        .map_err(|error: io::Error| {
            io::Error::other(format!(
                "fixture initialization failed; created directory preserved without cleanup: {error}"
            ))
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn validate(&self) -> io::Result<()> {
        for ancestor in self.path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(refused());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(refused());
                }
            }
        }
        let current = Handle::from_path(&self.path)?;
        if self.identity.as_ref() != Some(&current) {
            return Err(refused());
        }
        let relative = cap_primitives::fs::open_dir_nofollow(
            &self.parent.try_clone()?.into_std_file(),
            Path::new(self.path.file_name().ok_or_else(refused)?),
        )?;
        if self.identity.as_ref() != Some(&Handle::from_file(relative)?) {
            return Err(refused());
        }
        let directory = self.directory.as_ref().ok_or_else(refused)?;
        if !directory.symlink_metadata(MARKER)?.is_file() || directory.read(MARKER)? != self.marker
        {
            return Err(refused());
        }
        Ok(())
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !std::mem::replace(&mut self.cleanup_pending, false) {
            return Ok(());
        }
        self.validate()?;
        self.identity.take();
        self.directory
            .take()
            .ok_or_else(refused)?
            .remove_open_dir_all()
    }

    pub fn close(mut self) -> io::Result<()> {
        self.cleanup()
    }
}

impl Drop for OwnedTempDir {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("owned fixture cleanup refused or failed: {error}");
            if !std::thread::panicking() {
                panic!("owned fixture cleanup refused or failed");
            }
        }
    }
}

fn refused() -> io::Error {
    io::Error::other("fixture ownership or containment changed; preserved without cleanup")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outer() -> OwnedTempDir {
        OwnedTempDir::new(&std::env::temp_dir(), "sayaka-owned-check-").unwrap()
    }

    #[test]
    fn creation_refuses_existing_directory_without_adopting_it() {
        let outer = outer();
        let path = outer.path().join("existing");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"existing fixture").unwrap();
        let result = OwnedTempDir::create_named(
            outer.directory.as_ref().unwrap().try_clone().unwrap(),
            path.clone(),
            |_| panic!("must not initialize an existing directory"),
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"existing fixture");
        assert!(!path.join(MARKER).exists());
        outer.close().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn creation_refuses_existing_junction_without_adopting_target() {
        let outer = outer();
        let target = outer.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"junction target fixture").unwrap();
        let link = outer.path().join("existing-junction");
        junction::create(&target, &link).unwrap();
        let result = OwnedTempDir::create_named(
            outer.directory.as_ref().unwrap().try_clone().unwrap(),
            link.clone(),
            |_| panic!("must not initialize a junction target"),
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AlreadyExists);
        assert!(junction::exists(&link).unwrap());
        assert_eq!(
            fs::read(target.join("keep")).unwrap(),
            b"junction target fixture"
        );
        assert!(!target.join(MARKER).exists());
        junction::delete(&link).unwrap();
        outer.close().unwrap();
    }

    #[test]
    fn default_drop_cleans_successfully_initialized_fixture() {
        let outer = outer();
        let owned = OwnedTempDir::new(outer.path(), "owned-").unwrap();
        let path = owned.path().to_path_buf();
        fs::create_dir(path.join("nested")).unwrap();
        fs::write(path.join("nested/file"), b"owned fixture").unwrap();
        drop(owned);
        assert!(!path.exists());
        outer.close().unwrap();
    }

    #[test]
    fn initialization_failure_preserves_created_directory_and_contents() {
        let outer = outer();
        for marker_collision in [false, true] {
            let path = outer.path().join(if marker_collision {
                "marker-failure"
            } else {
                "init-failure"
            });
            let result = OwnedTempDir::create_named(
                outer.directory.as_ref().unwrap().try_clone().unwrap(),
                path.clone(),
                |directory| {
                    directory.write("keep", b"partially initialized fixture")?;
                    if marker_collision {
                        directory.write(MARKER, b"occupied marker")
                    } else {
                        Err(io::Error::other("injected initialization failure"))
                    }
                },
            );
            let error = result.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(error.to_string().contains("preserved without cleanup"));
            assert_eq!(
                fs::read(path.join("keep")).unwrap(),
                b"partially initialized fixture"
            );
            if marker_collision {
                assert_eq!(fs::read(path.join(MARKER)).unwrap(), b"occupied marker");
            }
        }
        outer.close().unwrap();
    }

    #[test]
    fn cleanup_rejects_different_identity_even_with_copied_marker() {
        let outer = outer();
        let mut owned = OwnedTempDir::new(outer.path(), "owned-").unwrap();
        let replacement = OwnedTempDir::new(outer.path(), "replacement-").unwrap();
        fs::write(replacement.path().join("keep"), b"replacement fixture").unwrap();
        fs::write(replacement.path().join(MARKER), &owned.marker).unwrap();
        owned.path = replacement.path().to_path_buf();
        assert!(owned.close().is_err());
        assert_eq!(
            fs::read(replacement.path().join("keep")).unwrap(),
            b"replacement fixture"
        );
        fs::write(replacement.path().join(MARKER), &replacement.marker).unwrap();
        replacement.close().unwrap();
        outer.close().unwrap();
    }

    #[test]
    fn cleanup_prevents_or_refuses_root_and_ancestor_replacement() {
        for replace_ancestor in [false, true] {
            let outer = outer();
            let parent = outer.path().join("parent");
            fs::create_dir(&parent).unwrap();
            let owned = OwnedTempDir::new(&parent, "owned-").unwrap();
            fs::write(owned.path().join("owned"), b"original fixture").unwrap();
            let target = if replace_ancestor {
                parent.clone()
            } else {
                owned.path().to_path_buf()
            };
            let moved = outer.path().join("moved");
            match fs::rename(&target, &moved) {
                Ok(()) => {
                    fs::create_dir_all(owned.path()).unwrap();
                    fs::write(owned.path().join("keep"), b"replacement fixture").unwrap();
                    let path = owned.path().to_path_buf();
                    assert!(owned.close().is_err());
                    assert_eq!(fs::read(path.join("keep")).unwrap(), b"replacement fixture");
                }
                Err(error) => {
                    assert!(
                        cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32)),
                        "{error}"
                    );
                    assert_eq!(
                        fs::read(owned.path().join("owned")).unwrap(),
                        b"original fixture"
                    );
                    let path = owned.path().to_path_buf();
                    owned.close().unwrap();
                    assert!(!path.exists());
                }
            }
            outer.close().unwrap();
        }
    }
}
