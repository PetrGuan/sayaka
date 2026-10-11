// SPDX-License-Identifier: MPL-2.0
//! Descriptor-relative, bounded logical metadata size; no content reads.
use crate::firmware::{Entries, child_directory, child_metadata, directory};
use std::{io, os::unix::fs::MetadataExt, path::Path, time::Instant};
pub fn size(path: &Path, deadline: Instant, remaining: &mut usize) -> io::Result<(u64, bool)> {
    let root = directory(path)?;
    let initial = root.metadata()?;
    let device = initial.dev();
    let mut total = 0u64;
    let mut complete = true;
    let mut stack = vec![(root, 0)];
    while let Some((dir, depth)) = stack.pop() {
        if Instant::now() >= deadline || *remaining == 0 {
            return Ok((total, false));
        }
        let before = dir.metadata()?;
        let mut entries = Entries::new(&dir)?;
        while let Some(name) = entries.next_name()? {
            if Instant::now() >= deadline || *remaining == 0 {
                return Ok((total, false));
            }
            *remaining -= 1;
            let s = child_metadata(&dir, &name)?;
            if s.st_dev as u64 != device || s.st_flags & 0x40000000 != 0 {
                complete = false;
                continue;
            }
            if s.st_mode & libc::S_IFMT == libc::S_IFDIR {
                if depth >= 64 {
                    complete = false;
                    continue;
                }
                let child = child_directory(&dir, &name)?;
                let m = child.metadata()?;
                if m.ino() != s.st_ino || m.dev() != device {
                    complete = false;
                    continue;
                }
                stack.push((child, depth + 1));
            } else if s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_size >= 0 {
                total = total
                    .checked_add(s.st_size as u64)
                    .ok_or_else(|| io::Error::other("size overflow"))?;
            } else {
                complete = false;
            }
        }
        let after = dir.metadata()?;
        if before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec() {
            complete = false;
        }
    }
    Ok((total, complete && Instant::now() < deadline))
}
