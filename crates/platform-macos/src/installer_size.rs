// SPDX-License-Identifier: MPL-2.0
//! Depth-bounded descriptor-relative metadata size, never content reads.
use crate::firmware::{Entries, child_directory, child_metadata, directory};
use std::{fs::File, io, os::unix::fs::MetadataExt, path::Path, time::Instant};
pub fn size(path: &Path, deadline: Instant, remaining: &mut usize) -> io::Result<(u64, bool)> {
    if Instant::now() >= deadline {
        return Ok((0, false));
    }
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let root = directory(path)?;
        let device = root.metadata()?.dev();
        let mut total = 0;
        let mut complete = true;
        visit(
            root,
            0,
            device,
            deadline,
            remaining,
            &mut total,
            &mut complete,
        )?;
        Ok((total, complete && Instant::now() < deadline))
    })();
    let restored = policy.restore();
    restored?;
    result
}
fn visit(
    dir: File,
    depth: usize,
    device: u64,
    deadline: Instant,
    remaining: &mut usize,
    total: &mut u64,
    complete: &mut bool,
) -> io::Result<()> {
    if Instant::now() >= deadline || *remaining == 0 {
        *complete = false;
        return Ok(());
    }
    let before = dir.metadata()?;
    let mut entries = Entries::new(&dir)?;
    loop {
        if Instant::now() >= deadline || *remaining == 0 {
            *complete = false;
            break;
        }
        let Some(name) = entries.next_name()? else {
            break;
        };
        if Instant::now() >= deadline {
            *complete = false;
            break;
        }
        *remaining -= 1;
        let s = child_metadata(&dir, &name)?;
        if s.st_dev as u64 != device || s.st_flags & 0x40000000 != 0 {
            *complete = false;
            continue;
        }
        if s.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if depth >= 64 || Instant::now() >= deadline {
                *complete = false;
                continue;
            }
            let child = child_directory(&dir, &name)?;
            let m = child.metadata()?;
            if m.ino() != s.st_ino || m.dev() != device {
                *complete = false;
                continue;
            }
            // Descend immediately: at most two descriptors per depth, not breadth.
            visit(
                child,
                depth + 1,
                device,
                deadline,
                remaining,
                total,
                complete,
            )?;
        } else if s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_size >= 0 {
            *total = total
                .checked_add(s.st_size as u64)
                .ok_or_else(|| io::Error::other("size overflow"))?;
        } else {
            *complete = false;
        }
    }
    let after = dir.metadata()?;
    if before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || Instant::now() >= deadline
    {
        *complete = false;
    }
    Ok(())
}
