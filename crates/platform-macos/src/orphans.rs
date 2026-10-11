// SPDX-License-Identifier: MPL-2.0
//! Bounded read-only observations for orphan cleanup. Unknown never means empty.
use crate::related::PathWitness;
use objc2::{
    msg_send,
    rc::{Retained, autoreleasepool},
    runtime::{AnyClass, AnyObject},
};
use std::{
    ffi::{CStr, CString},
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
fn error(s: impl ToString) -> io::Error {
    io::Error::other(s.to_string())
}
fn string(s: &str) -> io::Result<Retained<AnyObject>> {
    let c = AnyClass::get(c"NSString").ok_or_else(|| error("NSString unavailable"))?;
    let bytes = CString::new(s).map_err(error)?;
    // SAFETY: NSString copies the live UTF-8 input.
    let value: Option<Retained<AnyObject>> =
        unsafe { msg_send![c, stringWithUTF8String:bytes.as_ptr()] };
    value.ok_or_else(|| error("invalid string"))
}
fn class(n: &CStr) -> io::Result<&'static AnyClass> {
    AnyClass::get(n).ok_or_else(|| error("Foundation class unavailable"))
}
fn text(v: &AnyObject) -> io::Result<String> {
    // SAFETY: Check Foundation type before using string selectors.
    unsafe {
        let yes: bool = msg_send![v, isKindOfClass:class(c"NSString")?];
        if !yes {
            return Err(error("plist field is not a string"));
        }
        let len: usize = msg_send![v, length];
        if len > 4096 {
            return Err(error("string limit"));
        }
        let ptr: *const std::ffi::c_char = msg_send![v, UTF8String];
        if ptr.is_null() {
            return Err(error("string encoding"));
        }
        CStr::from_ptr(ptr)
            .to_str()
            .map(str::to_owned)
            .map_err(error)
    }
}
/// Reject spelling aliases as well as links, and retain no-follow ancestry.
pub fn exact(path: &Path) -> io::Result<PathWitness> {
    let witness = PathWitness::capture(path)?;
    for p in path.ancestors().take_while(|p| p.parent().is_some()) {
        let mut found = false;
        let start = Instant::now();
        for (i, entry) in std::fs::read_dir(p.parent().unwrap())?.enumerate() {
            if i >= 100_000 || start.elapsed() > Duration::from_secs(2) {
                return Err(error("spelling_unknown"));
            }
            if entry?.file_name() == p.file_name().unwrap() {
                found = true;
                break;
            }
        }
        if !found {
            return Err(error("path_spelling_alias"));
        }
    }
    witness.revalidate()?;
    Ok(witness)
}
pub fn verified_trash() -> io::Result<PathWitness> {
    let home = crate::effective_account_home()?;
    let root = exact(&home.join(".Trash"))?;
    let h = exact(&home)?;
    let m = std::fs::symlink_metadata(root.path())?;
    // SAFETY: geteuid has no arguments or ownership requirements.
    if !root.is_directory()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o022 != 0
        || root.identity().0 != h.identity().0
        || root.physical_path()? != h.physical_path()?.join(".Trash")
    {
        return Err(error("trash_root_unverified"));
    }
    Ok(root)
}
pub fn in_trash(root: &PathWitness, path: &Path) -> io::Result<PathWitness> {
    root.revalidate()?;
    if path == root.path()
        || !path.starts_with(root.path())
        || path.extension().is_none_or(|e| e != "app")
    {
        return Err(error("not_trash_bundle"));
    }
    let w = exact(path)?;
    if !w.is_directory()
        || w.identity().0 != root.identity().0
        || !w.physical_path()?.starts_with(root.physical_path()?)
    {
        return Err(error("trash_containment_unknown"));
    }
    root.revalidate()?;
    Ok(w)
}
/// Latest mtime, including root, with complete traversal or explicit failure.
pub fn latest_mtime(path: &Path) -> io::Result<SystemTime> {
    let start = Instant::now();
    let root = exact(path)?;
    let mut latest = SystemTime::UNIX_EPOCH;
    let mut stack = vec![(path.to_owned(), 0usize)];
    let mut count = 0;
    while let Some((p, depth)) = stack.pop() {
        count += 1;
        if count > 100_000 || depth > 128 || start.elapsed() >= Duration::from_secs(2) {
            return Err(error("inactivity_unknown"));
        }
        let w = PathWitness::capture(&p)?;
        let m = std::fs::symlink_metadata(&p)?;
        if m.dev() != root.identity().0 || (!m.is_dir() && (!m.is_file() || m.nlink() != 1)) {
            return Err(error("inactivity_unsafe_entry"));
        }
        latest = latest.max(m.modified()?);
        if m.is_dir() {
            for e in std::fs::read_dir(&p)? {
                if stack.len() + count >= 100_000 || start.elapsed() >= Duration::from_secs(2) {
                    return Err(error("inactivity_unknown"));
                }
                stack.push((e?.path(), depth + 1));
            }
        }
        w.revalidate()?;
    }
    root.revalidate()?;
    if start.elapsed() >= Duration::from_secs(2) {
        return Err(error("inactivity_unknown"));
    }
    Ok(latest)
}
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    static NSMetadataQueryLocalComputerScope: *const AnyObject;
}
/// All positive Spotlight paths. Empty completed initial gathering is weak evidence.
pub fn spotlight(id: &str, deadline: Instant) -> io::Result<Vec<PathBuf>> {
    if !crate::related::valid_bundle_id(id) {
        return Err(error("invalid_bundle_id"));
    }
    objc2::exception::catch(|| autoreleasepool(|_| {
        // SAFETY: Foundation documented signatures; retained objects stay on this
        // worker and its run loop. No query strings interpolate caller data.
        unsafe {
            let query: Retained<AnyObject> = msg_send![class(c"NSMetadataQuery")?, new];
            // The query is only stopped and dropped after an exception; no results
            // from partially completed Foundation work are reused.
            let run = objc2::exception::catch(std::panic::AssertUnwindSafe(|| {
                let key = string("kMDItemCFBundleIdentifier")?; let value = string(id)?;
                let args = [&*key as *const AnyObject, &*value as *const AnyObject];
                let array: Retained<AnyObject> = msg_send![class(c"NSArray")?, arrayWithObjects:args.as_ptr(), count:args.len()];
                let format = string("%K == %@")?;
                let predicate: Retained<AnyObject> = msg_send![class(c"NSPredicate")?, predicateWithFormat:&*format, argumentArray:&*array];
                let scopes: Retained<AnyObject> = msg_send![class(c"NSArray")?, arrayWithObject:NSMetadataQueryLocalComputerScope];
                let _: () = msg_send![&query,setPredicate:&*predicate];
                let _: () = msg_send![&query,setSearchScopes:&*scopes];
                let started: bool = msg_send![&query,startQuery];
                if !started {return Err(error("spotlight_unavailable"));}
                let limit = deadline.min(Instant::now()+Duration::from_secs(5));
                let loop_: Retained<AnyObject> = msg_send![class(c"NSRunLoop")?, currentRunLoop];
                loop {
                    if Instant::now() >= limit {return Err(error("spotlight_timeout"));}
                    let gathering: bool = msg_send![&query,isGathering];
                    if !gathering {break;}
                    let until: Retained<AnyObject> = msg_send![class(c"NSDate")?, dateWithTimeIntervalSinceNow:0.01f64];
                    let _: () = msg_send![&loop_,runUntilDate:&*until];
                }
                let _: () = msg_send![&query,disableUpdates];
                let count: usize = msg_send![&query,resultCount];
                if count>256 {return Err(error("spotlight_truncated"));}
                let attr = string("kMDItemPath")?;
                let mut out=Vec::new();
                for i in 0..count {
                    let item: &AnyObject=msg_send![&query,resultAtIndex:i];
                    let value: Option<Retained<AnyObject>>=msg_send![item,valueForAttribute:&*attr];
                    let p=PathBuf::from(text(&*value.ok_or_else(||error("spotlight_path_unknown"))?)?);
                    if !p.is_absolute() {return Err(error("spotlight_path_unknown"));}
                    out.push(p);
                }
                Ok(out)
            }));
            let _: () = msg_send![&query,stopQuery];
            run.map_err(|_|error("spotlight_exception"))?
        }
    })).map_err(|_|error("spotlight_exception"))?
}
/// Read only the three launchd identity/program fields; no job control.
pub fn launch_agent_document(path: &Path) -> io::Result<(Vec<(String, bool)>, Vec<u8>)> {
    let witness = exact(path)?;
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | 0x20000000 | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        if !m.is_file() || m.len() > 1_048_576 || (m.dev(), m.ino()) != witness.identity() {
            return Err(error("launch_agent_unknown"));
        }
        let mut bytes = Vec::new();
        f.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return Err(error("launch_agent_limit"));
        }
        let fields=objc2::exception::catch(|| autoreleasepool(|_| unsafe {
            // SAFETY: NSData copies bounded bytes; Foundation parses without execution.
            let data: Retained<AnyObject>=msg_send![class(c"NSData")?,dataWithBytes:bytes.as_ptr().cast::<std::ffi::c_void>(),length:bytes.len()];
            let value: Option<Retained<AnyObject>>=msg_send![class(c"NSPropertyListSerialization")?,propertyListWithData:&*data,options:0usize,format:std::ptr::null_mut::<usize>(),error:std::ptr::null_mut::<*mut AnyObject>()];
            let dict=value.ok_or_else(||error("launch_agent_parse_unknown"))?;
            let isdict: bool=msg_send![&dict,isKindOfClass:class(c"NSDictionary")?];
            if !isdict {return Err(error("launch_agent_dictionary_required"));}
            let mut out=Vec::new();
            for name in ["Label","Program","ProgramArguments"] {
                let key=string(name)?;
                let value: Option<Retained<AnyObject>>=msg_send![&dict,objectForKey:&*key];
                if let Some(value)=value {
                    if name=="ProgramArguments" {
                        let array: bool=msg_send![&value,isKindOfClass:class(c"NSArray")?];
                        if !array {return Err(error("launch_agent_arguments_unknown"));}
                        let count: usize=msg_send![&value,count];
                        if count==0 || count>4096 {return Err(error("launch_agent_arguments_unknown"));}
                        for i in 0..count { let s: &AnyObject=msg_send![&value,objectAtIndex:i]; let s=text(s)?; if i==0 {out.push((s, true));} }
                    } else {out.push((text(&value)?, name != "Label"));}
                }
            }
            Ok(out)
        })).map_err(|_|error("launch_agent_exception"))??;
        witness.revalidate()?;
        Ok((fields, bytes))
    })();
    let restored = policy.restore();
    let fields = result?;
    restored?;
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_observation_fixtures_compile_without_real_user_data() {
        let root =
            std::env::temp_dir().join(format!("sayaka-orphan-read-fixture-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let plist = root.join("job.plist");
        std::fs::write(&plist,b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>com.fixture.old.worker</string><key>ProgramArguments</key><array><string>/fixture/tool</string></array></dict></plist>").unwrap();
        let fields = launch_agent_document(&plist).unwrap().0;
        assert_eq!(
            fields,
            vec![
                ("com.fixture.old.worker".to_owned(), false),
                ("/fixture/tool".to_owned(), true)
            ]
        );
        std::fs::write(&plist, b"malformed plist").unwrap();
        assert!(launch_agent_document(&plist).is_err());
        std::os::unix::fs::symlink(&plist, root.join("linked.plist")).unwrap();
        assert!(launch_agent_document(&root.join("linked.plist")).is_err());
        assert!(latest_mtime(&root).is_err());
        std::fs::remove_file(root.join("linked.plist")).unwrap();
        assert!(latest_mtime(&root).unwrap() <= SystemTime::now());
        std::fs::remove_file(plist).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}

/// Finder alias flag from the bounded FinderInfo xattr; never resolve aliases.
pub fn is_finder_alias(path: &Path) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    let witness = exact(path)?;
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | 0x20000000)
            .open(path)?;
        let m = file.metadata()?;
        if (m.dev(), m.ino()) != witness.identity() {
            return Err(error("resource_changed"));
        }
        let mut info = [0u8; 32];
        // SAFETY: macOS fgetxattr writes at most the bounded FinderInfo buffer.
        // Finder flags occupy bytes 8..10 in the published FileInfo layout.
        let n = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"com.apple.FinderInfo".as_ptr(),
                info.as_mut_ptr().cast(),
                info.len(),
                0,
                0,
            )
        };
        let result = if n == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOATTR) {
                false
            } else {
                return Err(e);
            }
        } else if n == 32 {
            u16::from_be_bytes([info[8], info[9]]) & 0x8000 != 0
        } else {
            return Err(error("finder_alias_unknown"));
        };
        witness.revalidate()?;
        Ok(result)
    })();
    let restored = policy.restore();
    let alias = result?;
    restored?;
    Ok(alias)
}
