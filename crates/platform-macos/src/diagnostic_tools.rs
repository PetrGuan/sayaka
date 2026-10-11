// SPDX-License-Identifier: MPL-2.0
//! Closed ordinary-user read-only command table shared by diagnostics and storage.
use crate::devtools::{ToolOutput, run_bounded_cancellable, verify_code_requirement};
use std::{ffi::OsString, path::Path, time::Duration};
#[derive(Clone, Copy)]
pub enum Tool {
    Disk,
    LoginItems,
    Route4,
    Route6,
    Dns,
    Snapshots,
    BackupStatus,
    Destinations,
}
pub fn run(tool: Tool) -> Result<ToolOutput, &'static str> {
    run_cancel(tool, &|| false)
}
pub fn run_cancel(tool: Tool, cancel: &dyn Fn() -> bool) -> Result<ToolOutput, &'static str> {
    let (path, args, secs, errcap) = match tool {
        Tool::Disk => ("/usr/sbin/diskutil", vec!["verifyVolume", "/"], 300, 65536),
        Tool::LoginItems => ("/usr/bin/sfltool", vec!["dumpbtm"], 10, 65536),
        Tool::Route4 => ("/sbin/route", vec!["-n", "get", "default"], 5, 65536),
        Tool::Route6 => (
            "/sbin/route",
            vec!["-n", "get", "-inet6", "default"],
            5,
            65536,
        ),
        Tool::Dns => ("/usr/sbin/scutil", vec!["--dns"], 5, 65536),
        Tool::Snapshots => ("/usr/bin/tmutil", vec!["listlocalsnapshots", "/"], 5, 16384),
        Tool::BackupStatus => ("/usr/bin/tmutil", vec!["status"], 5, 16384),
        Tool::Destinations => ("/usr/bin/tmutil", vec!["destinationinfo"], 5, 16384),
    };
    fixed(path, &args, Duration::from_secs(secs), errcap, cancel)
}
fn fixed(
    path: &str,
    args: &[&str],
    timeout: Duration,
    errcap: usize,
    cancel: &dyn Fn() -> bool,
) -> Result<ToolOutput, &'static str> {
    let identifier = Path::new(path)
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("tool_unavailable")?;
    verify_code_requirement(
        Path::new(path),
        &format!("anchor apple and identifier \"com.apple.{identifier}\""),
    )
    .map_err(|_| "tool_trust_unavailable")?;
    run_bounded_cancellable(
        Path::new(path),
        &args.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        &[
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ],
        timeout,
        256 * 1024,
        errcap,
        cancel,
    )
    .map_err(tool_error)
}
fn tool_error(e: crate::devtools::ToolError) -> &'static str {
    match e {
        crate::devtools::ToolError::Timeout => "command_timeout",
        crate::devtools::ToolError::OutputCap => "output_limit",
        crate::devtools::ToolError::Io(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
            "cancelled"
        }
        _ => "command_unavailable",
    }
}

#[derive(Clone)]
pub struct Mount {
    path: String,
    fsid: [i32; 2],
}
impl Mount {
    pub fn path(&self) -> &str {
        &self.path
    }
}
pub fn mounts() -> Result<Vec<Mount>, &'static str> {
    // SAFETY: getfsstat fills an owned bounded buffer; MNT_NOWAIT does not refresh mounts.
    let mut buf: Vec<libc::statfs> = (0..257).map(|_| unsafe { std::mem::zeroed() }).collect();
    let n = unsafe {
        libc::getfsstat(
            buf.as_mut_ptr(),
            std::mem::size_of_val(buf.as_slice()) as i32,
            libc::MNT_NOWAIT,
        )
    };
    if n < 0 || n as usize >= buf.len() {
        return Err("mount_inventory_unavailable");
    }
    let mut result = Vec::new();
    for v in &buf[..n as usize] {
        if v.f_flags & libc::MNT_LOCAL as u32 == 0 {
            continue;
        }
        let bytes = v
            .f_mntonname
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect::<Vec<_>>();
        let path = String::from_utf8(bytes).map_err(|_| "mount_encoding")?;
        if !path.starts_with('/') || path.len() > 4096 {
            return Err("mount_encoding");
        }
        // SAFETY: Darwin fsid_t is exactly two int32_t values (sys/mount.h).
        // Copy the value, without depending on libc's optional extra_traits feature.
        let fsid = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(v.f_fsid) };
        if !result.iter().any(|m: &Mount| m.fsid == fsid) {
            result.push(Mount { path, fsid });
        }
    }
    if result.is_empty() {
        return Err("mount_inventory_empty");
    }
    Ok(result)
}
pub fn spotlight(
    mount: &Mount,
    timeout: Duration,
    cancel: &dyn Fn() -> bool,
) -> Result<ToolOutput, &'static str> {
    if !mounts()?.iter().any(|m| same_mount(m, mount)) {
        return Err("mount_changed");
    }
    let out = fixed(
        "/usr/bin/mdutil",
        &["-s", &mount.path],
        timeout.min(Duration::from_secs(5)),
        65536,
        cancel,
    )?;
    if !mounts()?.iter().any(|m| same_mount(m, mount)) {
        return Err("mount_changed");
    }
    Ok(out)
}

fn same_mount(a: &Mount, b: &Mount) -> bool {
    a.path == b.path && a.fsid == b.fsid
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_mount_identity() {
        let a = Mount {
            path: "/".into(),
            fsid: [0; 2],
        };
        let mut b = a.clone();
        assert!(same_mount(&a, &b));
        b.path = "/Volumes/changed".into();
        assert!(!same_mount(&a, &b));
    }
    #[test]
    fn timeout_cap_cancel() {
        assert_eq!(
            tool_error(crate::devtools::ToolError::Timeout),
            "command_timeout"
        );
        assert_eq!(
            tool_error(crate::devtools::ToolError::OutputCap),
            "output_limit"
        );
        assert_eq!(
            tool_error(crate::devtools::ToolError::Io(
                std::io::ErrorKind::Interrupted.into()
            )),
            "cancelled"
        );
    }
}
