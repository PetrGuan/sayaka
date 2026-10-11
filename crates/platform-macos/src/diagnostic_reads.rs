// SPDX-License-Identifier: MPL-2.0
//! Fixed native observations. No authentication, preferences writes or helper.
use std::{
    ffi::{CStr, CString, c_void},
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};
fn directory(path: &str) -> Result<File, &'static str> {
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err("directory_unavailable");
    }
    let mut fd = unsafe { File::from_raw_fd(root) };
    // The root open cannot normally fail, but never construct a File with an invalid fd.
    for part in path.split('/').filter(|x| !x.is_empty()) {
        if part == "." || part == ".." {
            return Err("invalid_path");
        }
        let c = CString::new(part).map_err(|_| "invalid_path")?;
        let next = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err("directory_unavailable");
        }
        fd = unsafe { File::from_raw_fd(next) };
    }
    Ok(fd)
}
pub fn pam(name: &str, cancel: &dyn Fn() -> bool) -> Result<Option<String>, &'static str> {
    if cancel() {
        return Err("cancelled");
    }
    if !["sudo", "sudo_local", "sudo_local.template"].contains(&name) {
        return Err("invalid_source");
    }
    let dir = directory("/private/etc/pam.d")?;
    let c = CString::new(name).map_err(|_| "invalid_source")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err("file_unreadable")
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|_| "file_metadata")?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0 || before.len() > 65536
    {
        return Err("file_unsupported");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_unreadable")?;
    let after = file.metadata().map_err(|_| "file_metadata")?;
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut current,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || current.st_ino != before.ino()
        || current.st_dev as u64 != before.dev()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() > 65536
    {
        return Err("file_changed");
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "file_encoding")
}
fn home_limit(count: usize, elapsed: Duration) -> bool {
    count > 256 || elapsed > Duration::from_secs(5)
}
pub struct HomeEntry {
    pub name: String,
    pub owner_matches: bool,
    pub mode: u32,
    pub symlink: bool,
}
pub fn home(cancel: &dyn Fn() -> bool) -> Result<(Vec<HomeEntry>, bool), &'static str> {
    let start = Instant::now();
    let uid = unsafe { libc::geteuid() };
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut pw,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    } != 0
        || found.is_null()
        || pw.pw_dir.is_null()
    {
        return Err("home_unavailable");
    }
    let path = unsafe { CStr::from_ptr(pw.pw_dir) }
        .to_str()
        .map_err(|_| "home_encoding")?;
    let fd = directory(path)?;
    let meta = fd.metadata().map_err(|_| "home_metadata")?;
    let mut result = vec![HomeEntry {
        name: "~".into(),
        owner_matches: meta.uid() == uid,
        mode: meta.mode() & 0o7777,
        symlink: false,
    }];
    let copy = unsafe { libc::dup(fd.as_raw_fd()) };
    if copy < 0 {
        return Err("home_unavailable");
    }
    let dir = unsafe { libc::fdopendir(copy) };
    if dir.is_null() {
        unsafe { libc::close(copy) };
        return Err("home_unavailable");
    }
    struct Dir(*mut libc::DIR);
    impl Drop for Dir {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let dir = Dir(dir);
    let mut complete = true;
    let mut count = 0;
    loop {
        if cancel() {
            return Err("cancelled");
        }
        if start.elapsed() > Duration::from_secs(5) {
            complete = false;
            break;
        }
        unsafe { *libc::__error() = 0 };
        let entry = unsafe { libc::readdir(dir.0) };
        if entry.is_null() {
            if unsafe { *libc::__error() } != 0 {
                complete = false
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        count += 1;
        if home_limit(count, start.elapsed()) {
            complete = false;
            break;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                fd.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            complete = false;
            continue;
        }
        let kind = st.st_mode & libc::S_IFMT;
        if kind != libc::S_IFDIR && kind != libc::S_IFLNK {
            continue;
        }
        let Ok(name) = name.to_str() else {
            complete = false;
            continue;
        };
        result.push(HomeEntry {
            name: format!("~/{name}"),
            owner_matches: st.st_uid == uid,
            mode: u32::from(st.st_mode & 0o7777),
            symlink: kind == libc::S_IFLNK,
        });
    }
    let now = directory(path)?.metadata().map_err(|_| "home_metadata")?;
    complete &= now.dev() == meta.dev()
        && now.ino() == meta.ino()
        && now.mtime() == meta.mtime()
        && now.mtime_nsec() == meta.mtime_nsec();
    Ok((result, complete))
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(a: *const c_void, s: *const i8, e: u32) -> *const c_void;
    fn CFPreferencesCopyValue(
        k: *const c_void,
        d: *const c_void,
        u: *const c_void,
        h: *const c_void,
    ) -> *const c_void;
    fn CFPreferencesAppValueIsForced(k: *const c_void, d: *const c_void) -> u8;
    fn CFRelease(p: *const c_void);
    fn CFGetTypeID(p: *const c_void) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFBooleanGetValue(p: *const c_void) -> u8;
    static kCFPreferencesCurrentUser: *const c_void;
    static kCFPreferencesAnyHost: *const c_void;
    static kCFPreferencesAnyApplication: *const c_void;
}
struct CF(*const c_void);
impl Drop for CF {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}
fn cf(s: &str) -> Result<CF, &'static str> {
    let s = CString::new(s).map_err(|_| "preference_key")?;
    let p = unsafe { CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), 0x08000100) };
    if p.is_null() {
        Err("preference_unavailable")
    } else {
        Ok(CF(p))
    }
}
fn preference_state(present: bool, boolean: bool, value: bool) -> &'static str {
    if !present {
        "unset"
    } else if !boolean {
        "unexpected_type"
    } else if value {
        "true"
    } else {
        "false"
    }
}
pub enum Preference {
    NetworkStores,
    AppNap,
    Verify,
    VerifyLocked,
    VerifyRemote,
}
pub fn preference(p: Preference) -> Result<(&'static str, Option<bool>), &'static str> {
    let (domain, key) = match p {
        Preference::NetworkStores => ("com.apple.desktopservices", "DSDontWriteNetworkStores"),
        Preference::AppNap => ("", "NSAppSleepDisabled"),
        Preference::Verify => ("com.apple.frameworks.diskimages", "skip-verify"),
        Preference::VerifyLocked => ("com.apple.frameworks.diskimages", "skip-verify-locked"),
        Preference::VerifyRemote => ("com.apple.frameworks.diskimages", "skip-verify-remote"),
    };
    let key = cf(key)?;
    let domain = cf(domain)?;
    let app = if matches!(p, Preference::AppNap) {
        unsafe { kCFPreferencesAnyApplication }
    } else {
        domain.0
    };
    let value = CF(unsafe {
        CFPreferencesCopyValue(key.0, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
    });
    let forced = if matches!(p, Preference::AppNap) {
        None
    } else {
        Some(unsafe { CFPreferencesAppValueIsForced(key.0, app) } != 0)
    };
    let state = preference_state(
        !value.0.is_null(),
        !value.0.is_null() && unsafe { CFGetTypeID(value.0) == CFBooleanGetTypeID() },
        !value.0.is_null()
            && unsafe {
                CFGetTypeID(value.0) == CFBooleanGetTypeID() && CFBooleanGetValue(value.0) != 0
            },
    );
    Ok((state, forced))
}
type DnsRef = *mut c_void;
#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceGetAddrInfo(
        r: *mut DnsRef,
        f: u32,
        i: u32,
        p: u32,
        h: *const i8,
        cb: Option<
            unsafe extern "C" fn(
                DnsRef,
                u32,
                u32,
                i32,
                *const i8,
                *const libc::sockaddr,
                u32,
                *mut c_void,
            ),
        >,
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(r: DnsRef) -> i32;
    fn DNSServiceProcessResult(r: DnsRef) -> i32;
    fn DNSServiceRefDeallocate(r: DnsRef);
}
struct Dns(DnsRef);
impl Drop for Dns {
    fn drop(&mut self) {
        unsafe { DNSServiceRefDeallocate(self.0) }
    }
}
#[derive(Default)]
struct DnsState {
    positive: bool,
    error: Option<i32>,
}
impl DnsState {
    fn record(&mut self, error: i32, valid: bool) {
        if error == 0 && valid {
            self.positive = true
        }
        if error != 0 {
            self.error = Some(error)
        }
    }
    fn terminal(&self) -> Result<bool, &'static str> {
        if self.positive {
            return Ok(true);
        }
        match self.error {
            Some(-65554) => Err("dns_no_such_record"),
            Some(_) => Err("dns_response_error"),
            None => Err("dns_timeout"),
        }
    }
}
unsafe extern "C" fn dns_callback(
    _: DnsRef,
    _: u32,
    _: u32,
    error: i32,
    _: *const i8,
    addr: *const libc::sockaddr,
    _: u32,
    ctx: *mut c_void,
) {
    // SAFETY: context is our stack value retained until the service is deallocated.
    let state = unsafe { &mut *(ctx as *mut DnsState) };
    state.record(
        error,
        error == 0
            && !addr.is_null()
            && matches!(
                unsafe { (*addr).sa_family } as i32,
                libc::AF_INET | libc::AF_INET6
            ),
    );
}
pub fn dns_lookup(cancel: &dyn Fn() -> bool) -> Result<bool, &'static str> {
    if cancel() {
        return Err("cancelled");
    }
    let mut state = DnsState::default();
    let mut r = std::ptr::null_mut();
    let code = unsafe {
        DNSServiceGetAddrInfo(
            &mut r,
            0,
            0,
            3,
            c"www.apple.com".as_ptr(),
            Some(dns_callback),
            (&mut state as *mut DnsState).cast(),
        )
    };
    if code != 0 || r.is_null() {
        return Err("dns_unavailable");
    }
    let service = Dns(r);
    let fd = unsafe { DNSServiceRefSockFD(service.0) };
    if fd < 0 {
        return Err("dns_unavailable");
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if cancel() {
            return Err("cancelled");
        }
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut p, 1, 100) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err("dns_unavailable");
        }
        if n > 0 {
            if p.revents & libc::POLLIN == 0 {
                return Err("dns_unavailable");
            }
            if unsafe { DNSServiceProcessResult(service.0) } != 0 {
                return Err("dns_unavailable");
            }
            if state.positive {
                return Ok(true);
            }
        }
    }
    state.terminal()
}
pub fn periodic_available() -> Result<bool, &'static str> {
    match std::fs::symlink_metadata("/usr/sbin/periodic") {
        Ok(m) => Ok(m.is_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("tool_unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_negative_then_positive() {
        let mut s = DnsState::default();
        s.record(-65554, false);
        assert_eq!(s.terminal(), Err("dns_no_such_record"));
        s.record(0, true);
        assert_eq!(s.terminal(), Ok(true));
    }
    #[test]
    fn dns_timeout_cancel() {
        assert_eq!(DnsState::default().terminal(), Err("dns_timeout"));
        assert_eq!(dns_lookup(&|| true), Err("cancelled"));
    }
    #[test]
    fn preference_type_and_home_limits() {
        assert_eq!(preference_state(false, false, false), "unset");
        assert_eq!(preference_state(true, false, false), "unexpected_type");
        assert_eq!(preference_state(true, true, true), "true");
        assert!(home_limit(257, Duration::ZERO));
        assert!(home_limit(1, Duration::from_secs(6)));
    }
}
