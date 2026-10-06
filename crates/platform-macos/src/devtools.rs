// SPDX-License-Identifier: MPL-2.0

//! Fixed `xcrun simctl` launch boundary for slice 1a of
//! `docs/SIMULATOR_CLEANUP.md`.
//!
//! Only `/usr/bin/xcrun` (Apple-signed) is launched, without a shell, with an
//! allow-listed environment, in its own process group, with bounded output and
//! a timeout. Argument vectors come from the engine's fixed tables; this module
//! never builds a command line from free text.

use std::ffi::{OsString, c_char, c_long, c_void};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const XCRUN: &str = "/usr/bin/xcrun";
/// Code requirement for `/usr/bin/xcrun`.
pub const XCRUN_REQUIREMENT: &str = "anchor apple and identifier \"com.apple.xcrun\"";
pub const MAX_STDOUT: usize = 8 * 1024 * 1024;
pub const MAX_STDERR: usize = 64 * 1024;
pub const LIST_TIMEOUT: Duration = Duration::from_secs(30);
pub const EXECUTE_TIMEOUT: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(20);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum ToolError {
    /// `xcrun`/`simctl` is missing, unsigned or not resolvable.
    Unavailable(String),
    Spawn(io::Error),
    /// The process group was terminated; the service may still finish.
    Timeout,
    /// Output exceeded its cap; the process group was terminated.
    OutputCap,
    Io(io::Error),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::Unavailable(reason) => write!(f, "simctl unavailable: {reason}"),
            ToolError::Spawn(error) => write!(f, "could not launch xcrun: {error}"),
            ToolError::Timeout => write!(f, "simctl timed out"),
            ToolError::OutputCap => write!(f, "simctl output exceeded its cap"),
            ToolError::Io(error) => write!(f, "simctl I/O error: {error}"),
        }
    }
}

impl std::error::Error for ToolError {}

#[derive(Debug)]
pub struct ToolOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Runs one fixed `xcrun` argument vector. Injected in tests.
pub trait ToolRunner {
    fn run(&self, args: &[String], timeout: Duration) -> Result<ToolOutput, ToolError>;
}

/// The production runner: `/usr/bin/xcrun` with the allow-listed environment.
///
/// Descriptor inheritance: only stdin (`/dev/null`), stdout and stderr are
/// set up for the child. Other host descriptors must be close-on-exec, which
/// holds for everything opened through Rust's standard library (including the
/// journal lock); hosts must not hand this process inheritable descriptors.
pub struct XcrunRunner {
    env: Vec<(OsString, OsString)>,
}

impl XcrunRunner {
    /// Verifies `/usr/bin/xcrun`'s signature and builds the environment.
    pub fn new() -> Result<Self, ToolError> {
        verify_code_requirement(Path::new(XCRUN), XCRUN_REQUIREMENT)?;
        Ok(Self {
            env: allowed_environment().map_err(ToolError::Io)?,
        })
    }
}

impl ToolRunner for XcrunRunner {
    fn run(&self, args: &[String], timeout: Duration) -> Result<ToolOutput, ToolError> {
        // Re-verified before every launch, narrowing the window between the
        // signature check and exec to this call.
        verify_code_requirement(Path::new(XCRUN), XCRUN_REQUIREMENT)?;
        run_bounded(
            Path::new(XCRUN),
            args,
            &self.env,
            timeout,
            MAX_STDOUT,
            MAX_STDERR,
        )
    }
}

/// Exactly `PATH`, `HOME` (password database), `LANG=C` and the user's private
/// `TMPDIR`. `DEVELOPER_DIR`, `SDKROOT`, `TOOLCHAINS`, `XCODE_*`, `SIMCTL_*`
/// and `DYLD_*` are never present.
pub fn allowed_environment() -> io::Result<Vec<(OsString, OsString)>> {
    Ok(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), account_home()?.into_os_string()),
        ("LANG".into(), "C".into()),
        ("TMPDIR".into(), user_temp_dir()?.into_os_string()),
    ])
}

fn account_home() -> io::Result<PathBuf> {
    // SAFETY: passwd is a plain C struct; all-zero is a valid initial value.
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; getpwuid_r is reentrant and
    // writes strings only into `buffer`.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut record,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || record.pw_dir.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "account home unavailable",
        ));
    }
    // SAFETY: pw_dir points to a NUL-terminated string inside `buffer`.
    let bytes = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }.to_bytes();
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

fn user_temp_dir() -> io::Result<PathBuf> {
    let mut buffer = vec![0 as c_char; 1024];
    // SAFETY: the buffer is writable for its full length.
    let needed = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if needed == 0 || needed > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "user temporary directory unavailable",
        ));
    }
    // SAFETY: confstr wrote a NUL-terminated string within the buffer.
    let bytes = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }.to_bytes();
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

/// Owns the child. Unless disarmed after a clean reap, dropping it kills the
/// whole process group and reaps the leader, so timeouts, caps, early errors
/// and panics never leave the group running or a zombie behind.
struct GroupGuard {
    child: Child,
    armed: bool,
}

impl GroupGuard {
    fn pgid(&self) -> i32 {
        self.child.id() as i32
    }

    /// True once the leader has exited. Uses `WNOWAIT`, so the leader stays a
    /// zombie: its pid, which is also the group id, cannot be reused while the
    /// group is still being terminated.
    fn exited_without_reaping(&self) -> io::Result<bool> {
        // SAFETY: siginfo_t is a plain C struct; all-zero is a valid initial value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is writable; WNOWAIT leaves the child unreaped.
        let status = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: si_pid is valid to read after waitid; it is 0 when nothing exited.
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn kill_group(&self) {
        // SAFETY: killpg only sends a signal. The leader is alive or an
        // unreaped zombie, so the group id still names this group; ESRCH is fine.
        unsafe { libc::killpg(self.pgid(), libc::SIGKILL) };
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if self.armed {
            self.kill_group();
            let _ = self.child.wait();
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    mut source: R,
    cap: usize,
) -> mpsc::Receiver<Result<Vec<u8>, ToolError>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        let result = loop {
            match source.read(&mut chunk) {
                Ok(0) => break Ok(data),
                Ok(read) => {
                    if data.len() + read > cap {
                        break Err(ToolError::OutputCap);
                    }
                    data.extend_from_slice(&chunk[..read]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => break Err(ToolError::Io(error)),
            }
        };
        let _ = sender.send(result);
    });
    receiver
}

/// Launches `program` without a shell in its own process group and enforces
/// caps while reading and a wall-clock timeout. During execution calls, every
/// error from this function means the outcome is `unknown`.
pub fn run_bounded(
    program: &Path,
    args: &[String],
    env: &[(OsString, OsString)],
    timeout: Duration,
    stdout_cap: usize,
    stderr_cap: usize,
) -> Result<ToolOutput, ToolError> {
    let child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(ToolError::Spawn)?;
    let mut guard = GroupGuard { child, armed: true };
    let broken = || ToolError::Io(io::ErrorKind::BrokenPipe.into());
    let stdout = spawn_reader(guard.child.stdout.take().ok_or_else(broken)?, stdout_cap);
    let stderr = spawn_reader(guard.child.stderr.take().ok_or_else(broken)?, stderr_cap);
    let started = Instant::now();
    let mut stdout_result = None;
    let mut stderr_result = None;
    loop {
        for (receiver, slot) in [(&stdout, &mut stdout_result), (&stderr, &mut stderr_result)] {
            if slot.is_none()
                && let Ok(result) = receiver.try_recv()
            {
                if matches!(result, Err(ToolError::OutputCap)) {
                    return Err(ToolError::OutputCap); // guard kills and reaps
                }
                *slot = Some(result);
            }
        }
        if guard.exited_without_reaping().map_err(ToolError::Io)? {
            break;
        }
        if started.elapsed() >= timeout {
            return Err(ToolError::Timeout); // guard kills and reaps
        }
        std::thread::sleep(POLL);
    }
    // The leader exited but is not reaped yet, so the group id is still ours:
    // terminate anything left in the group so the pipes close, then reap.
    guard.kill_group();
    let status = guard.child.wait().map_err(ToolError::Io)?;
    guard.armed = false;
    let collect = |slot: Option<Result<Vec<u8>, ToolError>>,
                   receiver: &mpsc::Receiver<Result<Vec<u8>, ToolError>>| {
        match slot {
            Some(result) => result,
            None => receiver
                .recv_timeout(DRAIN_TIMEOUT)
                .unwrap_or(Err(ToolError::Io(io::ErrorKind::TimedOut.into()))),
        }
    };
    let stdout = collect(stdout_result, &stdout)?;
    let stderr = collect(stderr_result, &stderr)?;
    Ok(ToolOutput {
        success: status.success(),
        code: status.code(),
        stdout,
        stderr,
    })
}

/// Identity of the `simctl` binary that `xcrun` resolves. Captured with the
/// same environment at preview and before every execution call; any
/// difference (including a same-path Xcode update) refuses the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolEvidence {
    pub simctl_path: PathBuf,
    pub real_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_unix_ns: i128,
}

impl ToolEvidence {
    /// Stable text used in plan digests and journal records.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}:{}|{}|{}",
            self.simctl_path.display(),
            self.real_path.display(),
            self.device,
            self.inode,
            self.size,
            self.modified_unix_ns
        )
    }
}

pub fn tool_evidence(runner: &dyn ToolRunner) -> Result<ToolEvidence, ToolError> {
    let output = runner.run(&["--find".into(), "simctl".into()], LIST_TIMEOUT)?;
    if !output.success {
        return Err(ToolError::Unavailable(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ToolError::Unavailable("non-UTF-8 simctl path".into()))?
        .trim();
    let simctl_path = PathBuf::from(text);
    if !simctl_path.is_absolute() || text.contains('\n') {
        return Err(ToolError::Unavailable(
            "xcrun returned an unexpected simctl path".into(),
        ));
    }
    let real_path = std::fs::canonicalize(&simctl_path).map_err(ToolError::Io)?;
    let metadata = std::fs::metadata(&real_path).map_err(ToolError::Io)?;
    if !metadata.is_file() {
        return Err(ToolError::Unavailable(
            "simctl is not a regular file".into(),
        ));
    }
    Ok(ToolEvidence {
        simctl_path,
        real_path,
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_unix_ns: i128::from(metadata.mtime()) * 1_000_000_000
            + i128::from(metadata.mtime_nsec()),
    })
}

/// Modification time of a device's data directory, for erase post-checks.
pub fn modified_unix_ns(path: &Path) -> Option<i128> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some(i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()))
}

/// Matches processes whose presence refuses a request: Xcode, Simulator,
/// command-line test runs (`xcodebuild`, `xctest`) and other `simctl` users.
pub fn is_developer_activity(executable: &Path) -> bool {
    let name = executable
        .file_name()
        .map(|n| n.as_bytes())
        .unwrap_or_default();
    matches!(name, b"xcodebuild" | b"xctest" | b"simctl")
        || executable.ends_with("Contents/MacOS/Xcode")
        || executable.ends_with("Contents/MacOS/Simulator")
}

/// Executable paths of running developer activity, excluding this process and
/// the process group `exclude_group` (this process's own `simctl` calls).
/// Fails when the process table cannot be read. Processes whose path cannot be
/// read (other users' or protected processes) are skipped.
pub fn developer_activity(exclude_group: Option<i32>) -> io::Result<Vec<PathBuf>> {
    let mut pids = vec![0 as libc::pid_t; 4096];
    loop {
        let bytes = (pids.len() * size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: the buffer is writable for `bytes` bytes.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        if (count as usize) < pids.len() {
            pids.truncate(count as usize);
            break;
        }
        if pids.len() >= 1 << 20 {
            return Err(io::Error::other("process table too large"));
        }
        pids.resize(pids.len() * 2, 0);
    }
    let own = std::process::id() as libc::pid_t;
    let mut found = Vec::new();
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    for pid in pids {
        if pid <= 0 || pid == own {
            continue;
        }
        // SAFETY: getpgid only reads process metadata.
        if exclude_group.is_some_and(|group| unsafe { libc::getpgid(pid) } == group) {
            continue;
        }
        // SAFETY: the buffer is writable for its full length.
        let length =
            unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if length <= 0 {
            continue;
        }
        let executable = PathBuf::from(std::ffi::OsStr::from_bytes(&path[..length as usize]));
        if is_developer_activity(&executable) {
            found.push(executable);
        }
    }
    Ok(found)
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: c_long,
        is_directory: u8,
    ) -> *const c_void;
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: c_long,
        encoding: u32,
        external_representation: u8,
    ) -> *const c_void;
    fn CFRelease(value: *const c_void);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(
        path: *const c_void,
        flags: u32,
        code: *mut *const c_void,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: *const c_void,
        flags: u32,
        requirement: *mut *const c_void,
    ) -> i32;
    fn SecStaticCodeCheckValidity(
        code: *const c_void,
        flags: u32,
        requirement: *const c_void,
    ) -> i32;
}

const UTF8: u32 = 0x0800_0100;

struct Owned(*const c_void);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Create/Copy call and is released once.
            unsafe { CFRelease(self.0) };
        }
    }
}

/// Checks a static code signature against a code requirement string.
pub fn verify_code_requirement(path: &Path, requirement: &str) -> Result<(), ToolError> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: inputs are valid for the calls; every created object is owned
    // by an `Owned` guard and released exactly once.
    unsafe {
        let url = Owned(CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as c_long,
            0,
        ));
        let string = Owned(CFStringCreateWithBytes(
            std::ptr::null(),
            requirement.as_ptr(),
            requirement.len() as c_long,
            UTF8,
            0,
        ));
        if url.0.is_null() || string.0.is_null() {
            return Err(ToolError::Unavailable(
                "could not prepare signature check".into(),
            ));
        }
        let mut code = std::ptr::null();
        let status = SecStaticCodeCreateWithPath(url.0, 0, &mut code);
        let code = Owned(code);
        if status != 0 {
            return Err(ToolError::Unavailable(format!(
                "{} has no readable signature ({status})",
                path.display()
            )));
        }
        let mut compiled = std::ptr::null();
        let status = SecRequirementCreateWithString(string.0, 0, &mut compiled);
        let compiled = Owned(compiled);
        if status != 0 {
            return Err(ToolError::Unavailable(format!(
                "invalid code requirement ({status})"
            )));
        }
        let status = SecStaticCodeCheckValidity(code.0, 0, compiled.0);
        if status != 0 {
            return Err(ToolError::Unavailable(format!(
                "{} does not satisfy its code requirement ({status})",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn environment_is_exactly_the_allow_list() {
        let env = allowed_environment().unwrap();
        let keys: Vec<_> = env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(keys, vec!["PATH", "HOME", "LANG", "TMPDIR"]);
        assert!(env.iter().all(|(_, v)| !v.is_empty()));
    }

    #[test]
    fn child_sees_only_the_allowed_environment() {
        let env = allowed_environment().unwrap();
        let output = run_bounded(
            Path::new("/usr/bin/env"),
            &[],
            &env,
            LIST_TIMEOUT,
            MAX_STDOUT,
            MAX_STDERR,
        )
        .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        // std passes the environment sorted; macOS may add its own
        // __CF_USER_TEXT_ENCODING to every process.
        let names: std::collections::BTreeSet<_> = text
            .lines()
            .filter_map(|line| line.split('=').next())
            .filter(|name| *name != "__CF_USER_TEXT_ENCODING")
            .collect();
        assert_eq!(
            names,
            ["HOME", "LANG", "PATH", "TMPDIR"].into_iter().collect()
        );
    }

    #[test]
    fn stderr_cap_is_enforced_too() {
        let result = run_bounded(
            Path::new("/bin/sh"),
            &args(&["-c", "yes >&2"]),
            &[],
            LIST_TIMEOUT,
            1024,
            4096,
        );
        assert!(matches!(result, Err(ToolError::OutputCap)));
    }

    #[test]
    fn background_grandchild_in_the_group_cannot_hold_the_call_open() {
        let started = Instant::now();
        let output = run_bounded(
            Path::new("/bin/sh"),
            &args(&["-c", "sleep 30 & echo started"]),
            &[],
            LIST_TIMEOUT,
            1024,
            1024,
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"started\n");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    struct Stub(Vec<u8>, bool);

    impl ToolRunner for Stub {
        fn run(&self, args: &[String], _: Duration) -> Result<ToolOutput, ToolError> {
            assert_eq!(args, ["--find", "simctl"]);
            Ok(ToolOutput {
                success: self.1,
                code: Some(if self.1 { 0 } else { 1 }),
                stdout: self.0.clone(),
                stderr: b"no developer directory".to_vec(),
            })
        }
    }

    #[test]
    fn tool_evidence_records_identity_and_rejects_bad_answers() {
        let evidence = tool_evidence(&Stub(b"/bin/echo\n".to_vec(), true)).unwrap();
        assert_eq!(evidence.simctl_path, PathBuf::from("/bin/echo"));
        assert!(evidence.inode > 0 && evidence.size > 0);
        assert_eq!(
            evidence,
            tool_evidence(&Stub(b"/bin/echo\n".to_vec(), true)).unwrap()
        );
        assert!(tool_evidence(&Stub(b"relative/simctl".to_vec(), true)).is_err());
        assert!(tool_evidence(&Stub(b"/bin\n".to_vec(), true)).is_err());
        assert!(matches!(
            tool_evidence(&Stub(Vec::new(), false)),
            Err(ToolError::Unavailable(_))
        ));
    }

    #[test]
    fn data_observation_reads_modification_time() {
        let fixture = std::env::temp_dir();
        assert!(modified_unix_ns(&fixture).is_some());
        assert!(modified_unix_ns(Path::new("/nonexistent/sayaka-test")).is_none());
    }

    #[test]
    fn timeout_terminates_the_process_group() {
        let started = Instant::now();
        let result = run_bounded(
            Path::new("/bin/sleep"),
            &args(&["30"]),
            &[],
            Duration::from_millis(200),
            1024,
            1024,
        );
        assert!(matches!(result, Err(ToolError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_cap_is_enforced_while_reading() {
        let result = run_bounded(
            Path::new("/usr/bin/yes"),
            &[],
            &[],
            LIST_TIMEOUT,
            4096,
            1024,
        );
        assert!(matches!(result, Err(ToolError::OutputCap)));
    }

    #[test]
    fn exit_status_and_output_are_reported() {
        let output = run_bounded(
            Path::new("/bin/echo"),
            &args(&["hello"]),
            &[],
            LIST_TIMEOUT,
            1024,
            1024,
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"hello\n");
        let failed = run_bounded(
            Path::new("/usr/bin/false"),
            &[],
            &[],
            LIST_TIMEOUT,
            1024,
            1024,
        )
        .unwrap();
        assert!(!failed.success);
    }

    #[test]
    fn xcrun_satisfies_its_apple_requirement_and_others_do_not() {
        assert!(verify_code_requirement(Path::new(XCRUN), XCRUN_REQUIREMENT).is_ok());
        assert!(verify_code_requirement(Path::new("/bin/echo"), XCRUN_REQUIREMENT).is_err());
    }

    #[test]
    fn developer_activity_matching_covers_apps_and_command_line_tools() {
        for path in [
            "/Applications/Xcode.app/Contents/MacOS/Xcode",
            "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator",
            "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild",
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/Library/Xcode/Agents/xctest",
            "/Applications/Xcode.app/Contents/Developer/usr/bin/simctl",
        ] {
            assert!(is_developer_activity(Path::new(path)), "{path}");
        }
        assert!(!is_developer_activity(Path::new("/usr/bin/xcrun")));
        assert!(!is_developer_activity(Path::new(
            "/Applications/XcodeHelper.app/Contents/MacOS/XcodeHelper"
        )));
    }

    #[test]
    fn process_table_is_readable() {
        assert!(developer_activity(None).is_ok());
    }
}
