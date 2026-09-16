// SPDX-License-Identifier: MPL-2.0

use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const OUTPUT_CAP: u64 = 1024 * 1024;
const CLI_CAP: u64 = 64 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(75);
const BROKER: &str = r#"
import json, os, subprocess, sys
status = int(sys.argv[1])
child = subprocess.Popen(sys.argv[2:], close_fds=True)
code = child.wait()
message = (json.dumps({"event": "finished", "pid": child.pid, "exit": code}) + "\n").encode()
assert os.write(status, message) == len(message)
# Retain a live, signalable group leader until the supervisor closes the group.
os.read(status, 1)
sys.exit(125)
"#;
const PTY_DRIVER: &str = r#"
import errno, os, pty, select, subprocess, sys, time
binary, root, state, sentinel, mode, count, *targets = sys.argv[1:]
expected = int(count)
assert expected in (1, 2) and len(targets) == expected
command = [binary, "installer", root, "--execute", "--state-dir", state, "--exclude", sentinel]
if mode == "explicit":
    for target in targets:
        command += ["--select", target]
else:
    assert mode == "numeric"
master, slave = pty.openpty()
child = None
output = bytearray()
deadline = time.monotonic() + 60
def receive():
    if time.monotonic() >= deadline:
        raise TimeoutError("native CLI deadline; outcome may be ambiguous")
    if not select.select([master], [], [], 0.05)[0]:
        return True
    try:
        chunk = os.read(master, 65536)
    except OSError as error:
        if error.errno == errno.EIO:
            return False
        raise
    if not chunk:
        return False
    output.extend(chunk)
    if len(output) > 262144:
        raise RuntimeError("native CLI output cap exceeded")
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    return True
def until(marker):
    while marker not in output:
        if not receive():
            raise RuntimeError("native CLI exited before required prompt")
try:
    # Inherit the supervisor's isolated process group so its timeout can stop
    # both the PTY driver and CLI without leaving an untracked mutating child.
    child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    slave = -1
    if mode == "numeric":
        until(b"Selection: ")
        selection = (",".join(str(i) for i in range(1, expected + 1)) + "\n").encode()
        assert os.write(master, selection) == len(selection)
    until(b"Execution plan (sealed before approval):")
    until(('Type "trash %d" to move exactly these files' % expected).encode())
    assert not os.listdir(state), "journal appeared before confirmation"
    phrase = ("trash %d\n" % expected).encode()
    print("\n[authorized owned-fixture confirmation]", flush=True)
    assert os.write(master, phrase) == len(phrase)
    while receive():
        pass
    assert child.wait(timeout=5) == 0, "native CLI reported failure/ambiguity"
finally:
    if child is not None and child.poll() is None:
        child.kill()
        child.wait(timeout=5)
    if slave != -1:
        os.close(slave)
    os.close(master)
"#;

fn ensure(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn authorized(run: Option<&str>, quiescent: Option<&str>) -> io::Result<()> {
    ensure(
        run == Some("1") && quiescent == Some("1"),
        "BLOCKED before fixture/Trash mutation: explicit installer fixture authorization and quiescence required",
    )
}

fn checked_bytes(path: &Path, observed: &Evidence, cap: u64) -> io::Result<Vec<u8>> {
    with_policy(|| checked_bytes_under_policy(path, observed, cap))
}

fn checked_bytes_under_policy(path: &Path, observed: &Evidence, cap: u64) -> io::Result<Vec<u8>> {
    ensure(
        observed.stamp.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFREG)
            && observed.stamp.size <= cap,
        "unexpected file kind/size",
    )?;
    observed.revalidate()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW_ANY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    ensure(
        Stamp::read(&file.metadata()?) == observed.stamp,
        "content handle changed",
    )?;
    let mut bytes = Vec::new();
    (&mut file).take(cap + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() as u64 == observed.stamp.size,
        "content size changed",
    )?;
    ensure(
        Stamp::read(&file.metadata()?) == observed.stamp,
        "file changed during content check",
    )?;
    observed.revalidate()?;
    Ok(bytes)
}

struct Log {
    root: PathBuf,
    directory: Evidence,
    events: File,
}

impl Log {
    fn new(repo: &Path, fixture_name: &OsStr) -> io::Result<Self> {
        let target = repo.join("target");
        let parent = Evidence::open_safety(&target)?;
        let root = target.join(format!(
            "installer-evidence-{}",
            fixture_name.to_string_lossy()
        ));
        parent.revalidate()?;
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        parent.revalidate()?;
        let directory = Evidence::open_safety(&root)?;
        private_recovery_directory(
            "private evidence directory",
            &directory,
            ordinary_authority()?,
            directory.stamp.device,
        )?;
        let events = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW_ANY | libc::O_CLOEXEC)
            .open(root.join("events.jsonl"))?;
        File::open(&root)?.sync_all()?;
        Ok(Self {
            root,
            directory,
            events,
        })
    }

    fn event(&mut self, value: Value) -> io::Result<()> {
        self.directory.revalidate()?;
        serde_json::to_writer(&mut self.events, &value)?;
        self.events.write_all(b"\n")?;
        full_sync(&self.events)
    }

    fn capture(&self, label: &str, suffix: &str) -> io::Result<File> {
        self.directory.revalidate()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW_ANY | libc::O_CLOEXEC)
            .open(self.root.join(format!("{label}.{suffix}")))?;
        File::open(&self.root)?.sync_all()?;
        Ok(file)
    }
}

fn command_output(command: &mut Command, label: &str, log: &mut Log) -> io::Result<Vec<u8>> {
    let mut stdout = log.capture(label, "stdout")?;
    let stderr = log.capture(label, "stderr")?;
    let (mut status_reader, status_writer) = UnixStream::pair()?;
    status_reader.set_nonblocking(true)?;
    let status_fd = status_writer.as_raw_fd();
    ensure(
        status_fd > 2,
        "broker control socket must not replace stdio",
    )?;
    // SAFETY: Querying flags on this live owned socket has no pointer arguments.
    let flags = unsafe { libc::fcntl(status_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut broker = Command::new("/usr/bin/python3");
    broker
        .arg("-c")
        .arg(BROKER)
        .arg(status_fd.to_string())
        .arg(command.get_program())
        .args(command.get_args())
        .env_clear();
    if let Some(directory) = command.get_current_dir() {
        broker.current_dir(directory);
    }
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => {
                broker.env(key, value);
            }
            None => {
                broker.env_remove(key);
            }
        }
    }
    // SAFETY: The child-only hook performs only fcntl on a still-live inherited
    // descriptor. The parent's CLOEXEC flag is never changed; grandchildren
    // close this private control socket via subprocess close_fds.
    unsafe {
        broker.pre_exec(move || {
            if libc::fcntl(status_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = broker
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .process_group(0)
        .spawn()?;
    drop(status_writer);
    let mut owned = OwnedGroup {
        child,
        reaped: false,
    };
    let started = Instant::now();
    let mut status_bytes = Vec::new();
    let outcome = loop {
        let too_large =
            stdout.metadata()?.len() > OUTPUT_CAP || stderr.metadata()?.len() > OUTPUT_CAP;
        if too_large || started.elapsed() >= DEADLINE {
            owned.stop()?;
            break Err(io::Error::other(
                "owned CLI group stopped at time/output bound; preserve ambiguous evidence",
            ));
        }
        if owned.observe_exit()?.is_some() {
            break Err(io::Error::other(
                "owned broker exited before supervised group closure",
            ));
        }
        let mut chunk = [0u8; 512];
        match status_reader.read(&mut chunk) {
            Ok(0) => break Err(io::Error::other("broker status socket closed unexpectedly")),
            Ok(count) => status_bytes.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => break Err(error),
        }
        ensure(
            status_bytes.len() <= 4096,
            "broker status exceeded its bound",
        )?;
        if status_bytes.contains(&b'\n') {
            let status: Value = serde_json::from_slice(&status_bytes)?;
            ensure(
                status["event"] == "finished" && status["pid"].as_u64().is_some_and(|pid| pid > 0),
                "invalid broker completion record",
            )?;
            let code = status["exit"]
                .as_i64()
                .ok_or_else(|| refused("missing broker exit status"))?;
            ensure((-128..=255).contains(&code), "invalid child exit status")?;
            owned.stop()?;
            break if code == 0 {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "owned command failed: status {code}; see private captures"
                )))
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let outcome = match (outcome, owned.stop()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(stop)) => Err(io::Error::other(format!(
            "{primary}; owned group cleanup also failed: {stop}"
        ))),
    };
    full_sync(&stdout)?;
    full_sync(&stderr)?;
    log.event(json!({"event": "command_finished", "label": label, "success": outcome.is_ok()}))?;
    outcome?;
    stdout.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&mut stdout).take(OUTPUT_CAP + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() as u64 <= OUTPUT_CAP,
        "capture exceeded output bound",
    )?;
    Ok(bytes)
}

struct OwnedGroup {
    child: Child,
    reaped: bool,
}

impl OwnedGroup {
    fn observe_exit(&self) -> io::Result<Option<(i32, i32)>> {
        ensure(!self.reaped, "owned leader was already reaped")?;
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: The initialized output storage is valid for this synchronous
        // query of our child. WNOWAIT explicitly retains the PID for group cleanup.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: Storage began zeroed and waitid succeeded; no-event is si_pid=0.
        let info = unsafe { info.assume_init() };
        if info.si_pid == 0 {
            return Ok(None);
        }
        ensure(
            u32::try_from(info.si_pid).ok() == Some(self.child.id()),
            "unexpected waitid PID",
        )?;
        Ok(Some((info.si_code, info.si_status)))
    }

    fn stop(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let pid = i32::try_from(self.child.id()).expect("native PID fits pid_t");
        // SAFETY: This still-unreaped child was placed in its own process group.
        // The PTY driver and CLI share that group, never the test runner's group.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        self.child.wait()?;
        self.reaped = true;
        Ok(())
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "failed to stop/reap owned command group {}: {error}",
                self.child.id()
            );
        }
    }
}

fn isolated(command: &mut Command, home: &Path, tmp: &Path) {
    command
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", tmp)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(home);
}

fn native_path(value: &Value) -> io::Result<PathBuf> {
    ensure(
        value["encoding"] == "unix_bytes",
        "unexpected native path encoding",
    )?;
    let values = value["bytes"]
        .as_array()
        .ok_or_else(|| refused("missing native path bytes"))?;
    ensure(
        !values.is_empty() && values.len() <= 4096,
        "invalid native path length",
    )?;
    let bytes = values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| refused("invalid native path byte"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    valid_path(&path)?;
    ensure(
        value["display"] == format!("{:?}", path.as_os_str()),
        "native display/bytes disagree",
    )?;
    Ok(path)
}

struct Target {
    path: PathBuf,
    bytes: Vec<u8>,
    held: Evidence,
}

struct Recovery {
    original: Evidence,
    trash: Evidence,
    ancestry: Vec<Evidence>,
    device: u64,
    uid: u32,
}

impl Recovery {
    fn prepare(root: &Path, target: &Target) -> io::Result<Self> {
        let uid = ordinary_authority()?;
        let original = Evidence::open_safety(root)?;
        let path = objc2::rc::autoreleasepool(|_| {
            foundation::Prepared::new(&target.path)?.existing_trash_directory()
        })?;
        let trash = Evidence::open_safety(&path)?;
        let ancestry = path
            .ancestors()
            .skip(1)
            .map(|path| {
                let entry = Evidence::open_safety(path)?;
                admissible_ancestor(&entry.stamp, uid)?;
                Ok(entry)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let recovery = Self {
            original,
            trash,
            ancestry,
            device: target.held.stamp.device,
            uid,
        };
        recovery.check()?;
        Ok(recovery)
    }

    fn check(&self) -> io::Result<()> {
        for ancestor in &self.ancestry {
            ancestor.revalidate()?;
        }
        private_recovery_directory("original directory", &self.original, self.uid, self.device)?;
        private_recovery_directory("Trash directory", &self.trash, self.uid, self.device)
    }
}

fn location(target: &Target, path: &Path) -> io::Result<Evidence> {
    let mut observed = Evidence::open_bound(path, Binding::PostMoveTarget)?;
    let mut expected = target.held.stamp.clone();
    expected.changed = observed.stamp.changed;
    let held_now = Stamp::read(&target.held.file.metadata()?);
    verify_post_move_consistency(
        &expected,
        &held_now,
        &observed.stamp,
        observed.acl == target.held.acl,
    )?;
    ensure(
        physical_path(&target.held.file)? == observed.physical,
        "held descriptor and location disagree",
    )?;
    observed.binding = Binding::FullTarget;
    observed.stamp = expected;
    ensure(
        checked_bytes(path, &observed, target.bytes.len() as u64)? == target.bytes,
        "owned installer content changed",
    )?;
    Ok(observed)
}

fn vacant(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(refused("path is not demonstrably vacant")),
    }
}

fn restore(
    fixture: &mut Fixture,
    target: &Target,
    destination: &Path,
    recovery: &Recovery,
    log: &mut Log,
    label: &str,
) -> io::Result<()> {
    with_policy(|| {
        recovery.check()?;
        let returned_parent = Evidence::open_safety(
            destination
                .parent()
                .ok_or_else(|| refused("missing parent"))?,
        )?;
        ensure(
            returned_parent.stamp.identity() == recovery.trash.stamp.identity()
                && returned_parent.physical == recovery.trash.physical,
            "destination is outside verified native Trash",
        )?;
        let returned = location(target, destination)?;
        admissible_file(&returned.stamp, recovery.uid)?;
        vacant(&target.path)?;
        let blocker_bytes = b"owned no-overwrite restore blocker";
        let mut blocker_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW_ANY | libc::O_CLOEXEC)
            .open(&target.path)?;
        blocker_file.write_all(blocker_bytes)?;
        full_sync(&blocker_file)?;
        let blocker = Evidence::open(&target.path)?;
        log.event(json!({"event": "owned_restore_blocker", "label": label,
            "path": target.path, "device": blocker.stamp.device, "inode": blocker.stamp.inode}))?;
        returned.revalidate()?;
        recovery.check()?;
        let rejected = no_overwrite_rename(
            &recovery.trash.file,
            destination
                .file_name()
                .ok_or_else(|| refused("missing Trash name"))?,
            &recovery.original.file,
            target
                .path
                .file_name()
                .ok_or_else(|| refused("missing original name"))?,
        );
        ensure(
            matches!(rejected, Err(ref error) if error.raw_os_error() == Some(libc::EEXIST)),
            "occupied restore did not fail with EEXIST",
        )?;
        ensure(
            checked_bytes(&target.path, &blocker, blocker_bytes.len() as u64)? == blocker_bytes,
            "restore overwrote blocker",
        )?;
        location(target, destination)?;
        let displaced_name = OsString::from(format!("{label}-owned-blocker.txt"));
        let displaced = recovery.original.path.join(&displaced_name);
        vacant(&displaced)?;
        blocker.revalidate()?;
        recovery.check()?;
        no_overwrite_rename(
            &recovery.original.file,
            target.path.file_name().unwrap(),
            &recovery.original.file,
            &displaced_name,
        )?;
        let displaced_evidence = Evidence::open(&displaced)?;
        ensure(
            displaced_evidence.stamp.identity() == blocker.stamp.identity()
                && checked_bytes(&displaced, &displaced_evidence, blocker_bytes.len() as u64)?
                    == blocker_bytes,
            "relocated blocker changed",
        )?;
        fixture.record(displaced, false);
        vacant(&target.path)?;
        location(target, destination)?.revalidate()?;
        recovery.check()?;
        no_overwrite_rename(
            &recovery.trash.file,
            destination.file_name().unwrap(),
            &recovery.original.file,
            target.path.file_name().unwrap(),
        )?;
        location(target, &target.path)?;
        vacant(destination)?;
        log.event(
            json!({"event": "restored", "label": label, "source": target.path,
            "destination": destination, "device": target.held.stamp.device,
            "inode": target.held.stamp.inode, "content_sha256": sha256(&target.bytes),
            "conflict_preserved_both": true}),
        )
    })
}

fn dmg_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 2048];
    let footer = &mut bytes[1536..];
    footer[..4].copy_from_slice(b"koly");
    footer[4..8].copy_from_slice(&4u32.to_be_bytes());
    footer[8..12].copy_from_slice(&512u32.to_be_bytes());
    footer[0xd8..0xe0].copy_from_slice(&128u64.to_be_bytes());
    footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
    bytes
}

fn pkg_bytes() -> io::Result<Vec<u8>> {
    let xml = b"<xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml)?;
    let toc = encoder.finish()?;
    let mut bytes = vec![0u8; 28];
    bytes[..4].copy_from_slice(b"xar!");
    bytes[4..6].copy_from_slice(&28u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes[8..16].copy_from_slice(&(toc.len() as u64).to_be_bytes());
    bytes[16..24].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    bytes.extend(toc);
    Ok(bytes)
}

fn validate_plan(value: &Value, root: &Path, targets: &[Target]) -> io::Result<()> {
    ensure(
        value["kind"] == "installer_trash_preview"
            && value["status"] == "ready_for_confirmation"
            && value["effects_performed"] == false
            && value["discovery"]["complete"] == true,
        "installer preview did not produce complete no-effect selection",
    )?;
    ensure(
        native_path(&value["plan"]["scope"])? == root
            && value["plan"]["execution_contract"] == "revalidated_trash_v1"
            && value["plan"]["rejected"] == json!([])
            && value["plan"]["selection_issues"] == json!([]),
        "unexpected plan scope/contract/refusals",
    )?;
    let items = value["plan"]["items"]
        .as_array()
        .ok_or_else(|| refused("missing plan items"))?;
    ensure(
        items.len() == targets.len(),
        "plan item count differs from frozen selection",
    )?;
    let mut seen = HashSet::new();
    for item in items {
        let path = native_path(&item["path"])?;
        let target = targets
            .iter()
            .find(|target| target.path == path)
            .ok_or_else(|| refused("unregistered plan target"))?;
        ensure(
            seen.insert(path)
                && item["identity"]["device"] == target.held.stamp.device
                && item["identity"]["inode"] == target.held.stamp.inode
                && item["logical_bytes"] == target.bytes.len(),
            "plan identity/size mismatch",
        )?;
    }
    Ok(())
}

fn receipt_destinations(
    value: &Value,
    root: &Path,
    targets: &[Target],
) -> io::Result<Vec<PathBuf>> {
    ensure(
        value["kind"] == "receipts"
            && value["schema_version"] == 1
            && value["journal"]["uncommitted_snapshots"] == json!([]),
        "receipt is incomplete or ambiguous",
    )?;
    let records = value["journal"]["records"]
        .as_array()
        .ok_or_else(|| refused("missing records"))?;
    ensure(records.len() == 1, "expected exactly one operation")?;
    let record = &records[0];
    ensure(
        record["schema_version"] == 1
            && record["plan_schema_version"] == 2
            && record["engine_version"] == 2
            && record["rules_version"] == 1
            && record["contract"] == "revalidated_trash_v1"
            && native_path(&record["scope"])? == root,
        "unexpected operation schema/scope/contract",
    )?;
    let items = record["items"]
        .as_array()
        .ok_or_else(|| refused("missing receipt items"))?;
    ensure(items.len() == targets.len(), "receipt item count mismatch")?;
    let mut destinations = Vec::new();
    let mut seen = HashSet::new();
    let decoded = items
        .iter()
        .map(|item| Ok((native_path(&item["path"])?, item)))
        .collect::<io::Result<Vec<_>>>()?;
    for target in targets {
        let matches = decoded
            .iter()
            .filter(|(path, _)| path == &target.path)
            .collect::<Vec<_>>();
        ensure(
            matches.len() == 1,
            "missing/duplicate original path in receipt",
        )?;
        let item = matches[0].1;
        ensure(
            item["state"] == "succeeded"
                && item["reason"].is_null()
                && item["device"] == target.held.stamp.device
                && item["inode"] == target.held.stamp.inode
                && item["logical_bytes"] == target.bytes.len()
                && item["recovery_evidence"].is_null(),
            "receipt outcome/identity mismatch",
        )?;
        let destination = native_path(&item["destination"])?;
        ensure(seen.insert(destination.clone()), "duplicate destination")?;
        destinations.push(destination);
    }
    Ok(destinations)
}

fn register_auxiliary(fixture: &mut Fixture, roots: &[PathBuf]) -> io::Result<()> {
    let mut known = fixture
        .objects
        .iter()
        .map(|(path, _, _)| path.clone())
        .collect::<HashSet<_>>();
    let mut pending = roots.to_vec();
    let mut count = 0;
    while let Some(root) = pending.pop() {
        for entry in fs::read_dir(&root)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            ensure(
                path.starts_with(&fixture.root)
                    && meta.uid() == ordinary_authority()?
                    && meta.dev() == fixture.objects[0].1.0
                    && !meta.file_type().is_symlink()
                    && (meta.is_dir() || meta.is_file()),
                "unexpected auxiliary fixture entry; preserve it",
            )?;
            count += 1;
            ensure(count <= 4096, "auxiliary fixture entry budget exceeded")?;
            if known.insert(path.clone()) {
                fixture.record(path.clone(), meta.is_dir());
            }
            if meta.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

#[test]
fn native_acceptance_requires_both_explicit_gates() {
    for (run, quiet) in [
        (None, None),
        (Some("1"), None),
        (None, Some("1")),
        (Some("0"), Some("1")),
    ] {
        assert!(authorized(run, quiet).is_err());
    }
    authorized(Some("1"), Some("1")).unwrap();
}

#[test]
fn native_receipt_paths_reject_display_only_and_traversal() {
    let path = PathBuf::from("/owned/fixture.dmg");
    let wire = json!({"display": format!("{:?}", path.as_os_str()),
        "encoding": "unix_bytes", "bytes": path.as_os_str().as_bytes()});
    assert_eq!(native_path(&wire).unwrap(), path);
    for bytes in [
        b"relative".as_slice(),
        b"/owned/../foreign",
        b"/owned/\0file",
    ] {
        let invalid = json!({"display": "irrelevant", "encoding": "unix_bytes", "bytes": bytes});
        assert!(native_path(&invalid).is_err());
    }
    assert!(native_path(&json!({"display": "/owned/fixture.dmg"})).is_err());
}

#[test]
fn exclusive_restore_control_keeps_both_owned_objects() {
    let mut fixture = Fixture::new();
    let source = fixture.file("source", b"source");
    let blocker = fixture.file("blocker", b"blocker");
    let directory = Evidence::open_safety(&fixture.root).unwrap();
    let source_before = Evidence::open(&source).unwrap();
    let blocker_before = Evidence::open(&blocker).unwrap();
    let result = no_overwrite_rename(
        &directory.file,
        OsStr::new("source"),
        &directory.file,
        OsStr::new("blocker"),
    );
    assert!(matches!(result, Err(error) if error.raw_os_error() == Some(libc::EEXIST)));
    assert_eq!(
        checked_bytes(&source, &source_before, 6).unwrap(),
        b"source"
    );
    assert_eq!(
        checked_bytes(&blocker, &blocker_before, 7).unwrap(),
        b"blocker"
    );
    fixture.finish();
}

#[test]
fn owned_command_group_is_stopped_and_reaped() {
    let child = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .process_group(0)
        .spawn()
        .unwrap();
    let mut owned = OwnedGroup {
        child,
        reaped: false,
    };
    owned.stop().unwrap();
    assert!(owned.reaped && owned.child.try_wait().unwrap().is_some());
}

#[test]
fn command_broker_handles_completed_commands_and_failed_descendants() {
    let mut fixture = Fixture::new();
    let auxiliary = fixture.directory("target");
    let mut log = Log::new(&fixture.root, OsStr::new("broker-control")).unwrap();
    let mut success = Command::new("/usr/bin/true");
    isolated(&mut success, &fixture.root, &fixture.root);
    assert!(
        command_output(&mut success, "success", &mut log)
            .unwrap()
            .is_empty()
    );
    let mut failure = Command::new("/usr/bin/false");
    isolated(&mut failure, &fixture.root, &fixture.root);
    assert!(command_output(&mut failure, "failure", &mut log).is_err());
    let leaked = fixture.root.join("must-not-be-created");
    let mut descendants = Command::new("/usr/bin/python3");
    descendants.args(["-c",
        "import os,subprocess,sys; subprocess.Popen([sys.executable,'-c',\"import pathlib,sys,time;time.sleep(1);pathlib.Path(sys.argv[1]).write_text('leaked')\",sys.argv[1]],close_fds=True); os._exit(7)"])
        .arg(&leaked);
    isolated(&mut descendants, &fixture.root, &fixture.root);
    assert!(command_output(&mut descendants, "descendants", &mut log).is_err());
    std::thread::sleep(Duration::from_secs(2));
    assert!(!leaked.exists(), "failed child left a live writer");
    drop(log);
    register_auxiliary(&mut fixture, &[auxiliary]).unwrap();
    fixture.finish();
}

#[test]
fn failed_leader_does_not_leave_a_live_descendant() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let (mut reader, writer) = UnixStream::pair().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let child = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import os,subprocess; subprocess.Popen(['/bin/sleep','5']); os._exit(7)",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .process_group(0)
        .spawn()
        .unwrap();
    let mut owned = OwnedGroup {
        child,
        reaped: false,
    };
    let started = Instant::now();
    loop {
        if let Some(status) = owned.observe_exit().unwrap() {
            assert_eq!(status, (libc::CLD_EXITED, 7));
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "leader did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!owned.reaped);
    owned.stop().unwrap();
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .expect("descendant's inherited stdout must close after group cleanup");
    assert!(output.is_empty());
}

#[test]
fn owned_relocation_reanchors_ctime_but_preserves_other_metadata_and_bytes() {
    let mut fixture = Fixture::new();
    let source = fixture.file("source", b"original");
    let destination = fixture.root.join("relocated");
    let mut target = Target {
        held: Evidence::open(&source).unwrap(),
        path: source.clone(),
        bytes: b"original".to_vec(),
    };
    fixture.rename(&source, &destination);
    target.held.stamp.changed = (0, 0);
    location(&target, &destination).expect("post-rename ctime is reanchored");
    target.held.stamp.size += 1;
    assert!(location(&target, &destination).is_err());
    target.held.stamp.size -= 1;
    target.bytes[0] = b'x';
    assert!(location(&target, &destination).is_err());
    drop(target);
    fixture.finish();
}

#[test]
fn receipt_rejects_pending_unknown_malformed_and_wrong_identity() {
    let mut fixture = Fixture::new();
    let path = fixture.file("source.dmg", b"fixture");
    let target = Target {
        held: Evidence::open(&path).unwrap(),
        path,
        bytes: b"fixture".to_vec(),
    };
    let destination = fixture.root.join("observed-only-destination");
    let wire = |path: &Path| {
        json!({
            "display": format!("{:?}", path.as_os_str()), "encoding": "unix_bytes",
            "bytes": path.as_os_str().as_bytes(),
        })
    };
    let base = json!({"kind": "receipts", "schema_version": 1, "journal": {
        "uncommitted_snapshots": [], "records": [{
            "schema_version": 1, "plan_schema_version": 2, "engine_version": 2, "rules_version": 1,
            "contract": "revalidated_trash_v1", "scope": wire(&fixture.root),
            "items": [{"path": wire(&target.path), "state": "succeeded", "reason": null,
                "device": target.held.stamp.device, "inode": target.held.stamp.inode,
                "logical_bytes": target.bytes.len(), "destination": wire(&destination)}]
        }]
    }});
    assert_eq!(
        receipt_destinations(&base, &fixture.root, std::slice::from_ref(&target)).unwrap(),
        vec![destination]
    );
    for mutation in ["pending", "unknown", "identity", "path", "duplicate"] {
        let mut changed = base.clone();
        let record = &mut changed["journal"]["records"][0];
        match mutation {
            "pending" => changed["journal"]["uncommitted_snapshots"] = json!(["pending"]),
            "unknown" => record["items"][0]["state"] = json!("unknown"),
            "identity" => record["items"][0]["inode"] = json!(0),
            "path" => record["items"][0]["path"]["bytes"] = json!([0]),
            "duplicate" => {
                let copy = record["items"][0].clone();
                record["items"].as_array_mut().unwrap().push(copy);
            }
            _ => unreachable!(),
        }
        assert!(
            receipt_destinations(&changed, &fixture.root, std::slice::from_ref(&target)).is_err(),
            "{mutation}"
        );
    }
    drop(target);
    fixture.finish();
}

#[test]
#[ignore = "REAL SYSTEM TRASH: exactly three owned installer files; explicit current authorization and quiescence required"]
fn real_installer_cli_owned_fixture_round_trips() -> io::Result<()> {
    authorized(
        std::env::var("SAYAKA_INSTALLER_TRASH_TEST").ok().as_deref(),
        std::env::var("SAYAKA_INSTALLER_TRASH_TEST_QUIESCENT")
            .ok()
            .as_deref(),
    )?;
    let expected_hash = std::env::var("SAYAKA_INSTALLER_CLI_SHA256")
        .map_err(|_| refused("explicit reviewed CLI SHA-256 is required"))?;
    ensure(
        expected_hash.len() == 64 && expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid expected CLI hash",
    )?;
    let repo = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    let binary = repo.join("target/release/sayaka");
    let binary_evidence = Evidence::open(&binary)?;
    ensure(
        binary_evidence.stamp.uid == ordinary_authority()?
            && binary_evidence.stamp.mode & 0o6000 == 0,
        "unexpected binary ownership/privilege bits",
    )?;
    let binary_bytes = checked_bytes(&binary, &binary_evidence, CLI_CAP)?;
    ensure(
        sha256(&binary_bytes) == expected_hash,
        "CLI artifact hash mismatch",
    )?;
    let mut fixture = Fixture::new();
    fixture.preserve = true;
    let marker = Evidence::open(&fixture.root.join("ownership-marker"))?;
    let mut log = Log::new(&repo, fixture.root.file_name().unwrap())?;
    println!("Private native acceptance evidence: {:?}", log.root);
    log.event(json!({"event": "frozen_contract", "cli_sha256": expected_hash,
        "test_source_sha256": sha256(include_bytes!("installer_roundtrip.rs")),
        "support_source_sha256": sha256(include_bytes!("tests.rs")),
        "native_source_sha256": sha256(include_bytes!("native.rs")),
        "foundation_source_sha256": sha256(include_bytes!("foundation.rs")),
        "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "fixture_root": fixture.root, "max_trash_items": 3, "cases": ["single_explicit", "batch_numeric"],
        "fixture_identity": fixture.objects[0].1,
        "marker_identity": marker.stamp.identity(),
        "output_cap_bytes": OUTPUT_CAP, "command_deadline_seconds": DEADLINE.as_secs(),
        "quiescence": "operator_confirmed", "residual_pathname_race": true}))?;
    let result = (|| -> io::Result<Value> {
        let staged = fixture.file("sayaka", &binary_bytes);
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
        let staged_evidence = Evidence::open(&staged)?;
        ensure(
            sha256(&checked_bytes(&staged, &staged_evidence, CLI_CAP)?) == expected_hash,
            "staged hash mismatch",
        )?;
        let mut auxiliary = Vec::new();
        let mut summaries = Vec::new();
        let mut completed_targets = Vec::new();
        let mut completed_destinations = Vec::new();
        let mut sentinels = Vec::new();
        let mut recovery_guards = Vec::new();
        let mut reserved_native_items = 0;
        for (case_index, mode) in ["explicit", "numeric"].into_iter().enumerate() {
            let root = fixture.directory(&format!("case-{case_index}"));
            let home = fixture.directory(&format!("home-{case_index}"));
            let tmp = fixture.directory(&format!("tmp-{case_index}"));
            let state = fixture.directory(&format!("state-{case_index}"));
            auxiliary.extend([home.clone(), tmp.clone(), state.clone()]);
            let sentinel = root.join("keep.txt");
            fs::write(&sentinel, b"owned non-target sentinel")?;
            fixture.record(sentinel.clone(), false);
            let sentinel_evidence = Evidence::open(&sentinel)?;
            let specs = if case_index == 0 {
                vec![("single.dmg", dmg_bytes())]
            } else {
                vec![("batch-a.dmg", dmg_bytes()), ("batch-b.pkg", pkg_bytes()?)]
            };
            let mut targets = Vec::new();
            for (name, bytes) in specs {
                let name = format!(
                    "{}-{name}",
                    fixture.root.file_name().unwrap().to_string_lossy()
                );
                let path = root.join(name);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(&bytes)?;
                full_sync(&file)?;
                fixture.record(path.clone(), false);
                let held = Evidence::open(&path)?;
                targets.push(Target { path, bytes, held });
            }
            File::open(&root)?.sync_all()?;
            File::open(&fixture.root)?.sync_all()?;
            let recovery = with_policy(|| Recovery::prepare(&root, &targets[0]))?;
            if let Some(previous) = recovery_guards.first() {
                let previous: &Recovery = previous;
                ensure(
                    previous.trash.stamp.identity() == recovery.trash.stamp.identity()
                        && previous.trash.physical == recovery.trash.physical,
                    "native Trash directory changed between cases",
                )?;
            }
            for target in &targets {
                with_policy(|| {
                    TrashCandidate::capture(&root, &target.path, std::slice::from_ref(&sentinel))
                })?;
                ensure(
                    checked_bytes(&target.path, &target.held, 4096)? == target.bytes,
                    "initial bytes mismatch",
                )?;
                log.event(
                    json!({"event": "registered_target", "case": case_index, "path": target.path,
                    "device": target.held.stamp.device, "inode": target.held.stamp.inode,
                    "bytes": target.bytes.len(), "sha256": sha256(&target.bytes)}),
                )?;
            }
            log.event(json!({"event": "recovery_preflight", "case": case_index,
                "original": root, "trash": recovery.trash.path,
                "original_device": recovery.original.stamp.device,
                "original_inode": recovery.original.stamp.inode,
                "original_physical": recovery.original.physical,
                "trash_physical": recovery.trash.physical,
                "trash_device": recovery.trash.stamp.device, "trash_inode": recovery.trash.stamp.inode}))?;
            let mut preview = Command::new(&staged);
            isolated(&mut preview, &home, &tmp);
            preview
                .arg("installer")
                .arg(&root)
                .arg("--json")
                .arg("--exclude")
                .arg(&sentinel)
                .arg("--state-dir")
                .arg(&state);
            for target in &targets {
                preview.arg("--select").arg(&target.path);
            }
            let preview = command_output(
                &mut preview,
                &format!("case-{case_index}-preview"),
                &mut log,
            )?;
            validate_plan(&serde_json::from_slice(&preview)?, &root, &targets)?;
            ensure(
                fs::read_dir(&state)?.next().is_none(),
                "preview created journal state",
            )?;
            recovery.check()?;
            marker.revalidate()?;
            staged_evidence.revalidate()?;
            for target in &targets {
                target.held.revalidate()?;
            }
            reserved_native_items += targets.len();
            ensure(
                targets.len() == case_index + 1 && reserved_native_items <= 3,
                "frozen native effect count exceeded",
            )?;
            log.event(json!({"event": "mutating_cli_intent", "case": case_index,
                "count": targets.len(), "mode": mode, "binary": staged,
                "root": root, "state": state, "home": home, "tmp": tmp,
                "targets": targets.iter().map(|target| &target.path).collect::<Vec<_>>(),
                "confirmation": format!("trash {}", targets.len())}))?;
            let mut execute = Command::new("/usr/bin/python3");
            isolated(&mut execute, &home, &tmp);
            execute
                .arg("-c")
                .arg(PTY_DRIVER)
                .arg(&staged)
                .arg(&root)
                .arg(&state)
                .arg(&sentinel)
                .arg(mode)
                .arg(targets.len().to_string());
            for target in &targets {
                execute.arg(&target.path);
            }
            command_output(
                &mut execute,
                &format!("case-{case_index}-execute"),
                &mut log,
            )?;
            let mut receipt = Command::new(&staged);
            isolated(&mut receipt, &home, &tmp);
            receipt
                .args(["receipt", "--json", "--state-dir"])
                .arg(&state);
            let receipt = command_output(
                &mut receipt,
                &format!("case-{case_index}-receipt"),
                &mut log,
            )?;
            let destinations =
                receipt_destinations(&serde_json::from_slice(&receipt)?, &root, &targets)?;
            for (index, (target, destination)) in targets.iter().zip(&destinations).enumerate() {
                restore(
                    &mut fixture,
                    target,
                    destination,
                    &recovery,
                    &mut log,
                    &format!("case-{case_index}-{index}"),
                )?;
            }
            marker.revalidate()?;
            ensure(
                checked_bytes(&sentinel, &sentinel_evidence, 128)? == b"owned non-target sentinel",
                "sentinel changed",
            )?;
            summaries.push(json!({"case": case_index, "selection_mode": mode, "moved": targets.len(),
                "receipts_verified": true, "identity_content_verified": true, "exclusive_conflicts_verified": targets.len(),
                "restored": targets.len(), "sentinel_unchanged": true}));
            completed_targets.extend(targets);
            completed_destinations.extend(destinations);
            sentinels.push((sentinel, sentinel_evidence));
            recovery_guards.push(recovery);
        }
        ensure(
            reserved_native_items == 3 && completed_targets.len() == 3,
            "native case count incomplete",
        )?;
        for guard in &recovery_guards {
            guard.check()?;
        }
        for target in &completed_targets {
            location(target, &target.path)?;
        }
        for destination in &completed_destinations {
            vacant(destination)?;
        }
        for (path, evidence) in &sentinels {
            ensure(
                checked_bytes(path, evidence, 128)? == b"owned non-target sentinel",
                "sentinel changed across cases",
            )?;
        }
        marker.revalidate()?;
        register_auxiliary(&mut fixture, &auxiliary)?;
        log.event(json!({"event": "cleanup_intent", "registered_entries": fixture.objects.len()}))?;
        fixture.cleanup()?;
        Ok(
            json!({"status": "completed", "cli_sha256": expected_hash, "cases": summaries,
            "native_moved": 3, "restored": 3, "conflict_checks": 3, "fixture_cleanup_verified": true,
            "trash_enumerated": false, "other_trash_entries_touched": false,
            "fixtures_are_synthetic_structure_only": true, "residual_pathname_race": true}),
        )
    })();
    match result {
        Ok(summary) => {
            log.event(json!({"event": "completed", "summary": summary}))?;
            println!("{}", serde_json::to_string(&summary)?);
            Ok(())
        }
        Err(error) => {
            let saved = log.event(json!({"event": "failed_preserved", "error": error.to_string(), "fixture_root": fixture.root}));
            Err(io::Error::other(format!(
                "{error}; fixtures preserved at {:?}; private evidence {:?}; evidence write: {saved:?}; no retry or guessed restore",
                fixture.root, log.root
            )))
        }
    }
}
