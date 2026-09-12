// SPDX-License-Identifier: MPL-2.0

use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const DEADLINE: Duration = Duration::from_secs(30);

#[test]
#[cfg(target_os = "macos")]
fn browse_plain_counts_hardlinks_independently_in_siblings() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("left")).unwrap();
    fs::create_dir(fixture.root.join("right")).unwrap();
    fs::write(fixture.root.join("left/data"), [0u8; 100]).unwrap();
    fs::hard_link(
        fixture.root.join("left/data"),
        fixture.root.join("right/alias"),
    )
    .unwrap();
    let state = fixture.base.join("browser-journal");
    let mut command = fixture.command();
    command
        .arg("browse")
        .arg(&fixture.root)
        .arg("--plain")
        .arg("--state-dir")
        .arg(&state);
    let result = capture(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(text.contains("Root unique files: 1"), "{text}");
    assert!(
        text.contains("Root logical subtotal: 100 bytes; unknown files: 0; complete: true"),
        "{text}"
    );
    for directory in ["left", "right"] {
        assert!(
            text.lines().any(|line| line.contains("(known_bytes=100)")
                && line.ends_with(&format!("/{directory}\""))),
            "{text}"
        );
    }
    assert!(!state.exists());
}

#[test]
fn browse_requires_a_root_and_does_not_implicitly_scan() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.arg("browse");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("snapshot"));
}

#[test]
#[cfg(target_os = "macos")]
fn browse_pipe_fallback_and_alias_are_read_only_and_missing_scope_fails() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("kept.txt"), b"kept").unwrap();
    let mut command = fixture.command();
    command.arg("analyze").arg(&fixture.root);
    let result = capture(command);
    assert!(result.status.success());
    assert!(!result.stdout.contains(&0x1b));
    assert_eq!(fs::read(fixture.root.join("kept.txt")).unwrap(), b"kept");
    let mut command = fixture.command();
    command.arg("browse").arg(fixture.root.join("missing"));
    let result = capture(command);
    assert!(!result.status.success());
    assert!(!result.stdout.contains(&0x1b));
}

#[cfg(target_os = "macos")]
fn exclusion_preview(
    fixture: &Fixture,
    file: &std::path::Path,
    excluded: &std::path::Path,
) -> Value {
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(file)
        .arg("--exclude")
        .arg(excluded)
        .arg("--json");
    let result = capture(command);
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[cfg(target_os = "macos")]
fn same_native_object(original: &std::path::Path, alias: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let original = fs::symlink_metadata(original).unwrap();
    match fs::symlink_metadata(alias) {
        Ok(alias) => (alias.dev(), alias.ino()) == (original.dev(), original.ino()),
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            false
        }
    }
}

#[test]
#[cfg(target_os = "macos")]
fn trash_file_case_alias_exclusion_is_not_ignored() {
    let fixture = Fixture::new();
    let file = fixture.root.join("Chosen.txt");
    let alias = fixture.root.join("chosen.txt");
    fs::write(&file, b"owned case alias fixture").unwrap();
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(value["items"].as_array().unwrap().len(), 0, "{value}");
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"owned case alias fixture");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_ancestor_case_alias_exclusion_is_not_ignored() {
    let fixture = Fixture::new();
    let parent = fixture.root.join("ChosenFolder");
    fs::create_dir(&parent).unwrap();
    let file = parent.join("file.txt");
    fs::write(&file, b"owned ancestor alias fixture").unwrap();
    let alias = fixture.root.join("chosenfolder");
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(value["items"].as_array().unwrap().len(), 0, "{value}");
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"owned ancestor alias fixture");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_unicode_alias_exclusion_uses_native_identity() {
    let fixture = Fixture::new();
    let file = fixture.root.join("caf\u{e9}.txt");
    let alias = fixture.root.join("cafe\u{301}.txt");
    fs::write(&file, b"owned normalization alias fixture").unwrap();
    let aliases = same_native_object(&file, &alias);
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(
        value["items"].as_array().unwrap().len(),
        usize::from(!aliases),
        "{value}"
    );
    if aliases {
        assert_eq!(value["rejected"][0]["reason"], "excluded");
    }
    assert_eq!(
        fs::read(file).unwrap(),
        b"owned normalization alias fixture"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn trash_missing_unrelated_exclusion_does_not_remove_selection() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"owned unrelated exclusion fixture").unwrap();
    let value = exclusion_preview(&fixture, &file, &fixture.root.join("unrelated/missing"));
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert!(value["rejected"].as_array().unwrap().is_empty());
}

#[test]
#[cfg(target_os = "macos")]
fn trash_refuses_disk_image_and_vm_package_members() {
    let fixture = Fixture::new();
    for name in ["Disk.sparsebundle", "Machine.vmwarevm"] {
        let parent = fixture.root.join(name).join("bands");
        fs::create_dir_all(&parent).unwrap();
        let file = parent.join("0");
        fs::write(&file, b"owned package member fixture").unwrap();
        let mut command = fixture.command();
        command
            .arg("trash")
            .arg("--scope")
            .arg(&fixture.root)
            .arg(&file)
            .arg("--json");
        let result = capture(command);
        assert_eq!(result.status.code(), Some(3));
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(value["items"].as_array().unwrap().is_empty(), "{value}");
        assert_eq!(value["rejected"].as_array().unwrap().len(), 1);
        assert_eq!(fs::read(&file).unwrap(), b"owned package member fixture");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn trash_preview_is_versioned_read_only_and_does_not_create_state() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"keep this fixture").unwrap();
    let state = fixture.base.join("journal");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["plan_schema_version"], 2);
    assert_eq!(value["execution_contract"], "revalidated_trash_v1");
    assert_eq!(value["effects_performed"], false);
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert!(
        value["warning"]
            .as_str()
            .unwrap()
            .contains("different file")
    );
    assert_eq!(fs::read(&file).unwrap(), b"keep this fixture");
    assert!(!state.exists());
}

#[test]
fn trash_execution_rejects_piped_confirmation_without_touching_state() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let state = fixture.base.join("journal");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--state-dir")
        .arg(&state)
        .arg("--execute");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("interactive terminal"));
    assert_eq!(fs::read(file).unwrap(), b"untouched");
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn trash_mixed_refusals_are_not_empty_success_and_include_paths() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let missing = fixture.root.join("missing");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg(&missing)
        .arg("--json");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["rejected"].as_array().unwrap().len(), 1);
    assert!(
        value["rejected"][0]["path"]["display"]
            .as_str()
            .unwrap()
            .contains("missing")
    );
    assert_eq!(value["selection_issues"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(file).unwrap(), b"untouched");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_exclusions_are_in_preview_and_never_eligible() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--exclude")
        .arg(&file)
        .arg("--json");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["items"].as_array().unwrap().is_empty());
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"untouched");
}

#[test]
fn receipt_missing_state_is_an_explicit_error_without_creation() {
    let fixture = Fixture::new();
    let state = fixture.base.join("absent-journal");
    let mut command = fixture.command();
    command
        .arg("receipt")
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(!result.status.success());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "receipt");
    assert_eq!(value["status"], "failed");
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn receipt_preserves_unverified_recovery_hints_without_retrying() {
    use sayaka_engine::journal::{
        FileEvidence, ItemRecord, ItemState, NativePath, NativeTime, Record, RecoveryEvidence,
        SCHEMA_VERSION, Store,
    };
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let fixture = Fixture::new();
    let file = fixture.root.join("untouched.txt");
    fs::write(&file, b"owned evidence fixture").unwrap();
    let metadata = fs::metadata(&file).unwrap();
    let evidence = FileEvidence {
        device: metadata.dev(),
        inode: metadata.ino(),
        logical_bytes: metadata.len(),
        modified: NativeTime::from_system_time(metadata.modified().unwrap()),
    };
    let state = fixture.base.join("evidence-journal");
    drop(Store::open(&state, true).unwrap());
    let record = Record {
        schema_version: SCHEMA_VERSION,
        plan_schema_version: 2,
        engine_version: 2,
        rules_version: 1,
        operation_id: "b-2".into(),
        contract: "revalidated_trash_v1".into(),
        scope: NativePath::from_path(&fixture.root),
        created_unix_ms: 1,
        items: vec![ItemRecord {
            path: NativePath::from_path(&file),
            device: metadata.dev(),
            inode: metadata.ino(),
            logical_bytes: metadata.len(),
            state: ItemState::Unknown,
            reason: Some("synthetic unverified outcome".into()),
            destination: None,
            updated_unix_ms: 1,
            recovery_evidence: Some(RecoveryEvidence {
                approved: evidence.clone(),
                returned_destination: Some(NativePath::from_path(std::path::Path::new(
                    "/fixture-trash/unverified",
                ))),
                held_source: Some(evidence),
                held_source_path: Some(NativePath::from_path(&file)),
                observation_errors: vec!["synthetic destination verification failure".into()],
            }),
        }],
    };
    record.validate().unwrap();
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join("b-2.json"))
        .unwrap();
    serde_json::to_writer(output, &record).unwrap();
    let before = fs::read(state.join("b-2.json")).unwrap();
    let mut command = fixture.command();
    command
        .arg("receipt")
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let item = &value["journal"]["records"][0]["items"][0];
    assert_eq!(item["state"], "unknown");
    assert!(item["destination"].is_null());
    assert_eq!(
        item["recovery_evidence"]["approved"]["inode"],
        metadata.ino()
    );
    assert!(
        item["recovery_evidence"]["returned_destination"]["display"]
            .as_str()
            .unwrap()
            .contains("/fixture-trash/unverified")
    );
    let mut command = fixture.command();
    command.arg("receipt").arg("--state-dir").arg(&state);
    let result = capture(command);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Unverified OS destination"));
    assert!(text.contains("no automatic retry or restoration"));
    assert_eq!(fs::read(&file).unwrap(), b"owned evidence fixture");
    assert_eq!(fs::read(state.join("b-2.json")).unwrap(), before);
}

struct Fixture {
    directory: Option<TempDir>,
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Never use the user's temp directory, HOME, or working tree as a scan root.
        let directory = tempfile::Builder::new()
            .prefix("sayaka-cli-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create dedicated fixture");
        let base = directory.path().canonicalize().expect("canonical fixture");
        for name in ["root", "home", "config", "state", "cache", "temp"] {
            fs::create_dir(base.join(name)).expect("create fixture directory");
        }
        let root = base.join("root");
        Self {
            directory: Some(directory),
            base,
            root,
        }
    }

    fn isolate(&self, command: &mut Command) {
        command
            .env_clear()
            .current_dir(&self.base)
            .env("HOME", self.base.join("home"))
            .env("USERPROFILE", self.base.join("home"))
            .env("APPDATA", self.base.join("config"))
            .env("LOCALAPPDATA", self.base.join("state"))
            .env("XDG_CONFIG_HOME", self.base.join("config"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env("XDG_CACHE_HOME", self.base.join("cache"))
            .env("TMPDIR", self.base.join("temp"))
            .env("TMP", self.base.join("temp"))
            .env("TEMP", self.base.join("temp"));
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sayaka"));
        self.isolate(&mut command);
        command
    }

    fn scan(&self, args: &[&str]) -> Captured {
        let mut command = self.command();
        command.arg("scan").arg(&self.root).args(args);
        capture(command)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            eprintln!("fixture cleanup failed: {error}");
            if !thread::panicking() {
                panic!("fixture cleanup failed");
            }
        }
    }
}

struct OwnedChild {
    process: Child,
    reaped: bool,
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        match self.process.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.process.kill() {
                    eprintln!(
                        "could not stop owned CLI child {}: {error}",
                        self.process.id()
                    );
                }
                if let Err(error) = self.process.wait() {
                    eprintln!(
                        "could not reap owned CLI child {}: {error}",
                        self.process.id()
                    );
                }
            }
            Err(error) => eprintln!(
                "owned CLI child status is unknown; not signalling an unverified PID: {error}"
            ),
        }
    }
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct Running {
    child: OwnedChild,
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
    #[cfg(target_os = "macos")]
    first_progress: mpsc::Receiver<()>,
}

impl Running {
    fn start(mut command: Command) -> Self {
        let mut child = OwnedChild {
            process: command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn owned child"),
            reaped: false,
        };
        let mut stdout = child.process.stdout.take().expect("stdout pipe");
        let stderr = child.process.stderr.take().expect("stderr pipe");
        let (sender, _first_progress) = mpsc::channel();
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read stdout");
            bytes
        });
        let stderr = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let mut notified = false;
            loop {
                let start = bytes.len();
                if reader.read_until(b'\n', &mut bytes).expect("read stderr") == 0 {
                    break;
                }
                if !notified
                    && serde_json::from_slice::<Value>(&bytes[start..])
                        .is_ok_and(|value| value["type"] == "progress")
                {
                    let _ = sender.send(());
                    notified = true;
                }
            }
            bytes
        });
        Self {
            child,
            stdout,
            stderr,
            #[cfg(target_os = "macos")]
            first_progress: _first_progress,
        }
    }

    fn finish(mut self) -> Captured {
        let deadline = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(status) = self.child.process.try_wait().expect("poll child") {
                self.child.reaped = true;
                break status;
            }
            if Instant::now() >= deadline {
                self.child
                    .process
                    .kill()
                    .expect("kill timed-out owned child");
                self.child
                    .process
                    .wait()
                    .expect("reap timed-out owned child");
                self.child.reaped = true;
                panic!("CLI exceeded finite test deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        Captured {
            status,
            stdout: self.stdout.join().expect("stdout reader"),
            stderr: self.stderr.join().expect("stderr reader"),
        }
    }
}

fn capture(command: Command) -> Captured {
    Running::start(command).finish()
}

fn json(output: &Captured, exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "stderr={:?}, stdout={:?}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("one final JSON object");
    let mut keys: Vec<_> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "complete",
            "entries",
            "issues",
            "issues_omitted",
            "metrics",
            "roots",
            "schema_version",
            "status",
            "task_id",
            "totals"
        ]
    );
    assert_eq!(value["schema_version"], 1);
    value
}

#[test]
fn help_version_and_required_root_are_portable() {
    let fixture = Fixture::new();
    for args in [vec!["--help"], vec!["--version"], vec!["scan", "--help"]] {
        let mut command = fixture.command();
        command.args(args);
        let output = capture(command);
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for args in [vec!["scan"], vec!["scan", "--json"]] {
        let mut command = fixture.command();
        command.args(args);
        let output = capture(command);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("\n\nUsage:"));
        assert!(!error.contains("\\n"));
        assert!(!error.contains("\\'"));
        assert!(error.contains("cargo run --quiet -p sayaka-cli -- scan ."));
        assert!(error.contains("current directory"));
        assert!(!error.contains("Scanning..."));
    }
}

#[test]
fn semantic_limits_are_fatal_json_but_syntax_errors_are_clap_diagnostics() {
    let fixture = Fixture::new();
    for args in [
        vec!["--workers", "0"],
        vec!["--queue-capacity", "0"],
        vec!["--max-open-dirs", "1"],
        vec!["--max-depth", "0"],
        vec!["--max-entries", "0"],
        vec!["--max-path-bytes", "0"],
        vec!["--timeout-ms", "0"],
        vec!["--timeout-ms", "86400001"],
    ] {
        let mut options = vec!["--json"];
        options.extend(args);
        let value = json(&fixture.scan(&options), 2);
        assert_eq!(value["status"], "failed");
        assert_eq!(value["complete"], false);
        assert!(value["task_id"].is_null());
        assert_eq!(value["roots"], serde_json::json!([]));
        assert_eq!(value["entries"], serde_json::json!([]));
        assert!(value["totals"].is_null());
        assert!(value["metrics"].is_null());
        assert_eq!(value["issues_omitted"], 0);
        assert_eq!(value["issues"][0]["code"], "invalid_limits");
        assert!(value["issues"][0]["path"].is_null());
    }
    for value in ["abc", "-1", "184467440737095516160", "\u{1b}[31m"] {
        let output = fixture.scan(&["--json", "--workers", value]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!output.stderr.contains(&0x1b));
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_scanning_is_explicitly_unsupported() {
    let fixture = Fixture::new();
    let value = json(&fixture.scan(&["--json"]), 1);
    assert_eq!(value["issues"][0]["code"], "unsupported_platform");
    assert_eq!(value["complete"], false);
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;
    use std::path::Path;

    fn raw(path: &Path) -> String {
        path.as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn entry<'a>(value: &'a Value, path: &Path) -> &'a Value {
        value["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|entry| entry["path"]["raw"] == raw(path))
            .expect("fixture entry")
    }

    #[test]
    fn exact_envelope_totals_empty_directories_and_hard_link_dedup() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("a"), b"hello").unwrap();
        fs::write(fixture.root.join("b"), b"abc").unwrap();
        fs::hard_link(fixture.root.join("a"), fixture.root.join("alias")).unwrap();
        fs::create_dir(fixture.root.join("empty")).unwrap();
        let output = fixture.scan(&["--json"]);
        let value = json(&output, 0);
        assert!(output.stderr.is_empty());
        assert_eq!(value["status"], "complete");
        assert_eq!(value["complete"], true);
        assert_eq!(value["totals"]["regular_files"], 3);
        assert_eq!(value["totals"]["unique_files"], 2);
        assert_eq!(value["totals"]["duplicate_files"], 1);
        assert_eq!(value["totals"]["directories"], 2);
        assert_eq!(value["totals"]["logical_bytes_known"], 8);
        assert_eq!(value["totals"]["logical_bytes_unknown_files"], 0);
        assert!(value["totals"]["allocated_bytes_known"].is_u64());
        assert_eq!(value["entries"].as_array().unwrap().len(), 5);
        assert_eq!(
            entry(&value, &fixture.root.join("empty"))["kind"],
            "directory"
        );
        let first = entry(&value, &fixture.root.join("a"));
        let alias = entry(&value, &fixture.root.join("alias"));
        assert_eq!(first["identity"], alias["identity"]);
        assert_ne!(first["resource_id"], alias["resource_id"]);
        assert_ne!(first["counted"], alias["counted"]);
        for item in value["entries"].as_array().unwrap() {
            assert_eq!(item.as_object().unwrap().len(), 9);
            assert!(
                item["resource_id"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{}/", value["task_id"].as_str().unwrap()))
            );
            assert_eq!(item["path"]["encoding"], "unix_bytes_hex");
            assert_eq!(item["identity"]["variant"], "unix");
            assert!(item["identity"]["device"].is_u64());
            assert!(item["identity"]["inode"].is_u64());
        }
    }

    #[test]
    fn native_utf8_control_paths_are_lossless_and_diagnostics_escape_controls() {
        let fixture = Fixture::new();
        let control = fixture.root.join("line\n\t\u{1b}[31m");
        fs::write(&control, b"ab").unwrap();
        let value = json(&fixture.scan(&["--json"]), 0);
        let item = entry(&value, &control);
        assert_eq!(item["path"]["raw"], raw(&control));
        assert!(
            !item["path"]["display"]
                .as_str()
                .unwrap()
                .chars()
                .any(char::is_control)
        );
        let link = fixture.root.join("link\n\u{1b}[2J");
        symlink(&control, &link).unwrap();
        let output = fixture.scan(&[]);
        assert_eq!(output.status.code(), Some(0));
        assert!(!output.stderr.contains(&0x1b));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Symbolic link skipped")
        );
    }

    #[test]
    fn invalid_byte_root_error_preserves_original_path_without_creating_a_file() {
        let fixture = Fixture::new();
        let root = fixture
            .root
            .join(OsString::from_vec(b"invalid-\xff".to_vec()));
        let mut command = fixture.command();
        command.arg("scan").arg(&root).arg("--json");
        let output = capture(command);
        assert!(matches!(output.status.code(), Some(1 | 3)));
        let value = json(&output, output.status.code().unwrap());
        assert_eq!(value["complete"], false);
        let expected = raw(&root);
        assert!(
            value["issues"].as_array().unwrap().iter().any(|issue| {
                issue["path"]["encoding"] == "unix_bytes_hex" && issue["path"]["raw"] == expected
            }),
            "failed native lookup must retain its original path: {value}"
        );
    }

    #[test]
    fn readable_reports_rank_files_and_keep_json_opt_in() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("small.txt"), b"1234").unwrap();
        let large = fs::File::create(fixture.root.join("large.bin")).unwrap();
        large.set_len(2 * 1024 * 1024).unwrap();
        drop(large);
        fs::hard_link(
            fixture.root.join("large.bin"),
            fixture.root.join("large-alias.bin"),
        )
        .unwrap();
        let output = fixture.scan(&[]);
        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Sayaka / Storage scan"));
        assert!(text.contains("Scan complete"));
        assert!(text.contains("2.0 MiB"));
        assert!(text.contains("Largest files"));
        assert!(text.contains("bytes counted once"));
        assert!(text.contains("Nothing was deleted"));
        assert!(!text.contains("schema_version"));
        assert!(!text.contains('\x1b'));
        assert!(output.stderr.is_empty());
        assert!(text.find("2.0 MiB  [").unwrap() < text.find("small.txt").unwrap());
        let wire = json(&fixture.scan(&["--json"]), 0);
        assert_eq!(wire["schema_version"], 1);
    }

    #[test]
    fn readable_missing_root_explains_the_path_and_next_step_without_zero_totals() {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        command.arg("scan").arg(fixture.root.join("missing"));
        let output = capture(command);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("Could not scan"));
        assert!(text.contains("Path not found"));
        assert!(text.contains("sayaka scan ."));
        assert!(!text.contains("0 B"));
        assert!(!text.contains("schema_version"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn readable_progress_uses_words_while_json_progress_keeps_its_protocol() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--progress"]);
        assert_eq!(output.status.code(), Some(0));
        let progress = String::from_utf8(output.stderr).unwrap();
        assert!(progress.contains("Scanning"));
        assert!(!progress.contains("schema_version"));
        assert!(!progress.contains('\x1b'));
        let report = String::from_utf8(output.stdout).unwrap();
        assert!(report.contains("Scan complete"));
    }

    #[test]
    fn partial_readable_report_is_explicitly_a_subtotal() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--max-entries", "1"]);
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Partial scan"));
        assert!(text.contains("Observed so far"));
        assert!(text.contains("not the complete folder total"));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Result limit reached")
        );
    }

    #[test]
    fn missing_and_invalid_roots_are_not_success() {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(fixture.root.join("missing\n\u{1b}[2J"))
            .arg("--json");
        let output = capture(command);
        assert!(matches!(output.status.code(), Some(1 | 3)));
        let value = json(&output, output.status.code().unwrap());
        assert_eq!(value["complete"], false);
        assert!(
            value["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["code"] == "not_found")
        );
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(fixture.root.join(".."))
            .arg("--json");
        let value = json(&capture(command), 2);
        assert_eq!(value["issues"][0]["code"], "invalid_root");
        assert!(value["task_id"].is_null());
    }

    #[test]
    fn root_and_ancestor_symlinks_are_never_followed() {
        let fixture = Fixture::new();
        let target = fixture.base.join("owned-target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("child")).unwrap();
        fs::write(target.join("child/secret"), b"must not be traversed").unwrap();
        let link = fixture.root.join("link");
        symlink(&target, &link).unwrap();
        let value = json(&fixture.scan(&["--json"]), 0);
        assert_eq!(value["totals"]["regular_files"], 0);
        assert_eq!(value["totals"]["links"], 1);
        assert_eq!(entry(&value, &link)["kind"], "link");
        for root in [&link, &link.join("child")] {
            let mut command = fixture.command();
            command.arg("scan").arg(root).arg("--json");
            let output = capture(command);
            assert!(!output.status.success());
            let value = json(&output, output.status.code().unwrap());
            assert_eq!(value["complete"], false);
            assert!(
                value["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|item| item["kind"] != "file")
            );
        }
    }

    #[test]
    fn explicit_descendants_are_validated_before_any_overlap_deduplication() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"1234").unwrap();
        let target = fixture.base.join("target");
        fs::create_dir(&target).unwrap();
        let alias = fixture.root.join("link");
        symlink(&target, &alias).unwrap();
        for (descendant, expected) in [
            (fixture.root.join("missing"), "not_found"),
            (alias, "link_skipped"),
            (fixture.root.join("data"), "invalid_root"),
        ] {
            let mut command = fixture.command();
            command
                .arg("scan")
                .arg(&fixture.root)
                .arg(&descendant)
                .arg("--json");
            let value = json(&capture(command), 3);
            assert_eq!(value["complete"], false);
            assert_eq!(value["totals"]["logical_bytes_known"], 4);
            assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
                issue["code"] == expected && issue["path"]["raw"] == raw(&descendant)
            }));
        }
    }

    #[test]
    fn accepted_nested_roots_are_counted_and_traversed_once() {
        let fixture = Fixture::new();
        let child = fixture.root.join("one/two");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("data"), b"1234").unwrap();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(&fixture.root)
            .arg(&child)
            .args(["--json", "--max-depth", "1"]);
        let value = json(&capture(command), 0);
        assert_eq!(value["complete"], true);
        assert_eq!(value["roots"].as_array().unwrap().len(), 2);
        assert_eq!(value["totals"]["directories"], 3);
        assert_eq!(value["totals"]["regular_files"], 1);
        assert_eq!(value["totals"]["logical_bytes_known"], 4);
        let paths: std::collections::HashSet<_> = value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["path"]["raw"].as_str().unwrap())
            .collect();
        assert_eq!(paths.len(), value["entries"].as_array().unwrap().len());
    }

    #[test]
    fn a_rejected_explicit_root_makes_a_mixed_scan_partial() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"1234").unwrap();
        let other = fixture.base.join("other");
        fs::create_dir(&other).unwrap();
        let alias = fixture.base.join("other-link");
        symlink(&other, &alias).unwrap();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(&fixture.root)
            .arg(&alias)
            .arg("--json");
        let value = json(&capture(command), 3);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["complete"], false);
        assert_eq!(value["totals"]["unique_files"], 1);
        assert_eq!(value["totals"]["logical_bytes_known"], 4);
        assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
            issue["code"] == "link_skipped" && issue["path"]["raw"] == raw(&alias)
        }));
    }

    #[test]
    fn entry_and_depth_budgets_are_partial() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.root.join("one/two/three")).unwrap();
        fs::write(fixture.root.join("one/two/three/file"), b"x").unwrap();
        for (flag, limit, code) in [
            ("--max-entries", "1", "entry_limit"),
            ("--max-depth", "1", "depth_limit"),
        ] {
            let value = json(&fixture.scan(&["--json", flag, limit]), 3);
            assert_eq!(value["status"], "partial");
            assert_eq!(value["complete"], false);
            assert!(
                value["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue["code"] == code)
            );
        }
    }

    #[test]
    fn progress_is_versioned_ndjson_only_on_stderr() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--json", "--progress"]);
        let value = json(&output, 0);
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(!stderr.is_empty());
        for line in stderr.lines() {
            let progress: Value = serde_json::from_str(line).unwrap();
            assert_eq!(progress["schema_version"], 1);
            assert_eq!(progress["type"], "progress");
            assert_eq!(progress["task_id"], value["task_id"]);
            for key in [
                "entries",
                "unique_files",
                "logical_bytes_known",
                "issues",
                "elapsed_ms",
            ] {
                assert!(progress[key].is_u64());
            }
            assert_eq!(progress.as_object().unwrap().len(), 8);
        }
    }

    #[test]
    fn sigint_cancels_an_owned_child_after_first_progress() {
        let fixture = Fixture::new();
        // Bounded, dedicated fixture; one worker keeps cancellation observable.
        for directory in 0..120 {
            let path = fixture.root.join(format!("dir-{directory}"));
            fs::create_dir(&path).unwrap();
            for file in 0..100 {
                fs::write(path.join(format!("file-{file}")), b"x").unwrap();
            }
        }
        let mut command = fixture.command();
        command.arg("scan").arg(&fixture.root).args([
            "--json",
            "--progress",
            "--workers",
            "1",
            "--timeout-ms",
            "20000",
        ]);
        let running = Running::start(command);
        running
            .first_progress
            .recv_timeout(Duration::from_secs(10))
            .expect("first progress");
        let mut signal = Command::new("/bin/kill");
        fixture.isolate(&mut signal);
        signal.args(["-INT", &running.child.process.id().to_string()]);
        assert!(capture(signal).status.success());
        let output = running.finish();
        let value = json(&output, 130);
        assert_eq!(value["status"], "cancelled");
        assert_eq!(value["complete"], false);
        assert!(value["entries"].as_array().unwrap().len() < 12_121);
    }
}
