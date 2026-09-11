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

struct Fixture {
    directory: Option<TempDir>,
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Never use the user's temp directory, HOME, or working tree as a scan root.
        let directory = tempfile::Builder::new()
            .prefix(".sayaka-cli-test-")
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
