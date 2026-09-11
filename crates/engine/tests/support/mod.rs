// SPDX-License-Identifier: MPL-2.0

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub struct Fixture {
    directory: Option<TempDir>,
}

impl Fixture {
    pub fn new() -> io::Result<Self> {
        let directory = tempfile::Builder::new().prefix("sayaka-m1-").tempdir()?;
        let fixture = Self {
            directory: Some(directory),
        };
        fs::write(
            fixture.path().join("owner-marker"),
            b"sayaka-m1-owned-fixture",
        )?;
        fs::write(fixture.path().join("target.txt"), b"test-owned target")?;
        fs::create_dir(fixture.path().join("protected"))?;
        fs::write(
            fixture.path().join("protected/keep.txt"),
            b"must remain unchanged",
        )?;
        for name in ["home", "state", "config", "temp"] {
            fs::create_dir(fixture.path().join(name))?;
        }
        Ok(fixture)
    }

    pub fn path(&self) -> &Path {
        self.directory
            .as_ref()
            .expect("fixture already closed")
            .path()
    }

    pub fn close(mut self) -> io::Result<()> {
        self.directory
            .take()
            .expect("fixture already closed")
            .close()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            eprintln!("test fixture cleanup failed: {error:?}");
            if !std::thread::panicking() {
                panic!("test fixture cleanup failed");
            }
        }
    }
}

struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl OwnedChild {
    fn wait(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture child exceeded its time budget",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            if let Err(error) = self.child.kill() {
                eprintln!(
                    "could not stop owned test child {}: {error:?}",
                    self.child.id()
                );
            }
            if let Err(error) = self.child.wait() {
                eprintln!(
                    "could not reap owned test child {}: {error:?}",
                    self.child.id()
                );
            }
        }
    }
}

pub fn run_child(root: &Path) -> io::Result<(ExitStatus, String, String)> {
    run_child_with_timeout(root, Duration::from_secs(15), false)
}

pub fn run_child_with_timeout(
    root: &Path,
    timeout: Duration,
    park: bool,
) -> io::Result<(ExitStatus, String, String)> {
    let stdout_path = root.join("child.stdout");
    let stderr_path = root.join("child.stderr");
    let stdout = fs::File::create(&stdout_path)?;
    let stderr = fs::File::create(&stderr_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "isolated_plan_round_trip",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("SAYAKA_M1_CHILD_ROOT", root)
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("APPDATA", root.join("config"))
        .env("LOCALAPPDATA", root.join("state"))
        .env("TMPDIR", root.join("temp"))
        .env("TEMP", root.join("temp"))
        .env("TMP", root.join("temp"))
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    if park {
        command.env("SAYAKA_M1_CHILD_PARK", "1");
    }
    let status = {
        let mut child = OwnedChild {
            child: command.spawn()?,
            reaped: false,
        };
        child.wait(timeout)?
    };
    Ok((
        status,
        fs::read_to_string(stdout_path)?,
        fs::read_to_string(stderr_path)?,
    ))
}
