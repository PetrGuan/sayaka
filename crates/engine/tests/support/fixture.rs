// SPDX-License-Identifier: MPL-2.0

use std::fs;
use std::io;
use std::path::Path;
#[path = "owned_temp.rs"]
mod owned_temp;
use owned_temp::OwnedTempDir as TempDir;

pub struct Fixture {
    directory: Option<TempDir>,
}

impl Fixture {
    pub fn new() -> io::Result<Self> {
        let directory = TempDir::new(&std::env::temp_dir(), "sayaka-m1-")?;
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
