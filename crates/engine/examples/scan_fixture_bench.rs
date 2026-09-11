// SPDX-License-Identifier: MPL-2.0

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("sayaka-m2-bench-");
    let fixture = match std::env::var_os("M2_BENCH_PARENT") {
        Some(parent) => builder.tempdir_in(parent)?,
        None => builder.tempdir()?,
    };
    let result = run_fixture(&fixture);
    if let Err(error) = fixture.close() {
        return Err(
            format!("fixture cleanup failed: {error}; benchmark result: {result:?}").into(),
        );
    }
    result?;
    println!("cleanup=complete");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_fixture(fixture: &tempfile::TempDir) -> Result<(), Box<dyn std::error::Error>> {
    use sayaka_engine::model::Cancellation;
    use sayaka_engine::scan::{ScanLimits, ScanStatus, scan};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::Instant;

    let parent = fixture.path().canonicalize()?;
    let root = parent.join("scope");
    fs::create_dir(&root)?;
    let payload = [b'x'; 64];
    for directory in 0..128 {
        let path = root.join(format!("bank-{directory:03}"));
        fs::create_dir(&path)?;
        for file in 0..64 {
            fs::write(path.join(format!("file-{file:03}")), payload)?;
        }
    }
    let mut deep = root.join("deep");
    fs::create_dir(&deep)?;
    for level in 0..48 {
        deep = deep.join(format!("d{level}"));
        fs::create_dir(&deep)?;
        fs::write(deep.join("data"), payload)?;
    }
    let hard_links = root.join("hard-links");
    fs::create_dir(&hard_links)?;
    for link in 0..128 {
        fs::hard_link(
            root.join("bank-000/file-000"),
            hard_links.join(format!("link-{link}")),
        )?;
    }
    let empty = root.join("empty");
    fs::create_dir(&empty)?;
    for directory in 0..32 {
        fs::create_dir(empty.join(directory.to_string()))?;
    }
    let sparse = fs::File::create(root.join("sparse"))?;
    sparse.set_len(64 * 1024 * 1024)?;
    drop(sparse);
    fs::write(root.join("line\nescape\u{1b}"), b"1234")?;
    fs::write(parent.join("canary"), b"outside the selected scope")?;
    symlink(parent.join("canary"), root.join("outside-link"))?;

    let limits = ScanLimits::default();
    println!("fixture=m2-v1 unique_files=8242 file_entries=8370 logical_bytes=67636228 runs=5");
    for sample in 0..5 {
        let report = scan(
            std::slice::from_ref(&root),
            &limits,
            &Cancellation::default(),
            |_| {},
        )?;
        if report.status != ScanStatus::Complete
            || report.totals.unique_files != 8242
            || report.totals.regular_files != 8370
            || report.totals.logical_bytes_known != 67_636_228
        {
            return Err(format!(
                "fixture correctness failed: {:?}; {:?}",
                report.totals, report.issues
            )
            .into());
        }
        println!(
            "sample={sample} elapsed_ms={} first_result_ms={} peak_workers={} peak_queued_dirs={} peak_open_dirs={} peak_pending_events={} retained_path_bytes={}",
            report.metrics.elapsed_ms,
            report
                .metrics
                .first_result_ms
                .ok_or("missing first result timing")?,
            report.metrics.peak_workers,
            report.metrics.peak_queued_dirs,
            report.metrics.peak_open_dirs,
            report.metrics.peak_pending_events,
            report.metrics.retained_path_bytes,
        );
    }
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let mut requested = None;
    let report = scan(std::slice::from_ref(&root), &limits, &cancel, |_| {
        if requested.is_none() {
            requested = Some(Instant::now());
            signal.cancel();
        }
    })?;
    if report.status != ScanStatus::Cancelled {
        return Err("cancellation was not reported".into());
    }
    let latency = requested
        .ok_or("missing cancellation progress event")?
        .elapsed();
    println!(
        "cancel_latency_ms={} cancel_latency_us={} cancel_entries={}",
        latency.as_millis(),
        latency.as_micros(),
        report.entries.len()
    );
    if fs::read(parent.join("canary"))? != b"outside the selected scope" {
        return Err("fixture canary changed".into());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The native M2 fixture benchmark requires macOS.");
    std::process::exit(1);
}
