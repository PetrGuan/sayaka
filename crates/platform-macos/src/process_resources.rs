// SPDX-License-Identifier: MPL-2.0
//! Read-only process diagnostics; never used for authorization or scan budgets.

pub struct ProcessResources {
    pub uptime_ns: u64,
    pub cpu_ns: u64,
    pub rss_bytes: u64,
    pub footprint_bytes: u64,
}

pub fn snapshot() -> std::io::Result<ProcessResources> {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v0>::zeroed();
    // SAFETY: RUSAGE_INFO_V0 writes one initialized rusage_info_v0-sized buffer.
    // Darwin declares this output parameter as void ** but writes the structure
    // directly, not an allocated pointer. getpid has no pointer preconditions.
    let result = unsafe {
        libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V0,
            info.as_mut_ptr().cast::<libc::rusage_info_t>())
    };
    if result != 0 { return Err(std::io::Error::last_os_error()); }
    // SAFETY: The successful V0 query initialized every field we read.
    let info = unsafe { info.assume_init() };
    Ok(ProcessResources {
        uptime_ns: crate::diagnostic_monotonic_ns()?,
        cpu_ns: crate::diagnostic_ticks_to_ns(info.ri_user_time.checked_add(info.ri_system_time)
            .ok_or_else(|| std::io::Error::other("CPU ticks overflow"))?)?,
        rss_bytes: info.ri_resident_size,
        footprint_bytes: info.ri_phys_footprint,
    })
}

/// Current-thread CPU time, already in nanoseconds (unlike proc_pid_rusage ticks).
/// Debug diagnostics only; never a budget or authorization input.
#[cfg(debug_assertions)]
pub fn thread_cpu_ns() -> std::io::Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes this output on success; no ownership transfer.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful clock_gettime initialized both fields.
    let time = unsafe { time.assume_init() };
    let secs = u64::try_from(time.tv_sec).map_err(|_| std::io::Error::other("negative CPU time"))?;
    let nanos = u64::try_from(time.tv_nsec).ok().filter(|n| *n < 1_000_000_000)
        .ok_or_else(|| std::io::Error::other("invalid CPU nanoseconds"))?;
    secs.checked_mul(1_000_000_000).and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| std::io::Error::other("thread CPU time overflow"))
}
