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
