// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::io;
use std::mem::{offset_of, size_of};
use std::ptr;
use std::time::Instant;

mod gpu;
mod power;
pub use gpu::gpu;
pub use power::power;

const ROUTE_CAP: usize = 1024 * 1024;
const INTERFACE_CAP: usize = 128;
const PID_CAP: usize = 65_536;
const PROCESS_TOP_MAX_LIMIT: usize = 32;
// SDK sys/proc_info.h; libc exposes proc_listpids but not this selector.
const PROC_ALL_PIDS: u32 = 1;

#[link(name = "System")]
unsafe extern "C" {
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn unsupported(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, reason)
}

fn mach_result(code: libc::kern_return_t, source: &'static str) -> io::Result<()> {
    if code == libc::KERN_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other(format!("{source} failed (Mach {code})")))
    }
}

fn count_in_range(count: u32, minimum: u32, capacity: u32) -> io::Result<()> {
    if count < minimum || count > capacity {
        Err(invalid("native counter record has an invalid word count"))
    } else {
        Ok(())
    }
}

struct HostRight(Option<libc::mach_port_t>);

impl HostRight {
    fn new() -> io::Result<Self> {
        // SAFETY: No arguments; returns an owned send right in this task.
        #[allow(deprecated)]
        let port = unsafe { libc::mach_host_self() };
        if port == libc::MACH_PORT_NULL as u32 {
            Err(io::Error::other("mach_host_self returned no host right"))
        } else {
            Ok(Self(Some(port)))
        }
    }

    fn close(&mut self) -> io::Result<()> {
        if let Some(port) = self.0.take() {
            // SAFETY: Only this owned host right is released. mach_task_self()
            // is the borrowed current-task port, not a right to deallocate.
            #[allow(deprecated)]
            let code = unsafe { mach_port_deallocate(libc::mach_task_self(), port) };
            mach_result(code, "mach_port_deallocate")
        } else {
            Ok(())
        }
    }
}

impl Drop for HostRight {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("Sayaka status host-right cleanup failed: {error}");
        }
    }
}

fn with_host<T>(read: impl FnOnce(libc::mach_port_t) -> io::Result<T>) -> io::Result<T> {
    let mut host = HostRight::new()?;
    let result = read(host.0.expect("new host right"));
    match (result, host.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(read), Err(close)) => Err(io::Error::other(format!("{read}; {close}"))),
    }
}

/// Aggregate `HOST_CPU_LOAD_INFO` ticks, widened from native u32, not percentages.
/// XNU may return cached ticks: the published implementation shares a randomized
/// 2–10-query, one-second budget across third-party callers, per flavor. Success
/// does not guarantee progress since the previous call, even 250 ms later.
/// See `rate_limit_host_statistics` in
/// <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/host.c>.
pub fn cpu() -> io::Result<CpuCounters> {
    with_host(|host| {
        // SAFETY: This libc C record consists entirely of integer fields.
        let mut info: libc::host_cpu_load_info = unsafe { std::mem::zeroed() };
        let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
        // SAFETY: Aligned output has capacity for the advertised integer count.
        let code = unsafe {
            libc::host_statistics(
                host,
                libc::HOST_CPU_LOAD_INFO,
                (&mut info as *mut libc::host_cpu_load_info).cast(),
                &mut count,
            )
        };
        mach_result(code, "host_statistics(CPU_LOAD_INFO)")?;
        count_in_range(
            count,
            libc::HOST_CPU_LOAD_INFO_COUNT,
            libc::HOST_CPU_LOAD_INFO_COUNT,
        )?;
        Ok(CpuCounters {
            user: info.cpu_ticks[libc::CPU_STATE_USER as usize].into(),
            system: info.cpu_ticks[libc::CPU_STATE_SYSTEM as usize].into(),
            idle: info.cpu_ticks[libc::CPU_STATE_IDLE as usize].into(),
            nice: info.cpu_ticks[libc::CPU_STATE_NICE as usize].into(),
        })
    })
}

fn bytes(units: u64, unit_size: u64) -> io::Result<u64> {
    if unit_size == 0 {
        return Err(invalid("native byte unit is zero"));
    }
    units
        .checked_mul(unit_size)
        .ok_or_else(|| invalid("native byte count overflow"))
}

/// `hw.memsize` and `HOST_VM_INFO64` pages in bytes using native page size.
/// VM categories overlap (notably free/speculative); these are not additive.
pub fn memory() -> io::Result<MemoryCounters> {
    let mut physical = 0_u64;
    let mut len = size_of::<u64>();
    // SAFETY: Static NUL-terminated name, correctly sized writable output;
    // null newp makes this a read-only sysctl.
    if unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut physical as *mut u64).cast(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if len != size_of::<u64>() || physical == 0 {
        return Err(invalid("hw.memsize returned an invalid size"));
    }
    // SAFETY: Read-only query with a public sysconf selector.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size == -1 {
        return Err(io::Error::last_os_error());
    }
    let page_size = u64::try_from(page_size).map_err(|_| invalid("negative page size"))?;
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(invalid("invalid native page size"));
    }
    with_host(|host| {
        // SAFETY: The libc VM record contains only integer fields.
        let mut info: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
        // SDK mach/host_info.h: REV1 ends before swapped_count. Request that
        // stable prefix, not newer SDK-only fields unavailable on older macOS.
        let capacity = (offset_of!(libc::vm_statistics64, swapped_count)
            / size_of::<libc::integer_t>()) as u32;
        let mut count = capacity;
        // SAFETY: Output is aligned and larger than the requested REV1 prefix.
        let code = unsafe {
            libc::host_statistics64(
                host,
                libc::HOST_VM_INFO64,
                (&mut info as *mut libc::vm_statistics64).cast(),
                &mut count,
            )
        };
        mach_result(code, "host_statistics64(VM_INFO64)")?;
        count_in_range(count, capacity, capacity)?;
        Ok(MemoryCounters {
            physical_bytes: physical,
            page_size,
            active_bytes: bytes(info.active_count.into(), page_size)?,
            inactive_bytes: bytes(info.inactive_count.into(), page_size)?,
            wired_bytes: bytes(info.wire_count.into(), page_size)?,
            free_bytes: bytes(info.free_count.into(), page_size)?,
            compressor_bytes: bytes(info.compressor_page_count.into(), page_size)?,
            speculative_bytes: bytes(info.speculative_count.into(), page_size)?,
            purgeable_bytes: bytes(info.purgeable_count.into(), page_size)?,
        })
    })
}

fn bounded_vec<T: Clone>(len: usize, cap: usize, initial: T) -> io::Result<Vec<T>> {
    if len == 0 || len > cap {
        return Err(invalid("native buffer length exceeds collection bounds"));
    }
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(len).map_err(io::Error::other)?;
    buffer.resize(len, initial);
    Ok(buffer)
}

fn route_read(buffer: Option<&mut [u8]>) -> io::Result<usize> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    let (out, mut len) = match buffer {
        Some(bytes) => (bytes.as_mut_ptr().cast(), bytes.len()),
        None => (ptr::null_mut(), 0),
    };
    // SAFETY: MIB is six native integers; the optional output points to len
    // writable bytes. A null newp prohibits setting any kernel value.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            out,
            &mut len,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(len)
    }
}

/// `NET_RT_IFLIST2` / `if_data64` cumulative bytes per non-loopback interface.
/// Includes native up/down flags; never sums overlapping physical/virtual links.
pub fn network() -> io::Result<Vec<NetworkCounters>> {
    let mut needed = route_read(None)?;
    for attempt in 0..2 {
        let mut buffer = bounded_vec(needed, ROUTE_CAP, 0_u8)?;
        match route_read(Some(&mut buffer)) {
            Ok(written) => {
                if written > buffer.len() {
                    return Err(invalid("routing sysctl returned an oversized buffer"));
                }
                return parse_routes(&buffer[..written], interface_name);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOMEM) && attempt == 0 => {
                needed = route_read(None)?;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("two bounded routing attempts")
}

fn interface_name(index: u32) -> io::Result<String> {
    let mut name = [0_i8; libc::IF_NAMESIZE];
    // SAFETY: if_indextoname writes at most IF_NAMESIZE bytes to this array.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("interface name is not terminated"))?;
    if end == 0
        || name[..end]
            .iter()
            .any(|byte| !matches!(*byte as u8, b'!'..=b'~'))
    {
        return Err(invalid("interface name is empty or not printable ASCII"));
    }
    let mut text = String::new();
    text.try_reserve_exact(end).map_err(io::Error::other)?;
    text.extend(name[..end].iter().map(|byte| char::from(*byte as u8)));
    Ok(text)
}

fn parse_routes(
    mut buffer: &[u8],
    mut name: impl FnMut(u32) -> io::Result<String>,
) -> io::Result<Vec<NetworkCounters>> {
    if buffer.len() > ROUTE_CAP {
        return Err(invalid("routing buffer exceeds collection bounds"));
    }
    let mut interfaces = Vec::new();
    interfaces
        .try_reserve_exact(INTERFACE_CAP)
        .map_err(io::Error::other)?;
    let mut seen = [0_u32; INTERFACE_CAP];
    let mut count = 0;
    while !buffer.is_empty() {
        if buffer.len() < 4 {
            return Err(invalid("truncated routing message prefix"));
        }
        let len = u16::from_ne_bytes([buffer[0], buffer[1]]) as usize;
        if len < 4 || len > buffer.len() || buffer[2] != libc::RTM_VERSION as u8 {
            return Err(invalid("invalid routing message length or version"));
        }
        let record = &buffer[..len];
        let required = match i32::from(record[3]) {
            libc::RTM_IFINFO2 => size_of::<libc::if_msghdr2>(),
            libc::RTM_NEWADDR => size_of::<libc::ifa_msghdr>(),
            libc::RTM_NEWMADDR2 => size_of::<libc::ifma_msghdr2>(),
            _ => return Err(invalid("unexpected NET_RT_IFLIST2 message type")),
        };
        if len < required {
            return Err(invalid("truncated routing message header"));
        }
        if i32::from(record[3]) == libc::RTM_IFINFO2 {
            // SAFETY: The record's length, version and type have been checked.
            // All fields are integer types; read_unaligned handles route packing.
            let info = unsafe { ptr::read_unaligned(record.as_ptr().cast::<libc::if_msghdr2>()) };
            let index = u32::from(info.ifm_index);
            if index == 0 || seen[..count].contains(&index) {
                return Err(invalid("zero or duplicate routing interface index"));
            }
            if count == INTERFACE_CAP {
                return Err(invalid("interface count exceeds collection bounds"));
            }
            seen[count] = index;
            count += 1;
            if info.ifm_flags & libc::IFF_LOOPBACK == 0 {
                interfaces.push(NetworkCounters {
                    index,
                    name: name(index)?,
                    up: info.ifm_flags & libc::IFF_UP != 0,
                    received_bytes: info.ifm_data.ifi_ibytes,
                    transmitted_bytes: info.ifm_data.ifi_obytes,
                });
            }
        }
        // Address payloads are deliberately neither decoded nor exposed.
        buffer = &buffer[len..];
    }
    interfaces.sort_unstable_by_key(|interface| interface.index);
    Ok(interfaces)
}

fn disk_units(total: u64, free: u64, available: u64, block_size: u64) -> io::Result<DiskCounters> {
    if total == 0 || free > total || available > free {
        return Err(invalid("inconsistent filesystem capacity counters"));
    }
    Ok(DiskCounters {
        total_bytes: bytes(total, block_size)?,
        free_bytes: bytes(free, block_size)?,
        available_bytes: bytes(available, block_size)?,
    })
}

/// Local startup filesystem `statfs("/")` block capacity, not purgeable estimates.
pub fn disk() -> io::Result<DiskCounters> {
    // SAFETY: libc statfs is a C record with integer and character array fields.
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: Static root path and writable correctly sized native output.
    if unsafe { libc::statfs(c"/".as_ptr(), &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if info.f_flags & libc::MNT_LOCAL as u32 == 0 {
        return Err(unsupported("startup filesystem is not local"));
    }
    disk_units(
        info.f_blocks,
        info.f_bfree,
        info.f_bavail,
        info.f_bsize.into(),
    )
}

fn timeval_ns(seconds: i64, micros: i64) -> io::Result<u64> {
    if seconds < 0 || !(0..1_000_000).contains(&micros) {
        return Err(invalid("invalid getrusage CPU time"));
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(micros as u64 * 1000))
        .ok_or_else(|| invalid("getrusage CPU time overflow"))
}

/// Self cumulative user+system CPU nanoseconds (`getrusage`) and current RSS
/// bytes (`MACH_TASK_BASIC_INFO.resident_size`, never maximum RSS).
pub fn sampler() -> io::Result<SamplerCounters> {
    // SAFETY: rusage and Mach task info are integer-only native records.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: Read-only current-process selector and writable native output.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let user = timeval_ns(usage.ru_utime.tv_sec, usage.ru_utime.tv_usec.into())?;
    let system = timeval_ns(usage.ru_stime.tv_sec, usage.ru_stime.tv_usec.into())?;
    let cpu_time_ns = user
        .checked_add(system)
        .ok_or_else(|| invalid("self CPU time overflow"))?;
    // SAFETY: All fields have valid zero integer representations.
    let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: Borrowed current task port, native aligned output, and its word
    // count. No task port is acquired, so mach_task_self is not deallocated.
    #[allow(deprecated)]
    let code = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            (&mut info as *mut libc::mach_task_basic_info).cast(),
            &mut count,
        )
    };
    mach_result(code, "task_info(MACH_TASK_BASIC_INFO)")?;
    count_in_range(
        count,
        libc::MACH_TASK_BASIC_INFO_COUNT,
        libc::MACH_TASK_BASIC_INFO_COUNT,
    )?;
    Ok(SamplerCounters {
        cpu_time_ns,
        resident_bytes: info.resident_size,
    })
}

fn pid_count(pids: &[libc::pid_t], written: usize) -> io::Result<u64> {
    let capacity = std::mem::size_of_val(pids);
    if written == 0 || written > capacity || !written.is_multiple_of(size_of::<libc::pid_t>()) {
        return Err(invalid("proc_listpids returned an invalid byte count"));
    }
    if written == capacity {
        return Err(invalid(
            "visible PID buffer is full; snapshot may be truncated",
        ));
    }
    let pids = &pids[..written / size_of::<libc::pid_t>()];
    if pids.iter().any(|pid| *pid < 0) {
        return Err(invalid("proc_listpids returned a negative PID"));
    }
    // PID 0 is a valid kernel process when returned by PROC_ALL_PIDS.
    Ok(pids.len() as u64)
}

fn pid_list(pids: &[libc::pid_t], written: usize) -> io::Result<(&[libc::pid_t], bool)> {
    let capacity = std::mem::size_of_val(pids);
    if written == 0 || written > capacity || !written.is_multiple_of(size_of::<libc::pid_t>()) {
        return Err(invalid("proc_listpids returned an invalid byte count"));
    }
    let truncated = written == capacity;
    let pids = &pids[..written / size_of::<libc::pid_t>()];
    if pids.iter().any(|pid| *pid < 0) {
        return Err(invalid("proc_listpids returned a negative PID"));
    }
    Ok((pids, truncated))
}

fn c_name(bytes: &[libc::c_char]) -> Option<String> {
    let raw = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if raw == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw);
    for byte in &bytes[..raw] {
        out.push(*byte as u8);
    }
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn mach_ticks_to_ns(ticks: u64, numer: u32, denom: u32) -> io::Result<u64> {
    if denom == 0 {
        return Err(invalid("mach timebase denominator is zero"));
    }
    let scaled = u128::from(ticks)
        .checked_mul(u128::from(numer))
        .ok_or_else(|| invalid("mach counter conversion overflow"))?;
    let ns = scaled / u128::from(denom);
    u64::try_from(ns).map_err(|_| invalid("mach counter conversion exceeds u64"))
}

fn process_name(info: &libc::proc_bsdinfo) -> Option<String> {
    c_name(&info.pbi_name).or_else(|| c_name(&info.pbi_comm))
}

/// Number of visible PIDs from `proc_listpids(PROC_ALL_PIDS)`, capped at 65,536.
/// No process names, arguments or environment are requested.
pub fn processes() -> io::Result<u64> {
    let mut pids = bounded_vec(PID_CAP, PID_CAP, 0 as libc::pid_t)?;
    let capacity = std::mem::size_of_val(pids.as_slice());
    // SAFETY: The integer-aligned output has capacity bytes and the selector
    // returns PID integers. Unlike proc_listallpids, this API returns BYTES.
    let written =
        unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), capacity as i32) };
    // Apple's libproc wrapper converts the underlying -1 error to 0, while
    // preserving errno. A self-visible process list cannot be empty.
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    pid_count(&pids, written as usize)
}

/// Bounded per-process PID/name/RSS/CPU counters from `PROC_PIDTASKALLINFO`.
/// No command line, executable path, cwd, environment, UID names, or arguments.
pub fn processes_top(
    limit: usize,
    _sort: ProcessTopSort,
    probe_cap: usize,
    collection_budget_ms: u64,
) -> io::Result<ProcessTopSnapshot> {
    if !(1..=PROCESS_TOP_MAX_LIMIT).contains(&limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "top limit must be in 1..=32",
        ));
    }
    if probe_cap == 0 || probe_cap > PID_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "top probe cap must be in 1..=65536",
        ));
    }
    if collection_budget_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "top collection budget must be positive milliseconds",
        ));
    }
    // SAFETY: Integer-only C API writes numer/denom to this initialized record.
    #[allow(deprecated)]
    let mut timebase: libc::mach_timebase_info_data_t = unsafe { std::mem::zeroed() };
    // SAFETY: Public API with writable pointer to a valid record.
    #[allow(deprecated)]
    mach_result(
        unsafe { libc::mach_timebase_info(&mut timebase) },
        "mach_timebase_info",
    )?;
    #[allow(deprecated)]
    if timebase.numer == 0 || timebase.denom == 0 {
        return Err(invalid("invalid mach timebase ratio"));
    }
    let mut pids = bounded_vec(PID_CAP, PID_CAP, 0 as libc::pid_t)?;
    let capacity = std::mem::size_of_val(pids.as_slice());
    // SAFETY: The output buffer has byte capacity and receives PID values.
    let written =
        unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), capacity as i32) };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    let (all, mut truncated) = pid_list(&pids, written as usize)?;
    let visible = all.len() as u64;
    let started = Instant::now();
    let budget = std::time::Duration::from_millis(collection_budget_ms);
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    let mut collection = ProcessTopCollection {
        visible_processes: visible,
        candidate_cap: PID_CAP,
        probe_cap,
        probed: 0,
        denied: 0,
        disappeared: 0,
        invalid: 0,
        truncated,
        partial: false,
    };
    for pid in all {
        if collection.probed >= probe_cap {
            collection.partial = true;
            truncated = true;
            break;
        }
        if started.elapsed() > budget {
            collection.partial = true;
            break;
        }
        if *pid < 0 {
            collection.invalid += 1;
            continue;
        }
        if !seen.insert(*pid) {
            collection.invalid += 1;
            continue;
        }
        let mut info: libc::proc_taskallinfo = unsafe { std::mem::zeroed() };
        // SAFETY: Pointer and length match the concrete proc_taskallinfo record.
        let size = unsafe {
            libc::proc_pidinfo(
                *pid,
                libc::PROC_PIDTASKALLINFO,
                0,
                (&mut info as *mut libc::proc_taskallinfo).cast(),
                size_of::<libc::proc_taskallinfo>() as i32,
            )
        };
        collection.probed += 1;
        if size <= 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => collection.disappeared += 1,
                Some(code) if code == libc::EPERM || code == libc::EACCES => collection.denied += 1,
                _ => collection.invalid += 1,
            }
            continue;
        }
        if usize::try_from(size).ok() != Some(size_of::<libc::proc_taskallinfo>()) {
            collection.invalid += 1;
            continue;
        }
        let bsd = &info.pbsd;
        if bsd.pbi_pid != *pid as u32 || bsd.pbi_start_tvusec >= 1_000_000 {
            collection.invalid += 1;
            continue;
        }
        let Some(name) = process_name(bsd) else {
            collection.invalid += 1;
            continue;
        };
        if name.is_empty() {
            collection.invalid += 1;
            continue;
        }
        let total_ticks = info
            .ptinfo
            .pti_total_user
            .checked_add(info.ptinfo.pti_total_system)
            .ok_or_else(|| invalid("process CPU counter overflow"))?;
        #[allow(deprecated)]
        let total_cpu_time_ns = mach_ticks_to_ns(total_ticks, timebase.numer, timebase.denom)?;
        rows.push(ProcessTopCounters {
            identity: ProcessIdentity {
                pid: bsd.pbi_pid,
                start_unix_sec: bsd.pbi_start_tvsec,
                start_unix_usec: bsd.pbi_start_tvusec,
            },
            name,
            resident_bytes: info.ptinfo.pti_resident_size,
            total_cpu_time_ns,
        });
    }
    if truncated || collection.probed < all.len() {
        collection.truncated = true;
        collection.partial = true;
    }
    if rows.is_empty() && collection.probed > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "top process details unavailable for all probed candidates",
        ));
    }
    Ok(ProcessTopSnapshot { rows, collection })
}

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

fn thermal_value(value: isize) -> io::Result<ThermalState> {
    match value {
        0 => Ok(ThermalState::Nominal),
        1 => Ok(ThermalState::Fair),
        2 => Ok(ThermalState::Serious),
        3 => Ok(ThermalState::Critical),
        _ => Err(unsupported(
            "NSProcessInfo returned an unknown thermal state",
        )),
    }
}

/// Public `NSProcessInfo.thermalState` enum, not a temperature. Apple reports
/// Nominal also on hardware where thermal state is unknown or unsupported.
pub fn thermal() -> io::Result<ThermalState> {
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    objc2::rc::autoreleasepool(|_| {
        let class = AnyClass::get(c"NSProcessInfo")
            .ok_or_else(|| unsupported("Foundation NSProcessInfo class is unavailable"))?;
        // SAFETY: Public class method returns a borrowed NSProcessInfo singleton
        // valid throughout this pool. Only primitive values escape the pool.
        let info: *mut AnyObject = unsafe { objc2::msg_send![class, processInfo] };
        if info.is_null() {
            return Err(io::Error::other("NSProcessInfo.processInfo returned nil"));
        }
        // SAFETY: Live NSObject receiver, public selector, correctly typed BOOL.
        let supported: Bool =
            unsafe { objc2::msg_send![info, respondsToSelector: objc2::sel!(thermalState)] };
        if !supported.as_bool() {
            return Err(unsupported(
                "NSProcessInfo.thermalState selector is unavailable",
            ));
        }
        // SAFETY: Availability checked above; NS_ENUM(NSInteger) uses isize.
        thermal_value(unsafe { objc2::msg_send![info, thermalState] })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static NATIVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn interface_record(index: u16, flags: i32) -> Vec<u8> {
        // Byte construction avoids ever exposing uninitialized C struct padding.
        let mut record = vec![0_u8; size_of::<libc::if_msghdr2>()];
        let len = record.len() as u16;
        record[..2].copy_from_slice(&len.to_ne_bytes());
        record[2] = libc::RTM_VERSION as u8;
        record[3] = libc::RTM_IFINFO2 as u8;
        let offset = offset_of!(libc::if_msghdr2, ifm_flags);
        record[offset..offset + 4].copy_from_slice(&flags.to_ne_bytes());
        let offset = offset_of!(libc::if_msghdr2, ifm_index);
        record[offset..offset + 2].copy_from_slice(&index.to_ne_bytes());
        let base = offset_of!(libc::if_msghdr2, ifm_data);
        let offset = base + offset_of!(libc::if_data64, ifi_ibytes);
        record[offset..offset + 8].copy_from_slice(&(u64::from(u32::MAX) + 10).to_ne_bytes());
        let offset = base + offset_of!(libc::if_data64, ifi_obytes);
        record[offset..offset + 8].copy_from_slice(&999_u64.to_ne_bytes());
        record
    }

    fn name(index: u32) -> io::Result<String> {
        Ok(format!("test{index}"))
    }

    #[test]
    fn libc_layouts_match_verified_apple_sdk_prefixes() {
        // Also checked independently against SDK C headers using clang.
        assert_eq!(size_of::<libc::if_msghdr2>(), 160);
        assert_eq!(offset_of!(libc::if_msghdr2, ifm_data), 32);
        assert_eq!(offset_of!(libc::if_data64, ifi_ibytes), 64);
        assert_eq!(size_of::<libc::mach_task_basic_info>(), 48);
        assert_eq!(libc::MACH_TASK_BASIC_INFO_COUNT, 12);
        assert_eq!(libc::HOST_CPU_LOAD_INFO_COUNT, 4);
        assert_eq!(offset_of!(libc::vm_statistics64, swapped_count), 152);
        assert_eq!(size_of::<libc::proc_bsdinfo>(), 136);
        assert!(size_of::<libc::proc_taskinfo>() >= 96);
        assert_eq!(
            size_of::<libc::proc_taskallinfo>(),
            size_of::<libc::proc_bsdinfo>() + size_of::<libc::proc_taskinfo>()
        );
        assert_eq!(offset_of!(libc::proc_taskallinfo, pbsd), 0);
        assert_eq!(offset_of!(libc::proc_taskallinfo, ptinfo), 136);
        assert!(offset_of!(libc::proc_bsdinfo, pbi_name) >= 60);
        assert_eq!(offset_of!(libc::proc_bsdinfo, pbi_start_tvsec), 120);
        assert_eq!(offset_of!(libc::proc_taskinfo, pti_resident_size), 8);
        assert_eq!(offset_of!(libc::proc_taskinfo, pti_total_user), 16);
        assert_eq!(offset_of!(libc::proc_taskinfo, pti_total_system), 24);
    }

    #[test]
    #[ignore = "bounded read-only CPU counter trace; run explicitly, optionally in concurrent test processes"]
    fn native_cpu_counter_trace() {
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let mut previous: Option<[u64; 4]> = None;
        let mut repeats = 0;
        let mut decreases = 0;
        for sample in 0..16 {
            if sample != 0 {
                std::thread::sleep(Duration::from_millis(250));
            }
            let read_start = Instant::now();
            let counters = cpu().unwrap();
            let ticks = [counters.user, counters.system, counters.idle, counters.nice];
            let delta = previous.map(|old| {
                std::array::from_fn::<_, 4, _>(|i| i128::from(ticks[i]) - i128::from(old[i]))
            });
            if let Some(old) = previous {
                repeats += usize::from(ticks == old);
                decreases += usize::from(ticks.iter().zip(old).any(|(now, before)| *now < before));
            }
            eprintln!(
                "CPU_TRACE sample={sample} elapsed_ms={} read_us={} ticks={ticks:?} delta={delta:?}",
                start.elapsed().as_millis(),
                read_start.elapsed().as_micros()
            );
            previous = Some(ticks);
        }
        eprintln!("CPU_TRACE summary samples=16 repeats={repeats} decreases={decreases}");
        // Only source success/layout is asserted. Cached repeats are valid raw
        // evidence, not zero utilization, and callers must handle discontinuity.
    }

    #[test]
    fn route_counters_preserve_width_flags_and_interface_identity() {
        let mut data = interface_record(1, libc::IFF_LOOPBACK | libc::IFF_UP);
        data.extend(interface_record(3, 0));
        data.extend(interface_record(2, libc::IFF_UP));
        let values = parse_routes(&data, name).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].index, 2);
        assert_eq!(values[0].name, "test2");
        assert!(values[0].up);
        assert!(!values[1].up);
        assert_eq!(values[0].received_bytes, u64::from(u32::MAX) + 10);
        assert_eq!(values[0].transmitted_bytes, 999);
    }

    #[test]
    fn route_parser_rejects_every_truncated_prefix_and_invalid_header() {
        let record = interface_record(1, libc::IFF_UP);
        for len in 1..record.len() {
            assert!(parse_routes(&record[..len], name).is_err(), "length {len}");
        }
        for short_len in [0_u16, 1, 3, 4, 159, u16::MAX] {
            let mut malformed = record.clone();
            malformed[..2].copy_from_slice(&short_len.to_ne_bytes());
            assert!(parse_routes(&malformed, name).is_err());
        }
        for (index, value) in [(2, 0), (3, 255)] {
            let mut malformed = record.clone();
            malformed[index] = value;
            assert!(parse_routes(&malformed, name).is_err());
        }
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(parse_routes(&trailing, name).is_err());
    }

    #[test]
    fn route_parser_bounds_count_bytes_and_rejects_ambiguous_identity() {
        assert!(parse_routes(&interface_record(0, 0), name).is_err());
        let mut duplicate = interface_record(1, 0);
        duplicate.extend(interface_record(1, 0));
        assert!(parse_routes(&duplicate, name).is_err());
        let mut data = Vec::new();
        for index in 1..=INTERFACE_CAP as u16 {
            data.extend(interface_record(index, 0));
        }
        assert_eq!(parse_routes(&data, name).unwrap().len(), INTERFACE_CAP);
        data.extend(interface_record(
            INTERFACE_CAP as u16 + 1,
            libc::IFF_LOOPBACK,
        ));
        assert!(parse_routes(&data, name).is_err());
        assert!(parse_routes(&vec![0; ROUTE_CAP + 1], name).is_err());
        let error = parse_routes(&interface_record(1, 0), |_| {
            Err(io::Error::from_raw_os_error(libc::ENXIO))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENXIO));
    }

    #[test]
    fn unused_route_address_records_are_length_checked_not_exposed() {
        for (kind, len) in [
            (libc::RTM_NEWADDR, size_of::<libc::ifa_msghdr>()),
            (libc::RTM_NEWMADDR2, size_of::<libc::ifma_msghdr2>()),
        ] {
            let mut record = vec![0_u8; len];
            record[..2].copy_from_slice(&(len as u16).to_ne_bytes());
            record[2] = libc::RTM_VERSION as u8;
            record[3] = kind as u8;
            assert!(parse_routes(&record, name).unwrap().is_empty());
            record.pop();
            record[..2].copy_from_slice(&((len - 1) as u16).to_ne_bytes());
            assert!(parse_routes(&record, name).is_err());
        }
    }

    #[test]
    fn native_units_lengths_and_error_codes_are_checked() {
        assert_eq!(bytes(3, 16_384).unwrap(), 49_152);
        assert_eq!(bytes(0, 4096).unwrap(), 0);
        assert!(bytes(1, 0).is_err());
        assert!(bytes(u64::MAX, 2).is_err());
        assert_eq!(timeval_ns(2, 123_456).unwrap(), 2_123_456_000);
        for (sec, micros) in [(-1, 0), (0, -1), (0, 1_000_000), (i64::MAX, 0)] {
            assert!(timeval_ns(sec, micros).is_err());
        }
        assert!(count_in_range(3, 4, 4).is_err());
        assert!(count_in_range(5, 4, 4).is_err());
        assert!(count_in_range(4, 4, 4).is_ok());
        assert!(mach_result(libc::KERN_SUCCESS, "test").is_ok());
        assert!(
            mach_result(libc::KERN_FAILURE, "test")
                .unwrap_err()
                .to_string()
                .contains("Mach")
        );
        assert!(bounded_vec(0, 8, 0_u8).is_err());
        assert!(bounded_vec(9, 8, 0_u8).is_err());
        assert_eq!(bounded_vec(8, 8, 0_u8).unwrap().len(), 8);
    }

    #[test]
    fn disk_units_preserve_available_free_and_total_meanings() {
        assert_eq!(
            disk_units(100, 20, 10, 4096).unwrap(),
            DiskCounters {
                total_bytes: 409_600,
                free_bytes: 81_920,
                available_bytes: 40_960,
            }
        );
        assert!(disk_units(100, 0, 0, 4096).is_ok());
        for (total, free, available, size) in [
            (0, 0, 0, 4096),
            (100, 101, 10, 4096),
            (100, 20, 21, 4096),
            (100, 20, 10, 0),
            (u64::MAX, 1, 1, 2),
        ] {
            assert!(disk_units(total, free, available, size).is_err());
        }
    }

    #[test]
    fn process_result_is_bytes_not_pids_and_never_accepts_truncation() {
        assert_eq!(pid_count(&[0, 1, 42, 0], 12).unwrap(), 3);
        for count in [0, 1, 2, 3, 16, 20] {
            assert!(pid_count(&[0, 1, 42, 0], count).is_err());
        }
        assert!(pid_count(&[-1, 0], 4).is_err());
    }

    #[test]
    fn process_top_helpers_enforce_conversion_name_and_budget_bounds() {
        assert_eq!(mach_ticks_to_ns(10, 3, 2).unwrap(), 15);
        assert!(mach_ticks_to_ns(1, 1, 0).is_err());
        assert!(mach_ticks_to_ns(u64::MAX, u32::MAX, 1).is_err());
        assert_eq!(c_name(&[b'a' as i8, b'b' as i8, 0]), Some("ab".into()));
        assert_eq!(c_name(&[0]), None);
        let list = pid_list(&[0, 1, 2, 3], 16).unwrap();
        assert_eq!(list.0.len(), 4);
        assert!(list.1);
    }

    #[test]
    fn thermal_maps_only_public_enum_values() {
        for (raw, expected) in [
            (0, ThermalState::Nominal),
            (1, ThermalState::Fair),
            (2, ThermalState::Serious),
            (3, ThermalState::Critical),
        ] {
            assert_eq!(thermal_value(raw).unwrap(), expected);
        }
        assert_eq!(
            thermal_value(4).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            thermal_value(-1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn native_read_only_smoke() {
        let _guard = NATIVE_TEST_LOCK.lock().unwrap();
        let ticks = cpu().unwrap();
        assert!(ticks.user + ticks.system + ticks.idle + ticks.nice > 0);
        let vm = memory().unwrap();
        assert!(vm.physical_bytes > 0 && vm.page_size.is_power_of_two());
        assert!(vm.active_bytes.is_multiple_of(vm.page_size));
        let links = network().unwrap();
        assert!(links.len() <= INTERFACE_CAP);
        let volume = disk().unwrap();
        assert!(volume.total_bytes >= volume.free_bytes);
        assert!(volume.free_bytes >= volume.available_bytes);
        let before = sampler().unwrap();
        assert!(before.resident_bytes > 0);
        assert!(processes().unwrap() > 0);
        for _ in 0..8 {
            match power() {
                Ok(value) => {
                    assert_eq!(value.battery_percent.is_some(), value.charging.is_some());
                    if let Some(percent) = value.battery_percent {
                        assert!((0.0..=100.0).contains(&percent));
                    } else {
                        assert!(value.on_ac);
                    }
                }
                Err(error) => {
                    eprintln!("optional native power unavailable: {error}");
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
                }
            }
        }
        match thermal() {
            Ok(_) => {}
            Err(error) => {
                eprintln!("optional native thermal unavailable: {error}");
                assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            }
        }
        assert!(sampler().unwrap().cpu_time_ns >= before.cpu_time_ns);
    }

    #[test]
    fn native_process_top_smoke_and_bounds() {
        let _guard = NATIVE_TEST_LOCK.lock().unwrap();
        let top = processes_top(10, ProcessTopSort::Cpu, 256, 150).unwrap();
        assert!(top.collection.probed > 0);
        assert!(top.collection.probe_cap <= 256);
        assert!(top.rows.len() <= top.collection.probed);
        for row in top.rows {
            assert!(row.identity.start_unix_usec < 1_000_000);
            assert!(!row.name.is_empty());
            assert!(row.resident_bytes > 0);
        }
    }

    #[link(name = "System")]
    unsafe extern "C" {
        fn mach_port_get_refs(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
            right: u32,
            refs: *mut u32,
        ) -> libc::kern_return_t;
    }

    #[test]
    fn host_right_released_on_success_error_and_explicit_close() {
        let _guard = NATIVE_TEST_LOCK.lock().unwrap();
        let mut host = HostRight::new().unwrap();
        let port = host.0.unwrap();
        let refs = || {
            let mut count = 0;
            // SAFETY: Borrowed task port and live owned host send right; SDK
            // MACH_PORT_RIGHT_SEND = 0, output is mach_port_urefs_t (u32).
            #[allow(deprecated)]
            let code = unsafe { mach_port_get_refs(libc::mach_task_self(), port, 0, &mut count) };
            mach_result(code, "mach_port_get_refs").unwrap();
            count
        };
        let before = refs();
        for _ in 0..8 {
            with_host(|_| Ok(())).unwrap();
            assert!(with_host::<()>(|_| Err(invalid("injected read failure"))).is_err());
        }
        assert_eq!(refs(), before);
        host.close().unwrap();
        assert!(host.0.is_none());
        host.close().unwrap();
        // A borrowed task port was not deallocated by any of the host cleanup.
        assert!(sampler().unwrap().resident_bytes > 0);
    }
}
