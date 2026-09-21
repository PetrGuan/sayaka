// SPDX-License-Identifier: MPL-2.0

use super::{invalid, unsupported};
use std::ffi::{c_char, c_long, c_ulong, c_void};
use std::io;
use std::ptr::{self, NonNull};

// GPU utilization comes from the public IOKit registry: IOServiceMatching
// matches subclasses, so "IOAccelerator" covers Apple Silicon AGX* classes
// and Intel integrated/discrete accelerators. The PerformanceStatistics
// property is a per-service observation, not a cumulative or inferred value.

#[repr(C)]
struct CfString {
    _private: [u8; 0],
}
#[repr(C)]
struct CfNumber {
    _private: [u8; 0],
}
#[repr(C)]
struct CfDictionary {
    _private: [u8; 0],
}
#[repr(C)]
struct CfAllocator {
    _private: [u8; 0],
}

// mach_port_t / io_object_t / io_iterator_t are 32-bit kernel port names.
type IoObject = u32;
const KERN_SUCCESS: i32 = 0;
// CFNumber.h: kCFNumberDoubleType converts any numeric storage on read.
const K_CF_NUMBER_DOUBLE_TYPE: c_long = 13;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
    fn CFGetTypeID(value: *const c_void) -> c_ulong;
    fn CFDictionaryGetTypeID() -> c_ulong;
    fn CFDictionaryGetValue(dictionary: *const CfDictionary, key: *const c_void) -> *const c_void;
    fn CFNumberGetTypeID() -> c_ulong;
    fn CFNumberGetValue(number: *const CfNumber, kind: c_long, out: *mut c_void) -> u8;
    fn CFStringCreateWithCString(
        allocator: *const CfAllocator,
        string: *const c_char,
        encoding: u32,
    ) -> *const CfString;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> *const c_void;
    fn IOServiceGetMatchingServices(
        main_port: IoObject,
        matching: *const c_void,
        iterator: *mut IoObject,
    ) -> i32;
    fn IOIteratorNext(iterator: IoObject) -> IoObject;
    fn IORegistryEntryCreateCFProperty(
        entry: IoObject,
        key: *const CfString,
        allocator: *const CfAllocator,
        options: u32,
    ) -> *const c_void;
    fn IOObjectRelease(object: IoObject) -> i32;
}

struct OwnedObject(NonNull<c_void>);

impl OwnedObject {
    // SAFETY: Callers must supply only a Copy/Create result (+1) CF object.
    unsafe fn from_copy(value: *const c_void, source: &'static str) -> io::Result<Self> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or_else(|| io::Error::other(format!("{source} returned null")))
    }
}

impl Drop for OwnedObject {
    fn drop(&mut self) {
        // SAFETY: This non-Clone owner contains precisely one +1 CF reference.
        unsafe { CFRelease(self.0.as_ptr()) };
    }
}

struct OwnedEntry(IoObject);

impl Drop for OwnedEntry {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: The entry name came from IOIteratorNext and is released once.
            unsafe { IOObjectRelease(self.0) };
        }
    }
}

fn string(value: &std::ffi::CStr) -> io::Result<OwnedObject> {
    // SAFETY: Input is a live NUL-terminated C string. UTF-8 = 0x08000100
    // (CFString.h); null allocator selects default. Create returns +1.
    unsafe {
        OwnedObject::from_copy(
            CFStringCreateWithCString(ptr::null(), value.as_ptr(), 0x0800_0100).cast(),
            "CFStringCreateWithCString",
        )
    }
}

/// Current GPU device utilization percent for the first accelerator service
/// that publishes it, or an explicit unsupported/unavailable error.
pub fn gpu() -> io::Result<f64> {
    let class = c"IOAccelerator";
    // SAFETY: class is a live NUL-terminated C string. IOServiceMatching
    // returns a +1 matching dictionary that GetMatchingServices always
    // consumes, including on failure, so it is not released here.
    let matching = unsafe { IOServiceMatching(class.as_ptr()) };
    if matching.is_null() {
        return Err(io::Error::other("IOServiceMatching returned null"));
    }
    let mut iterator: IoObject = 0;
    // SAFETY: matching is a live +1 dictionary consumed by this call;
    // iterator receives a kernel port name on success.
    let result = unsafe { IOServiceGetMatchingServices(0, matching, &mut iterator) };
    if result != KERN_SUCCESS {
        return Err(io::Error::other(format!(
            "IOServiceGetMatchingServices failed with kernel return {result}"
        )));
    }
    let _iterator = OwnedEntry(iterator);
    let statistics_key = string(c"PerformanceStatistics")?;
    let utilization_key = string(c"Device Utilization %")?;
    loop {
        // SAFETY: iterator is a live port owned above; the returned entry is
        // a +1 kernel object name owned by OwnedEntry.
        let entry = unsafe { IOIteratorNext(iterator) };
        if entry == 0 {
            return Err(unsupported(
                "no IOAccelerator service publishes Device Utilization %",
            ));
        }
        let _entry = OwnedEntry(entry);
        // SAFETY: entry is live; key is a live CFString. Create returns +1.
        let statistics = unsafe {
            IORegistryEntryCreateCFProperty(entry, statistics_key.0.as_ptr().cast(), ptr::null(), 0)
        };
        if statistics.is_null() {
            continue;
        }
        // SAFETY: statistics is a +1 CF object from the Create call above.
        let statistics =
            unsafe { OwnedObject::from_copy(statistics, "IORegistryEntryCreateCFProperty")? };
        // SAFETY: statistics is live for this block.
        if unsafe { CFGetTypeID(statistics.0.as_ptr()) } != unsafe { CFDictionaryGetTypeID() } {
            return Err(invalid("PerformanceStatistics has an unexpected CF type"));
        }
        // SAFETY: live dictionary and live key; the returned value is
        // borrowed and remains valid while statistics is alive.
        let value = unsafe {
            CFDictionaryGetValue(statistics.0.as_ptr().cast(), utilization_key.0.as_ptr())
        };
        if value.is_null() {
            continue;
        }
        // SAFETY: value is a live borrowed CF object.
        if unsafe { CFGetTypeID(value) } != unsafe { CFNumberGetTypeID() } {
            return Err(invalid("Device Utilization % has an unexpected CF type"));
        }
        let mut percent = 0.0_f64;
        // SAFETY: value is a live CFNumber; out points to a writable f64.
        let out: *mut c_void = (&mut percent as *mut f64).cast();
        if unsafe { CFNumberGetValue(value.cast(), K_CF_NUMBER_DOUBLE_TYPE, out) } == 0 {
            return Err(invalid("Device Utilization % is not a readable number"));
        }
        return Ok(percent);
    }
}
