// SPDX-License-Identifier: MPL-2.0

use super::{PowerCounters, invalid, unsupported};
use std::ffi::{CStr, c_char, c_long, c_ulong, c_void};
use std::io;
use std::ptr::{self, NonNull};

// CoreFoundation CFBase.h: distinct opaque reference types, CFIndex = long,
// CFTypeID = unsigned long, Boolean = unsigned char on macOS.
macro_rules! opaque {
    ($($name:ident),+) => {$(
        #[repr(C)]
        struct $name { _private: [u8; 0] }
    )+};
}
opaque!(
    CfArray,
    CfDictionary,
    CfString,
    CfNumber,
    CfBoolean,
    CfAllocator
);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
    fn CFGetTypeID(value: *const c_void) -> c_ulong;
    fn CFEqual(left: *const c_void, right: *const c_void) -> u8;
    fn CFArrayGetTypeID() -> c_ulong;
    fn CFArrayGetCount(array: *const CfArray) -> c_long;
    fn CFArrayGetValueAtIndex(array: *const CfArray, index: c_long) -> *const c_void;
    fn CFDictionaryGetTypeID() -> c_ulong;
    fn CFDictionaryGetValue(dictionary: *const CfDictionary, key: *const c_void) -> *const c_void;
    fn CFStringGetTypeID() -> c_ulong;
    fn CFStringCreateWithCString(
        allocator: *const CfAllocator,
        string: *const c_char,
        encoding: u32,
    ) -> *const CfString;
    fn CFNumberGetTypeID() -> c_ulong;
    fn CFNumberIsFloatType(number: *const CfNumber) -> u8;
    fn CFNumberGetValue(number: *const CfNumber, kind: c_long, out: *mut c_void) -> u8;
    fn CFBooleanGetTypeID() -> c_ulong;
    // volume.rs declares this with an erased CF object pointer. Both have the
    // same C pointer ABI; retain the precise CFBooleanRef type in this boundary.
    #[allow(clashing_extern_declarations)]
    fn CFBooleanGetValue(value: *const CfBoolean) -> u8;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOPSCopyPowerSourcesInfo() -> *const c_void;
    fn IOPSCopyPowerSourcesList(info: *const c_void) -> *const CfArray;
    fn IOPSGetProvidingPowerSourceType(info: *const c_void) -> *const CfString;
    fn IOPSGetPowerSourceDescription(
        info: *const c_void,
        source: *const c_void,
    ) -> *const CfDictionary;
}

struct Owned<T>(NonNull<T>);

impl<T> Owned<T> {
    // SAFETY: Callers must supply only a Copy/Create result (+1) of type T.
    unsafe fn from_copy(value: *const T, source: &'static str) -> io::Result<Self> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or_else(|| io::Error::other(format!("{source} returned null")))
    }

    fn pointer(&self) -> *const T {
        self.0.as_ptr().cast_const()
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: This non-Clone owner contains precisely one +1 CF reference.
        unsafe { CFRelease(self.pointer().cast()) };
    }
}

fn string(value: &CStr) -> io::Result<Owned<CfString>> {
    // SAFETY: Input is a live NUL-terminated C string. UTF-8 = 0x08000100
    // (CFString.h); null allocator selects default. Create returns +1.
    unsafe {
        Owned::from_copy(
            CFStringCreateWithCString(ptr::null(), value.as_ptr(), 0x0800_0100),
            "CFStringCreateWithCString",
        )
    }
}

// SAFETY: Callers supply null or a live CF object valid for the entire call.
unsafe fn require_type(value: *const c_void, expected: c_ulong) -> io::Result<()> {
    if value.is_null() {
        return Err(unsupported("required IOPS power property is unavailable"));
    }
    // SAFETY: Non-null live CF object as required by this function's contract.
    if unsafe { CFGetTypeID(value) } != expected {
        return Err(invalid("IOPS power property has an unexpected CF type"));
    }
    Ok(())
}

// SAFETY: value is null or a live CF object.
unsafe fn equals_string(value: *const c_void, expected: &CStr) -> io::Result<bool> {
    // SAFETY: value is live if non-null; type is checked before CFEqual.
    unsafe { require_type(value, CFStringGetTypeID())? };
    let expected = string(expected)?;
    // SAFETY: Both objects are live CFStrings.
    Ok(unsafe { CFEqual(value, expected.pointer().cast()) } != 0)
}

// SAFETY: dictionary is a live CFDictionary; its borrowed values remain live
// as long as the IOPS snapshot, which the caller must retain.
unsafe fn property(dictionary: *const CfDictionary, key_name: &CStr) -> io::Result<*const c_void> {
    let key = string(key_name)?;
    // SAFETY: Caller guarantees a live dictionary; key is a live CFString.
    let value = unsafe { CFDictionaryGetValue(dictionary, key.pointer().cast()) };
    if value.is_null() {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "required IOPS property {} is missing",
                key_name.to_string_lossy()
            ),
        ))
    } else {
        Ok(value)
    }
}

// SAFETY: value is null or a live CF object.
unsafe fn boolean(value: *const c_void) -> io::Result<bool> {
    // SAFETY: Runtime validation precedes conversion to the distinct CF type.
    unsafe { require_type(value, CFBooleanGetTypeID())? };
    // SAFETY: Value was checked to be CFBoolean.
    Ok(unsafe { CFBooleanGetValue(value.cast()) } != 0)
}

// SAFETY: value is null or a live CF object.
unsafe fn integer(value: *const c_void) -> io::Result<i64> {
    // SAFETY: Runtime validation precedes conversion to the distinct CF type.
    unsafe { require_type(value, CFNumberGetTypeID())? };
    // SAFETY: Value was checked to be CFNumber. IOPS capacities are integers;
    // reject floating-point values rather than permit CFNumber truncation.
    if unsafe { CFNumberIsFloatType(value.cast()) } != 0 {
        return Err(invalid("IOPS capacity is not an integer CFNumber"));
    }
    let mut number = 0_i64;
    // SAFETY: CFNumber.h kCFNumberSInt64Type = 4; output is exactly i64.
    if unsafe { CFNumberGetValue(value.cast(), 4, (&mut number as *mut i64).cast()) } == 0 {
        return Err(invalid("IOPS capacity cannot be represented as i64"));
    }
    Ok(number)
}

fn percent(current: i64, maximum: i64) -> io::Result<f64> {
    if maximum <= 0 || current < 0 || current > maximum {
        return Err(invalid("IOPS battery capacity is outside its valid range"));
    }
    Ok(current as f64 / maximum as f64 * 100.0)
}

fn source_count(count: c_long) -> io::Result<c_long> {
    if !(0..=8).contains(&count) {
        Err(invalid("IOPS power source count exceeds collection bounds"))
    } else {
        Ok(count)
    }
}

fn single_battery(battery: &mut Option<(f64, bool)>, value: (f64, bool)) -> io::Result<()> {
    if battery.is_some() {
        return Err(unsupported(
            "multiple internal batteries have ambiguous aggregate capacity",
        ));
    }
    *battery = Some(value);
    Ok(())
}

fn power_counters(on_ac: bool, battery: Option<(f64, bool)>) -> io::Result<PowerCounters> {
    if !on_ac && battery.is_none() {
        return Err(unsupported(
            "IOPS reports battery supply without a present internal battery",
        ));
    }
    Ok(PowerCounters {
        on_ac,
        battery_percent: battery.map(|value| value.0),
        charging: battery.map(|value| value.1),
    })
}

/// Public IOPS snapshot: AC supply and optional internal battery percent/charging.
/// Desktops without a battery report None, not 0%. UPS supply and ambiguous
/// multi-battery aggregation are explicitly unsupported.
pub fn power() -> io::Result<PowerCounters> {
    // SAFETY: Copy functions return owned CF objects; each is held by an owner.
    let info = unsafe { Owned::from_copy(IOPSCopyPowerSourcesInfo(), "IOPSCopyPowerSourcesInfo")? };
    // SAFETY: Snapshot is live; Get returns a borrowed CFString.
    let source = unsafe { IOPSGetProvidingPowerSourceType(info.pointer()) };
    // SAFETY: Borrowed source remains live while info is held.
    let on_ac = if unsafe { equals_string(source.cast(), c"AC Power")? } {
        true
    // SAFETY: Same live borrowed source, checked again before use.
    } else if unsafe { equals_string(source.cast(), c"Battery Power")? } {
        false
    } else {
        return Err(unsupported(
            "IOPS supply is UPS or an unrecognized power source",
        ));
    };
    // SAFETY: Live snapshot; Copy returns a new +1 array, not a borrowed one.
    let list = unsafe {
        Owned::from_copy(
            IOPSCopyPowerSourcesList(info.pointer()),
            "IOPSCopyPowerSourcesList",
        )?
    };
    // SAFETY: Live CF object; ensure array type before array operations.
    unsafe { require_type(list.pointer().cast(), CFArrayGetTypeID())? };
    // SAFETY: Runtime-checked array. Bound iteration before accessing any item.
    let count = source_count(unsafe { CFArrayGetCount(list.pointer()) })?;
    let mut battery = None;
    for index in 0..count {
        // SAFETY: Index is within the checked array count. The returned handle
        // is opaque to us and passed only to the public IOPS accessor.
        let handle = unsafe { CFArrayGetValueAtIndex(list.pointer(), index) };
        if handle.is_null() {
            return Err(invalid("IOPS array contains a null power source"));
        }
        // SAFETY: Snapshot and its source handle are live. Get is borrowed.
        let dictionary = unsafe { IOPSGetPowerSourceDescription(info.pointer(), handle) };
        // SAFETY: A non-null accessor output is a live CF object; check type.
        unsafe { require_type(dictionary.cast(), CFDictionaryGetTypeID())? };
        // SAFETY: Validated dictionary; borrowed properties live with snapshot.
        let internal =
            unsafe { equals_string(property(dictionary, c"Type")?, c"InternalBattery")? };
        if !internal {
            continue;
        }
        // SAFETY: Valid dictionary; helper checks CFBoolean before reading.
        if !unsafe { boolean(property(dictionary, c"Is Present")?)? } {
            continue;
        }
        // SAFETY: Typed dictionary with live properties; helpers require exact
        // CFNumber/CFBoolean types and lossless integer conversion.
        let (current, maximum, charging) = unsafe {
            (
                integer(property(dictionary, c"Current Capacity")?)?,
                integer(property(dictionary, c"Max Capacity")?)?,
                boolean(property(dictionary, c"Is Charging")?)?,
            )
        };
        single_battery(&mut battery, (percent(current, maximum)?, charging))?;
    }
    power_counters(on_ac, battery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_and_source_bounds_do_not_fabricate_values() {
        assert_eq!(percent(0, 100).unwrap(), 0.0);
        assert_eq!(percent(25, 50).unwrap(), 50.0);
        assert_eq!(percent(100, 100).unwrap(), 100.0);
        for (current, max) in [(1, 0), (-1, 100), (101, 100), (0, -1)] {
            assert!(percent(current, max).is_err());
        }
        assert!(source_count(-1).is_err());
        assert!(source_count(9).is_err());
        assert_eq!(source_count(0).unwrap(), 0);
        assert_eq!(source_count(8).unwrap(), 8);
        let mut battery = None;
        single_battery(&mut battery, (50.0, false)).unwrap();
        assert_eq!(
            single_battery(&mut battery, (50.0, true))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported,
        );
    }

    #[test]
    fn desktop_has_no_battery_not_zero_percent() {
        assert_eq!(
            power_counters(true, None).unwrap(),
            PowerCounters {
                on_ac: true,
                battery_percent: None,
                charging: None,
            }
        );
        assert_eq!(
            power_counters(false, Some((0.0, false))).unwrap(),
            PowerCounters {
                on_ac: false,
                battery_percent: Some(0.0),
                charging: Some(false),
            }
        );
        assert_eq!(
            power_counters(false, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn cf_type_and_null_checks_precede_typed_access() {
        let text = string(c"not a number or boolean").unwrap();
        // SAFETY: Owned CFString is live; null inputs are permitted by helpers.
        unsafe {
            assert_eq!(
                integer(text.pointer().cast()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                boolean(text.pointer().cast()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                integer(ptr::null()).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                boolean(ptr::null()).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
        // SAFETY: Explicit null tests the Copy-result rejection; no owner exists.
        assert!(unsafe { Owned::<CfString>::from_copy(ptr::null(), "test") }.is_err());
    }
}
