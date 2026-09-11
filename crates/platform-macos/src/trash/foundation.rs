// SPDX-License-Identifier: MPL-2.0

use super::{MAX_PATH_BYTES, valid_path};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2::{msg_send, sel};
use std::ffi::{CStr, c_char, c_long, c_void};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: c_long,
        is_directory: u8,
    ) -> *const c_void;
    fn CFURLGetFileSystemRepresentation(
        url: *const c_void,
        resolve_against_base: u8,
        buffer: *mut u8,
        length: c_long,
    ) -> u8;
    fn CFRelease(value: *const c_void);
}

struct OwnedUrl(NonNull<AnyObject>);

impl Drop for OwnedUrl {
    fn drop(&mut self) {
        // SAFETY: The sole owner of the +1 CFURL Create result.
        unsafe { CFRelease(self.0.as_ptr().cast()) };
    }
}

pub(super) enum Outcome {
    Cancelled,
    Failed(String),
    Unknown {
        message: String,
        returned_destination: Option<PathBuf>,
        destination_error: Option<String>,
    },
    Destination(PathBuf),
}

pub(super) struct Prepared {
    manager: Retained<AnyObject>,
    source: OwnedUrl,
}

impl Prepared {
    #[cfg(test)]
    pub(super) fn existing_trash_directory(&self) -> io::Result<PathBuf> {
        let mut error: *mut AnyObject = ptr::null_mut();
        // SAFETY: Documented Foundation lookup with NSTrashDirectory,
        // NSUserDomainMask and this live source NSURL. create=false forbids
        // directory creation; the caller owns an autorelease pool.
        let directory: Option<Retained<AnyObject>> = unsafe {
            msg_send![&self.manager,
                URLForDirectory: 102usize,
                inDomain: 1usize,
                appropriateForURL: self.source.0.as_ref(),
                create: false,
                error: &mut error]
        };
        if let Some(error) = NonNull::new(error) {
            return Err(io::Error::other(native_error(error)));
        }
        let directory = directory
            .ok_or_else(|| io::Error::other("Foundation did not provide an existing Trash URL"))?;
        destination_path(NonNull::from(&*directory))
    }

    pub(super) fn new(path: &Path) -> io::Result<Self> {
        valid_path(path)?;
        let class = AnyClass::get(c"NSFileManager")
            .ok_or_else(|| io::Error::other("Foundation NSFileManager is unavailable"))?;
        // SAFETY: NSFileManager's documented no-argument +new returns an owned
        // initialized instance. Option handles nil without a panic.
        let manager: Option<Retained<AnyObject>> = unsafe { msg_send![class, new] };
        let manager = manager.ok_or_else(|| io::Error::other("could not create NSFileManager"))?;
        // SAFETY: Every NSObject supports respondsToSelector:. Check availability
        // before entering the mutation boundary.
        let supported: bool = unsafe {
            msg_send![&manager, respondsToSelector: sel!(trashItemAtURL:resultingItemURL:error:)]
        };
        if !supported {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native Trash selector is unavailable",
            ));
        }
        let bytes = path.as_os_str().as_bytes();
        let length = c_long::try_from(bytes.len())
            .map_err(|_| io::Error::other("source URL length overflow"))?;
        // SAFETY: CF copies the live byte slice; this is a filesystem URL, not a
        // lossy UTF-8 conversion. Null allocator selects the default allocator.
        let pointer = unsafe {
            CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), length, 0)
        };
        let source = OwnedUrl(
            NonNull::new(pointer.cast_mut().cast())
                .ok_or_else(|| io::Error::other("could not create Foundation source URL"))?,
        );
        Ok(Self { manager, source })
    }

    pub(super) fn trash(&self, cancelled: impl FnOnce() -> bool) -> Outcome {
        let mut destination: *mut AnyObject = ptr::null_mut();
        let mut error: *mut AnyObject = ptr::null_mut();
        // SAFETY: CFURL and NSURL are toll-free bridged. The retained CFURL
        // outlives this borrow and the synchronous message.
        let source = unsafe { self.source.0.as_ref() };
        if cancelled() {
            return Outcome::Cancelled;
        }
        // SAFETY: Documented macOS Foundation signature: BOOL, NSURL input and
        // nullable autoreleasing NSURL**/NSError** outputs. Raw output pointers
        // are initialized, aligned and live, and consumed within the caller's
        // autorelease pool. This is the ONLY mutation attempt; no fallback.
        let moved: bool = unsafe {
            msg_send![&self.manager,
                trashItemAtURL: source,
                resultingItemURL: &mut destination,
                error: &mut error]
        };
        // Preserve any filesystem pathname before interpreting contradictory
        // BOOL/NSError outputs. It remains unverified until the native verifier.
        classify_response(
            moved,
            NonNull::new(error).map(native_error),
            NonNull::new(destination).map(destination_path),
        )
    }
}

pub(super) fn classify_response(
    moved: bool,
    error: Option<String>,
    destination: Option<io::Result<PathBuf>>,
) -> Outcome {
    let had_destination = destination.is_some();
    let (returned_destination, destination_error) = match destination {
        Some(Ok(path)) => (Some(path), None),
        Some(Err(error)) => (None, Some(format!("Foundation destination URL: {error}"))),
        None => (
            None,
            Some("Foundation did not return a destination URL".into()),
        ),
    };
    if !moved {
        let cause = error.unwrap_or_else(|| {
            "Foundation returned NO without NSError; no move reported".to_owned()
        });
        if !had_destination {
            // NSFileManager.h promises NO means the item was not moved.
            return Outcome::Failed(cause);
        }
        return Outcome::Unknown {
            message: format!("Foundation returned NO with a destination URL: {cause}"),
            returned_destination,
            destination_error,
        };
    }
    if let Some(error) = error {
        return Outcome::Unknown {
            message: format!("Foundation returned YES with NSError: {error}"),
            returned_destination,
            destination_error,
        };
    }
    match returned_destination {
        Some(path) => Outcome::Destination(path),
        None => Outcome::Unknown {
            message: "Foundation returned YES without a usable destination pathname".into(),
            returned_destination: None,
            destination_error,
        },
    }
}

fn destination_path(url: NonNull<AnyObject>) -> io::Result<PathBuf> {
    // SAFETY: Foundation's documented successful output is a live NSURL within
    // this autorelease pool. The selector does not perform file I/O.
    let is_file: bool = unsafe { msg_send![url.as_ref(), isFileURL] };
    if !is_file {
        return Err(io::Error::other("result is not a file URL"));
    }
    let mut bytes = [0u8; MAX_PATH_BYTES + 1];
    // SAFETY: Live toll-free bridged NSURL and a writable bounded byte buffer.
    // This extracts the pathname; it does not open or hydrate the resulting file.
    if unsafe {
        CFURLGetFileSystemRepresentation(
            url.as_ptr().cast(),
            1,
            bytes.as_mut_ptr(),
            bytes.len() as c_long,
        )
    } == 0
    {
        return Err(io::Error::other(
            "cannot represent destination URL within path bound",
        ));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| io::Error::other("unterminated destination pathname"))?;
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes[..end].to_vec()));
    // Preserve bounded returned bytes even if their pathname form is invalid.
    // The native no-follow verifier validates them before any filesystem lookup.
    Ok(path)
}

fn native_error(error: NonNull<AnyObject>) -> String {
    // SAFETY: NSError is a documented autoreleased output, live in this pool;
    // code, domain and description have their documented integer/object types.
    let (code, domain, description): (
        isize,
        Option<Retained<AnyObject>>,
        Option<Retained<AnyObject>>,
    ) = unsafe {
        (
            msg_send![error.as_ref(), code],
            msg_send![error.as_ref(), domain],
            msg_send![error.as_ref(), description],
        )
    };
    format!(
        "NSError domain={} code={code}: {}",
        string_text(domain.as_deref()),
        string_text(description.as_deref()),
    )
}

fn string_text(value: Option<&AnyObject>) -> String {
    let Some(value) = value else {
        return "<missing native string>".into();
    };
    // SAFETY: NSError's domain/description are NSString instances. UTF8String
    // returns a NUL-terminated borrow valid while the string is retained.
    let text: *const c_char = unsafe { msg_send![value, UTF8String] };
    if text.is_null() {
        return "<native string has no UTF-8 representation>".into();
    }
    // SAFETY: Non-null NSString UTF8String result under its documented lifetime.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}
