// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use super::*;
use std::fs;
use std::os::unix::ffi::OsStrExt;

#[test]
fn one_shot_contract_rejects_bad_layout_and_returns_bounded_json() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/app-orphans-ffi-fixture");
    let _ = fs::remove_dir_all(&root);
    let apps = root.join("Applications");
    let caches = root.join("Library/Caches");
    fs::create_dir_all(&apps).unwrap();
    fs::create_dir_all(caches.join("com.example.leftover")).unwrap();
    let app_bytes = apps.as_os_str().as_bytes();
    let cache_bytes = caches.as_os_str().as_bytes();
    let mut request = SayakaOrphanPreviewRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<SayakaOrphanPreviewRequestV1>() as u32,
        app_root: SayakaPathV1 {
            encoding: UNIX_BYTES,
            bytes: app_bytes.as_ptr(),
            byte_length: app_bytes.len(),
        },
        caches_root: SayakaPathV1 {
            encoding: UNIX_BYTES,
            bytes: cache_bytes.as_ptr(),
            byte_length: cache_bytes.len(),
        },
        reserved: 0,
    };
    let mut output = vec![0u8; ORPHAN_RESULT_BYTES];
    let mut required = 0usize;
    let mut call =
        |request: &SayakaOrphanPreviewRequestV1, capacity: usize, required: &mut usize| {
            // SAFETY: All request fields and owned output buffers are valid and disjoint.
            unsafe { sayaka_orphan_preview_v1(request, output.as_mut_ptr(), capacity, required) }
        };
    assert_eq!(
        call(&request, ORPHAN_RESULT_BYTES - 1, &mut required),
        INVALID_ARGUMENT
    );
    request.reserved = 1;
    assert_eq!(
        call(&request, ORPHAN_RESULT_BYTES, &mut required),
        INVALID_ARGUMENT
    );
    request.reserved = 0;
    request.abi_version += 1;
    assert_eq!(
        call(&request, ORPHAN_RESULT_BYTES, &mut required),
        UNSUPPORTED_VERSION
    );
    request.abi_version = ABI_VERSION;
    let invalid = b"/";
    request.app_root.bytes = invalid.as_ptr();
    request.app_root.byte_length = invalid.len();
    assert_eq!(
        call(&request, ORPHAN_RESULT_BYTES, &mut required),
        INVALID_ARGUMENT
    );
    request.app_root.bytes = app_bytes.as_ptr();
    request.app_root.byte_length = app_bytes.len();
    assert_eq!(call(&request, ORPHAN_RESULT_BYTES, &mut required), OK);
    drop(call);
    assert!(required > 0 && required <= ORPHAN_RESULT_BYTES);
    let json: serde_json::Value = serde_json::from_slice(&output[..required]).unwrap();
    assert_eq!(json["kind"], "orphan_app_cache_preview");
    assert_eq!(json["effects_performed"], false);
    let _ = fs::remove_dir_all(root);
}
