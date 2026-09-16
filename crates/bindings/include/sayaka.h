/* SPDX-License-Identifier: MPL-2.0 */
#ifndef SAYAKA_H
#define SAYAKA_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(SAYAKA_STATIC)
#define SAYAKA_API __declspec(dllimport)
#else
#define SAYAKA_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SAYAKA_ABI_VERSION_V1 1u
#define SAYAKA_MAX_TASKS_V1 4u
#define SAYAKA_MAX_RESULT_BYTES_V1 67108864u
#define SAYAKA_PATH_UNIX_BYTES_V1 1u
#define SAYAKA_PATH_WINDOWS_UTF16LE_V1 2u

enum SayakaStatusV1 {
    SAYAKA_OK = 0,
    SAYAKA_INVALID_ARGUMENT = 1,
    SAYAKA_UNSUPPORTED_VERSION = 2,
    SAYAKA_UNSUPPORTED_PLATFORM = 3,
    SAYAKA_INVALID_HANDLE = 4,
    SAYAKA_LIMIT_EXCEEDED = 5,
    SAYAKA_NOT_READY = 6,
    SAYAKA_BUFFER_TOO_SMALL = 7,
    SAYAKA_BUSY = 8,
    SAYAKA_INTERNAL_ERROR = 9,
    SAYAKA_PANIC = 10
};

enum SayakaScanStateV1 {
    SAYAKA_SCAN_RUNNING = 1,
    SAYAKA_SCAN_COMPLETE = 2,
    SAYAKA_SCAN_PARTIAL = 3,
    SAYAKA_SCAN_CANCELLED = 4,
    SAYAKA_SCAN_FAILED = 5
};

typedef struct SayakaPathV1 {
    uint32_t encoding;
    const uint8_t *bytes;
    size_t byte_length; /* Native bytes, not NUL terminated; UTF-16LE uses bytes. */
} SayakaPathV1;

typedef struct SayakaScanRequestV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    const SayakaPathV1 *roots;
    size_t root_count; /* 1..64 absolute roots; input copied by start. */
} SayakaScanRequestV1;

typedef struct SayakaScanSnapshotV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t state;
    uint32_t cancellation_requested;
    uint32_t has_progress; /* When zero, progress values are absent, not measured zeroes. */
    uint32_t reserved;
    uint64_t progress_sequence;
    uint64_t observed_entries;
    uint64_t unique_files;
    uint64_t logical_bytes_known;
    uint64_t observed_issues;
    uint64_t elapsed_ms;
} SayakaScanSnapshotV1;

/* Caller pointers must be valid, correctly aligned and non-overlapping.
 * Null/alignment checks cannot validate arbitrary foreign memory.
 * No Rust allocation is returned for the caller to free. */
SAYAKA_API uint32_t sayaka_abi_version_v1(void);
SAYAKA_API const char *sayaka_status_message_v1(int32_t code); /* Static, do not free. */
SAYAKA_API int32_t sayaka_scan_start_v1(const SayakaScanRequestV1 *request, uint64_t *out_handle);
SAYAKA_API int32_t sayaka_scan_poll_v1(uint64_t handle, SayakaScanSnapshotV1 *out_snapshot);
SAYAKA_API int32_t sayaka_scan_cancel_v1(uint64_t handle);
/* Result serialization/copy may be expensive: use a host worker queue.
 * NULL/0 queries length via BUFFER_TOO_SMALL; JSON length excludes any NUL.
 * A successful copy is not scan success: inspect snapshot/report status. */
SAYAKA_API int32_t sayaka_scan_result_v1(uint64_t handle, uint8_t *buffer, size_t capacity, size_t *required);
/* BUSY retains ownership. If the worker is active, release requests cancellation;
 * a concurrent operation holding the handle can also return BUSY before that.
 * Retry until OK. Poll/cancel/result also return BUSY on concurrent handle use.
 * Do not unload while any handle is live or any host API call is in flight.
 * Cancellation cannot forcibly interrupt a blocked native OS call. */
SAYAKA_API int32_t sayaka_scan_release_v1(uint64_t handle);

#ifdef __cplusplus
}
#endif
#endif
