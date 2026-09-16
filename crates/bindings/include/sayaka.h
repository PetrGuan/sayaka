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
#define SAYAKA_MAX_QUERY_BYTES_V1 1048576u
#define SAYAKA_MAX_PAGE_NODES_V1 256u
#define SAYAKA_MAX_INSTALLER_CANDIDATES_V1 512u
#define SAYAKA_MAX_INSTALLER_SELECTIONS_V1 32u
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
    SAYAKA_PANIC = 10,
    SAYAKA_INVALID_NODE = 11,
    SAYAKA_NOT_DIRECTORY = 12,
    SAYAKA_QUERY_UNAVAILABLE = 13,
    SAYAKA_INVALID_CANDIDATE = 14
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

typedef struct SayakaNodeRefV1 {
    uint64_t task_handle;
    uint64_t node_id;
} SayakaNodeRefV1;

enum SayakaSortV1 {
    SAYAKA_SORT_NAME = 1,          /* Native path ascending; not locale/case folded. */
    SAYAKA_SORT_LOGICAL_SIZE = 2,  /* Known subtotal descending, unknown last. */
    SAYAKA_SORT_ALLOCATED_SIZE = 3 /* Size ties use native path ascending. */
};

typedef struct SayakaPageRequestV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t offset;
    uint32_t limit; /* 1..SAYAKA_MAX_PAGE_NODES_V1 */
    uint32_t sort;
} SayakaPageRequestV1;

typedef struct SayakaInstallerRequestV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    SayakaPathV1 root; /* One explicit native absolute root; input copied. */
} SayakaInstallerRequestV1;

typedef struct SayakaInstallerCandidateRefV1 {
    uint64_t task_handle; /* Discovery handle, never a scan or selection handle. */
    uint64_t candidate_id;
} SayakaInstallerCandidateRefV1;

enum SayakaInstallerTaskKindV1 {
    SAYAKA_INSTALLER_DISCOVERY = 1,
    SAYAKA_INSTALLER_SELECTION = 2
};

enum SayakaInstallerPhaseV1 {
    SAYAKA_INSTALLER_SCANNING = 1,
    SAYAKA_INSTALLER_INSPECTING = 2,
    SAYAKA_INSTALLER_CHECKING_SELECTION = 3
};

typedef struct SayakaInstallerSnapshotV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t kind;
    uint32_t state; /* SayakaScanStateV1; selection PARTIAL means a refused batch. */
    uint32_t cancellation_requested;
    uint32_t has_progress;
    uint32_t phase;
    uint32_t reserved;
    uint64_t progress_sequence;
    uint64_t observed_entries;
    uint64_t total_candidates; /* Meaningful after scanning, not a scan estimate. */
    uint64_t inspected_candidates; /* Selection: full checked batch count, else 0. */
    uint64_t elapsed_ms;
} SayakaInstallerSnapshotV1;

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
/* Read-only immutable queries; first query builds/caches a bounded ScanTree.
 * Run on a host worker, not the UI thread. No filesystem access or authority.
 * NULL/0 and BUFFER_TOO_SMALL follow result's caller-buffer protocol, but use
 * SAYAKA_MAX_QUERY_BYTES_V1. No partial writes or trailing NUL. On payload limit
 * failure, reduce the page limit; required stays zero.
 * Roots/children data: {offset,total,next_offset,nodes}; node data: one detail.
 * Each response carries schema/task/scan status; inspect incomplete/unknown
 * summaries, not only API status. Details/paths use docs/BINDINGS.md's schema.
 * References encode task_handle/node_id as decimal JSON strings. Pass BOTH
 * unchanged; a reference from a different task returns INVALID_NODE.
 * Offset == total gives an empty terminal page; offset > total is invalid.
 * New scans are explicit refreshes. Old tasks remain snapshots until release;
 * never carry old references into the new task. These IDs are not capabilities.
 * These symbols are additive to the original v1 scan ABI; hosts using them
 * require a library build that exports them, not just an ABI version of 1. */
SAYAKA_API int32_t sayaka_scan_roots_v1(uint64_t handle, const SayakaPageRequestV1 *request,
                                     uint8_t *buffer, size_t capacity, size_t *required);
SAYAKA_API int32_t sayaka_scan_node_v1(uint64_t handle, const SayakaNodeRefV1 *node,
                                    uint8_t *buffer, size_t capacity, size_t *required);
SAYAKA_API int32_t sayaka_scan_children_v1(uint64_t handle, const SayakaNodeRefV1 *parent,
                                        const SayakaPageRequestV1 *request,
                                        uint8_t *buffer, size_t capacity, size_t *required);
/* BUSY retains ownership. If the worker is active, release requests cancellation;
 * a concurrent operation holding the handle can also return BUSY before that.
 * Retry until OK. Poll/cancel/result/queries return BUSY on concurrent handle use.
 * Do not unload while any handle is live or any host API call is in flight.
 * Cancellation cannot forcibly interrupt a blocked native OS call. */
SAYAKA_API int32_t sayaka_scan_release_v1(uint64_t handle);

/* Installer discovery and selection checks are macOS-only in this slice;
 * other platforms return UNSUPPORTED_PLATFORM before discovery starts.
 * Scan and installer tasks share the total four-handle limit and never reuse
 * handles. Each API accepts only its own kind; wrong-kind is INVALID_HANDLE.
 * The lifecycle/release/buffer memory contracts above apply unchanged. */
SAYAKA_API int32_t sayaka_installer_start_v1(const SayakaInstallerRequestV1 *request, uint64_t *out_handle);
SAYAKA_API int32_t sayaka_installer_poll_v1(uint64_t handle, SayakaInstallerSnapshotV1 *out_snapshot);
SAYAKA_API int32_t sayaka_installer_cancel_v1(uint64_t handle);
/* Immutable cached observations, no filesystem I/O. Page limits/sorts/buffer cap
 * match scan queries. Candidate references are decimal-string IDs in JSON.
 * Format recognition/selection_check_eligible is not trust or cleanup authority.
 * Failed discovery returns QUERY_UNAVAILABLE; inspect installer_result instead. */
SAYAKA_API int32_t sayaka_installer_candidates_v1(uint64_t handle, const SayakaPageRequestV1 *request,
                                                uint8_t *buffer, size_t capacity, size_t *required);
SAYAKA_API int32_t sayaka_installer_candidate_v1(uint64_t handle, const SayakaInstallerCandidateRefV1 *candidate,
                                               uint8_t *buffer, size_t capacity, size_t *required);
/* Copies 1..32 unique references from this discovery, then starts a separate
 * read-only native check task. The source may be released after a successful
 * start: the new task owns the required evidence. Old/cross-task refs fail.
 * Revalidation runs off-thread; a changed/unknown/refused member refuses the
 * entire batch. No Plan/Approval or executable session survives the check.
 * A "checked" result is an observation at check time, NOT future authority. */
SAYAKA_API int32_t sayaka_installer_selection_start_v1(uint64_t discovery_handle,
                                                     const SayakaInstallerCandidateRefV1 *candidates,
                                                     size_t count, uint64_t *out_handle);
/* Terminal discovery/selection/error envelope, max MAX_RESULT_BYTES_V1, no NUL.
 * Inspect data.status and issues even when the copy returns OK. */
SAYAKA_API int32_t sayaka_installer_result_v1(uint64_t handle, uint8_t *buffer, size_t capacity, size_t *required);
SAYAKA_API int32_t sayaka_installer_release_v1(uint64_t handle);

#ifdef __cplusplus
}
#endif
#endif
