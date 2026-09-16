/* SPDX-License-Identifier: MPL-2.0 */
#include "sayaka.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
#else
#include <time.h>
#include <pthread.h>
#endif

_Static_assert(sizeof(SayakaScanSnapshotV1) == 72, "snapshot ABI size");
_Static_assert(offsetof(SayakaScanSnapshotV1, progress_sequence) == 24, "snapshot ABI offset");

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "native host: %s\n", message);
        exit(1);
    }
}

static void check(int32_t status) {
    require(status == SAYAKA_OK, sayaka_status_message_v1(status));
}

static void pause_briefly(void) {
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec delay = {0, 1000000};
    nanosleep(&delay, NULL);
#endif
}

static uint64_t start(const uint8_t *bytes, size_t length, uint32_t encoding) {
    uint8_t *copy = malloc(length);
    require(copy != NULL, "path allocation");
    memcpy(copy, bytes, length);
    SayakaPathV1 path = {encoding, copy, length};
    SayakaScanRequestV1 request = {SAYAKA_ABI_VERSION_V1, sizeof(request), &path, 1};
    uint64_t handle = 0;
    check(sayaka_scan_start_v1(&request, &handle));
    memset(copy, 0, length);
    free(copy); /* start copied the input; no caller path memory is retained. */
    require(handle != 0, "zero handle");
    return handle;
}

static void release(uint64_t handle) {
    for (size_t attempt = 0; attempt < 30000; ++attempt) {
        int32_t status = sayaka_scan_release_v1(handle);
        if (status == SAYAKA_OK) return;
        require(status == SAYAKA_BUSY, sayaka_status_message_v1(status));
        pause_briefly();
    }
    require(0, "release deadline; host must not unload with live handles");
}

#ifndef _WIN32
static void *concurrent_calls(void *context) {
    uint64_t handle = *(uint64_t *)context;
    for (size_t i = 0; i < 100; ++i) {
        SayakaScanSnapshotV1 snapshot = {0};
        int32_t status = sayaka_scan_poll_v1(handle, &snapshot);
        require(status == SAYAKA_OK || status == SAYAKA_BUSY || status == SAYAKA_INVALID_HANDLE,
                "concurrent poll");
        status = sayaka_scan_cancel_v1(handle);
        require(status == SAYAKA_OK || status == SAYAKA_BUSY || status == SAYAKA_INVALID_HANDLE,
                "concurrent cancel");
        size_t needed = 0;
        status = sayaka_scan_result_v1(handle, NULL, 0, &needed);
        require(status == SAYAKA_BUFFER_TOO_SMALL || status == SAYAKA_BUSY || status == SAYAKA_INVALID_HANDLE,
                "concurrent result");
    }
    return NULL;
}
#endif

static void run(const uint8_t *root, size_t length, uint32_t encoding, int expected_failure) {
    require(sayaka_abi_version_v1() == SAYAKA_ABI_VERSION_V1, "ABI version");
    uint64_t invalid = 99;
    require(sayaka_scan_start_v1(NULL, &invalid) == SAYAKA_INVALID_ARGUMENT && invalid == 0,
            "null request contract");
    SayakaPathV1 path = {encoding, root, length};
    SayakaScanRequestV1 wrong = {2, sizeof(wrong), &path, 1};
    require(sayaka_scan_start_v1(&wrong, &invalid) == SAYAKA_UNSUPPORTED_VERSION,
            "version rejection");

    uint64_t handles[SAYAKA_MAX_TASKS_V1];
    for (size_t i = 0; i < SAYAKA_MAX_TASKS_V1; ++i) {
        handles[i] = start(root, length, encoding);
        for (size_t j = 0; j < i; ++j) require(handles[i] != handles[j], "handle reuse");
    }
    SayakaScanRequestV1 request = {SAYAKA_ABI_VERSION_V1, sizeof(request), &path, 1};
    require(sayaka_scan_start_v1(&request, &invalid) == SAYAKA_LIMIT_EXCEEDED && invalid == 0,
            "retained task bound");
    for (size_t i = 1; i < SAYAKA_MAX_TASKS_V1; ++i) {
        check(sayaka_scan_cancel_v1(handles[i]));
        release(handles[i]);
        require(sayaka_scan_cancel_v1(handles[i]) == SAYAKA_INVALID_HANDLE, "released handle accepted");
    }
    SayakaScanSnapshotV1 snapshot = {0};
    uint64_t previous = 0;
    for (size_t attempt = 0; attempt < 30000; ++attempt) {
        check(sayaka_scan_poll_v1(handles[0], &snapshot));
        require(snapshot.abi_version == 1 && snapshot.struct_size == sizeof(snapshot), "snapshot layout");
        require(snapshot.reserved == 0 && snapshot.progress_sequence >= previous, "progress sequence");
        previous = snapshot.progress_sequence;
        if (snapshot.state != SAYAKA_SCAN_RUNNING) break;
        pause_briefly();
    }
    require(snapshot.state == (expected_failure ? SAYAKA_SCAN_FAILED : SAYAKA_SCAN_COMPLETE),
            "unexpected terminal scan status");
    size_t required = 0;
    require(sayaka_scan_result_v1(handles[0], NULL, 0, &required) == SAYAKA_BUFFER_TOO_SMALL,
            "result length query");
    require(required > 0 && required <= SAYAKA_MAX_RESULT_BYTES_V1, "result bound");
    uint8_t guard[3] = {0xA1, 0xB2, 0xC3};
    size_t again = 0;
    require(sayaka_scan_result_v1(handles[0], &guard[1], 1, &again) == SAYAKA_BUFFER_TOO_SMALL,
            "undersized result buffer accepted");
    require(again == required && guard[0] == 0xA1 && guard[1] == 0xB2 && guard[2] == 0xC3,
            "undersized result buffer was written");
    uint8_t *json = malloc(required);
    require(json != NULL, "result allocation");
    check(sayaka_scan_result_v1(handles[0], json, required, &again));
    require(again == required, "result length changed");
    require(fwrite(json, 1, required, stdout) == required, "result stdout");
    free(json);
#ifndef _WIN32
    pthread_t callers[4];
    for (size_t i = 0; i < 4; ++i)
        require(pthread_create(&callers[i], NULL, concurrent_calls, &handles[0]) == 0, "host thread start");
#endif
    release(handles[0]);
#ifndef _WIN32
    for (size_t i = 0; i < 4; ++i)
        require(pthread_join(callers[i], NULL) == 0, "host thread join");
#endif
    require(sayaka_scan_poll_v1(handles[0], &snapshot) == SAYAKA_INVALID_HANDLE,
            "stale handle accepted");
    require(sayaka_scan_release_v1(handles[0]) == SAYAKA_INVALID_HANDLE, "double release accepted");
}

#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
    require(argc == 2 || argc == 3, "supply an absolute fixture root");
    run((const uint8_t *)argv[1], wcslen(argv[1]) * sizeof(wchar_t),
        SAYAKA_PATH_WINDOWS_UTF16LE_V1, argc == 3);
    return 0;
}
#else
int main(int argc, char **argv) {
    require(argc == 2 || argc == 3, "supply an absolute fixture root");
    run((const uint8_t *)argv[1], strlen(argv[1]), SAYAKA_PATH_UNIX_BYTES_V1, argc == 3);
    return 0;
}
#endif
