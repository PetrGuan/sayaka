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
_Static_assert(sizeof(SayakaNodeRefV1) == 16, "node reference ABI size");
_Static_assert(sizeof(SayakaPageRequestV1) == 24, "page request ABI size");
_Static_assert(offsetof(SayakaPageRequestV1, offset) == 8, "page offset ABI offset");
_Static_assert(sizeof(SayakaIssuePageRequestV1) == 24, "issue page ABI size");
_Static_assert(offsetof(SayakaIssuePageRequestV1, reserved) == 20, "issue reserved ABI offset");

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
        SayakaPageRequestV1 page = {1, sizeof(page), 0, 1, SAYAKA_SORT_NAME};
        status = sayaka_scan_roots_v1(handle, &page, NULL, 0, &needed);
        require(status == SAYAKA_BUFFER_TOO_SMALL || status == SAYAKA_BUSY ||
                status == SAYAKA_INVALID_HANDLE || status == SAYAKA_QUERY_UNAVAILABLE,
                "concurrent roots query");
        SayakaIssuePageRequestV1 issues = {1, sizeof(issues), 0, 1, 0};
        status = sayaka_scan_issues_v1(handle, &issues, NULL, 0, &needed);
        require(status == SAYAKA_BUFFER_TOO_SMALL || status == SAYAKA_BUSY ||
                status == SAYAKA_INVALID_HANDLE, "concurrent diagnostic query");
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
    SayakaIssuePageRequestV1 issues = {1, sizeof(issues), 0, 1, 0};
    size_t issue_length = 0, issue_again = 0;
    require(sayaka_scan_issues_v1(handles[0], &issues, NULL, 0, &issue_length) ==
            SAYAKA_BUFFER_TOO_SMALL, "diagnostic length query");
    require(issue_length > 0 && issue_length <= SAYAKA_MAX_QUERY_BYTES_V1, "diagnostic bound");
    uint8_t issue_guard[3] = {0xA1, 0xB2, 0xC3};
    require(sayaka_scan_issues_v1(handles[0], &issues, &issue_guard[1], 1, &issue_again) ==
            SAYAKA_BUFFER_TOO_SMALL, "undersized diagnostic buffer accepted");
    require(issue_again == issue_length && issue_guard[0] == 0xA1 &&
            issue_guard[1] == 0xB2 && issue_guard[2] == 0xC3, "diagnostic guard overwritten");
    uint8_t *issue_json = malloc(issue_length + 1);
    require(issue_json != NULL, "diagnostic allocation");
    issue_json[issue_length] = 0xA1;
    check(sayaka_scan_issues_v1(handles[0], &issues, issue_json, issue_length, &issue_again));
    require(issue_again == issue_length && issue_json[issue_length] == 0xA1,
            "diagnostic length or terminator contract changed");
    issue_json[issue_length] = 0;
    require(strstr((const char *)issue_json, expected_failure
                   ? "\"scan_status\":\"failed\"" : "\"scan_status\":\"complete\"") != NULL,
            "diagnostic scan state changed");
    require(strstr((const char *)issue_json, "\"issues\":[") != NULL, "diagnostic issues missing");
    free(issue_json);
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
    SayakaPageRequestV1 page = {1, sizeof(page), 0, 1, SAYAKA_SORT_NAME};
    required = 99;
    int32_t query_status = sayaka_scan_roots_v1(handles[0], &page, NULL, 0, &required);
    if (expected_failure) {
        require(query_status == SAYAKA_QUERY_UNAVAILABLE && required == 0,
                "failed scan became empty query success");
    } else {
        require(query_status == SAYAKA_BUFFER_TOO_SMALL && required > 0 &&
                required <= SAYAKA_MAX_QUERY_BYTES_V1, "roots length query");
        require(sayaka_scan_roots_v1(handles[0], &page, &guard[1], 1, &again) ==
                SAYAKA_BUFFER_TOO_SMALL, "undersized roots buffer accepted");
        require(again == required && guard[0] == 0xA1 && guard[1] == 0xB2 && guard[2] == 0xC3,
                "undersized roots buffer was written");
        json = malloc(required);
        require(json != NULL, "query allocation");
        check(sayaka_scan_roots_v1(handles[0], &page, json, required, &again));
        require(again == required, "roots payload length changed");
        free(json);
        uint64_t refreshed = start(root, length, encoding);
        SayakaNodeRefV1 old_node = {handles[0], 1};
        require(sayaka_scan_node_v1(refreshed, &old_node, NULL, 0, &again) ==
                SAYAKA_INVALID_NODE && again == 0, "cross-task node accepted");
        require(sayaka_scan_children_v1(refreshed, &old_node, &page, NULL, 0, &again) ==
                SAYAKA_INVALID_NODE && again == 0, "cross-task parent accepted");
        release(refreshed);
    }
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
    require(sayaka_scan_roots_v1(handles[0], &page, NULL, 0, &again) == SAYAKA_INVALID_HANDLE,
            "query accepted a released task");
    require(sayaka_scan_issues_v1(handles[0], &issues, NULL, 0, &again) == SAYAKA_INVALID_HANDLE &&
            again == 0, "diagnostics accepted a released task");
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
