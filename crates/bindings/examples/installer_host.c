/* SPDX-License-Identifier: MPL-2.0 */
#include "sayaka.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
#else
#include <time.h>
#endif

_Static_assert(sizeof(SayakaInstallerSnapshotV1) == 72, "installer snapshot size");
_Static_assert(offsetof(SayakaInstallerSnapshotV1, progress_sequence) == 32, "progress offset");
_Static_assert(sizeof(SayakaInstallerCandidateRefV1) == 16, "candidate reference size");

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "installer host: %s\n", message); exit(1); }
}
static void check(int32_t code) { require(code == SAYAKA_OK, sayaka_status_message_v1(code)); }
static void pause_briefly(void) {
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec delay = {0, 1000000};
    nanosleep(&delay, NULL);
#endif
}
static void release(uint64_t handle, int scan) {
    for (size_t i = 0; i < 30000; ++i) {
        int32_t code = scan ? sayaka_scan_release_v1(handle) : sayaka_installer_release_v1(handle);
        if (code == SAYAKA_OK) return;
        require(code == SAYAKA_BUSY, "release status");
        pause_briefly();
    }
    require(0, "release deadline; live task must not be unloaded");
}
static void finish(uint64_t handle, uint32_t kind) {
    uint64_t previous = 0;
    for (size_t i = 0; i < 30000; ++i) {
        SayakaInstallerSnapshotV1 snapshot = {0};
        check(sayaka_installer_poll_v1(handle, &snapshot));
        require(snapshot.abi_version == 1 && snapshot.struct_size == sizeof(snapshot), "snapshot ABI");
        require(snapshot.kind == kind && snapshot.progress_sequence >= previous, "kind/progress");
        previous = snapshot.progress_sequence;
        if (snapshot.state != SAYAKA_SCAN_RUNNING) {
            require(snapshot.state == SAYAKA_SCAN_COMPLETE, "expected complete fixture operation");
            return;
        }
        pause_briefly();
    }
    require(0, "installer task deadline");
}
static uint8_t *result(uint64_t handle, size_t *length) {
    require(sayaka_installer_result_v1(handle, NULL, 0, length) == SAYAKA_BUFFER_TOO_SMALL, "result length");
    require(*length > 0 && *length <= SAYAKA_MAX_RESULT_BYTES_V1, "result bound");
    uint8_t *bytes = malloc(*length);
    require(bytes != NULL, "result allocation");
    size_t required = 0;
    check(sayaka_installer_result_v1(handle, bytes, *length, &required));
    require(required == *length, "result length changed");
    return bytes;
}

static void run(const uint8_t *root, size_t length, uint32_t encoding) {
    SayakaPathV1 path = {encoding, root, length};
    SayakaInstallerRequestV1 request = {1, sizeof(request), path};
    uint64_t handle = 0;
#ifdef _WIN32
    require(sayaka_installer_start_v1(&request, &handle) == SAYAKA_UNSUPPORTED_PLATFORM &&
            handle == 0, "unsupported installer platform must be explicit");
    puts("{\"status\":\"unsupported_platform\"}");
    return;
#endif
    check(sayaka_installer_start_v1(&request, &handle));
    uint64_t scans[3] = {0};
    SayakaScanRequestV1 scan_request = {1, sizeof(scan_request), &path, 1};
    for (size_t i = 0; i < 3; ++i) check(sayaka_scan_start_v1(&scan_request, &scans[i]));
    uint64_t overflow = 99;
    require(sayaka_installer_start_v1(&request, &overflow) == SAYAKA_LIMIT_EXCEEDED &&
            overflow == 0, "scan/installer handles must share one capacity bound");
    for (size_t i = 0; i < 3; ++i) release(scans[i], 1);
    finish(handle, SAYAKA_INSTALLER_DISCOVERY);
    SayakaScanSnapshotV1 wrong = {0};
    require(sayaka_scan_poll_v1(handle, &wrong) == SAYAKA_INVALID_HANDLE, "wrong-kind handle accepted");
    SayakaPageRequestV1 page = {1, sizeof(page), 0, 1, SAYAKA_SORT_NAME};
    size_t needed = 0;
    SayakaIssuePageRequestV1 issues = {1, sizeof(issues), 0, 1, 0};
    require(sayaka_scan_issues_v1(handle, &issues, NULL, 0, &needed) == SAYAKA_INVALID_HANDLE &&
            needed == 0, "diagnostics accepted an installer handle");
    require(sayaka_installer_candidates_v1(handle, &page, NULL, 0, &needed) ==
            SAYAKA_BUFFER_TOO_SMALL, "candidate length");
    require(needed > 0 && needed <= SAYAKA_MAX_QUERY_BYTES_V1, "candidate bound");
    uint8_t guard[3] = {0x31, 0x42, 0x53};
    size_t again = 0;
    require(sayaka_installer_candidates_v1(handle, &page, &guard[1], 1, &again) ==
            SAYAKA_BUFFER_TOO_SMALL && again == needed &&
            guard[0] == 0x31 && guard[1] == 0x42 && guard[2] == 0x53, "short-buffer guard");
    uint8_t *json = malloc(needed + 1);
    require(json != NULL, "candidate allocation");
    check(sayaka_installer_candidates_v1(handle, &page, json, needed, &again));
    require(again == needed, "candidate payload changed");
    json[needed] = 0;
    /* Fixture-only extraction. Production C clients should use a JSON decoder. */
    const char *field = strstr((const char *)json, "\"candidate_id\":\"");
    require(field != NULL, "candidate reference absent");
    field += strlen("\"candidate_id\":\"");
    require(*field >= '0' && *field <= '9', "candidate id encoding");
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(field, &end, 10);
    require(errno == 0 && end != field && *end == '"' && parsed > 0 &&
            parsed <= UINT64_MAX, "candidate id range");
    SayakaInstallerCandidateRefV1 candidate = {handle, (uint64_t)parsed};
    free(json);
    require(sayaka_installer_candidate_v1(handle, &candidate, NULL, 0, &needed) ==
            SAYAKA_BUFFER_TOO_SMALL, "candidate detail");
    size_t discovery_length = 0;
    uint8_t *discovery = result(handle, &discovery_length);
    uint64_t selection = 0;
    check(sayaka_installer_selection_start_v1(handle, &candidate, 1, &selection));
    require(selection != handle, "selection handle reused discovery");
    uint64_t wrong_source = 99;
    require(sayaka_installer_selection_start_v1(selection, &candidate, 1, &wrong_source) ==
            SAYAKA_INVALID_CANDIDATE && wrong_source == 0, "cross-task reference accepted");
    release(handle, 0);
    require(sayaka_installer_candidate_v1(handle, &candidate, NULL, 0, &needed) ==
            SAYAKA_INVALID_HANDLE, "released source accepted");
    finish(selection, SAYAKA_INSTALLER_SELECTION);
    size_t selection_length = 0;
    uint8_t *selected = result(selection, &selection_length);
    release(selection, 0);
    require(fputs("{\"discovery\":", stdout) >= 0, "stdout");
    require(fwrite(discovery, 1, discovery_length, stdout) == discovery_length, "discovery stdout");
    require(fputs(",\"selection\":", stdout) >= 0, "stdout");
    require(fwrite(selected, 1, selection_length, stdout) == selection_length, "selection stdout");
    require(fputs("}\n", stdout) >= 0, "stdout");
    free(discovery);
    free(selected);
}

#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
    require(argc == 2, "supply an absolute owned installer fixture root");
    run((const uint8_t *)argv[1], wcslen(argv[1]) * sizeof(wchar_t), SAYAKA_PATH_WINDOWS_UTF16LE_V1);
    return 0;
}
#else
int main(int argc, char **argv) {
    require(argc == 2, "supply an absolute owned installer fixture root");
    run((const uint8_t *)argv[1], strlen(argv[1]), SAYAKA_PATH_UNIX_BYTES_V1);
    return 0;
}
#endif
