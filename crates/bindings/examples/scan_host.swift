// SPDX-License-Identifier: MPL-2.0
import Foundation

func check(_ code: Int32) {
    precondition(code == Int32(SAYAKA_OK.rawValue), String(cString: sayaka_status_message_v1(code)))
}

precondition(CommandLine.arguments.count == 2, "Supply an absolute owned fixture root")
precondition(sayaka_abi_version_v1() == SAYAKA_ABI_VERSION_V1)
var handle: UInt64 = 0
let pathBytes = Array(CommandLine.arguments[1].utf8)
pathBytes.withUnsafeBufferPointer { bytes in
    var path = SayakaPathV1(
        encoding: SAYAKA_PATH_UNIX_BYTES_V1,
        bytes: bytes.baseAddress,
        byte_length: bytes.count
    )
    withUnsafePointer(to: &path) { root in
        var request = SayakaScanRequestV1(
            abi_version: SAYAKA_ABI_VERSION_V1,
            struct_size: UInt32(MemoryLayout<SayakaScanRequestV1>.size),
            roots: root,
            root_count: 1
        )
        check(sayaka_scan_start_v1(&request, &handle))
    }
}

// A real App runs this polling/result work off its main actor.
let deadline = ProcessInfo.processInfo.systemUptime + 30
var snapshot = SayakaScanSnapshotV1()
while true {
    check(sayaka_scan_poll_v1(handle, &snapshot))
    if snapshot.state != SAYAKA_SCAN_RUNNING.rawValue { break }
    precondition(ProcessInfo.processInfo.systemUptime < deadline, "Scan deadline")
    Thread.sleep(forTimeInterval: 0.001)
}
precondition(snapshot.state == SAYAKA_SCAN_COMPLETE.rawValue, "Expected complete owned fixture")
var required = 0
precondition(sayaka_scan_result_v1(handle, nil, 0, &required) == Int32(SAYAKA_BUFFER_TOO_SMALL.rawValue))
precondition(required > 0 && required <= Int(SAYAKA_MAX_RESULT_BYTES_V1))
var data = Data(count: required)
data.withUnsafeMutableBytes { bytes in
    check(sayaka_scan_result_v1(handle, bytes.bindMemory(to: UInt8.self).baseAddress,
                                bytes.count, &required))
}
let result = try JSONSerialization.jsonObject(with: data) as! [String: Any]
precondition(result["status"] as? String == "complete")
check(sayaka_scan_release_v1(handle))
precondition(sayaka_scan_poll_v1(handle, &snapshot) == Int32(SAYAKA_INVALID_HANDLE.rawValue))
try FileHandle.standardOutput.write(contentsOf: data)
