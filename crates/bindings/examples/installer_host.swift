// SPDX-License-Identifier: MPL-2.0
import Foundation

func check(_ code: Int32) {
    precondition(code == Int32(SAYAKA_OK.rawValue), String(cString: sayaka_status_message_v1(code)))
}

func copyJSON(_ call: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>) -> Int32) -> Data {
    var required = 0
    precondition(call(nil, 0, &required) == Int32(SAYAKA_BUFFER_TOO_SMALL.rawValue))
    precondition(required > 0 && required <= Int(SAYAKA_MAX_RESULT_BYTES_V1))
    var data = Data(count: required)
    data.withUnsafeMutableBytes {
        check(call($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &required))
    }
    return data
}

struct Reference: Decodable, Equatable {
    let taskHandle: String
    let candidateId: String
    var native: SayakaInstallerCandidateRefV1 {
        guard let handle = UInt64(taskHandle), let id = UInt64(candidateId) else {
            preconditionFailure("Invalid candidate reference")
        }
        return SayakaInstallerCandidateRefV1(task_handle: handle, candidate_id: id)
    }
}
struct NativePath: Decodable, Equatable {
    let encoding: String
    let raw: String
}
struct Format: Decodable, Equatable {
    let status: String
    let family: String
}
struct Candidate: Decodable, Equatable {
    let reference: Reference
    let path: NativePath
    let logicalBytes: UInt64?
    let allocatedBytes: UInt64?
    let format: Format
    let selectionCheckEligible: Bool
}
struct Page: Decodable {
    let offset: UInt64
    let total: Int
    let nextOffset: UInt64?
    let candidates: [Candidate]
}
struct Query<T: Decodable>: Decodable {
    let schemaVersion: Int
    let taskHandle: String
    let status: String
    let complete: Bool
    let executionAuthority: Bool
    let effectsPerformed: Bool
    let data: T
}
func decode<T: Decodable>(_ data: Data) throws -> T {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return try decoder.decode(T.self, from: data)
}
func pageRequest(_ offset: UInt64, _ sort: SayakaSortV1) -> SayakaPageRequestV1 {
    SayakaPageRequestV1(abi_version: 1, struct_size: UInt32(MemoryLayout<SayakaPageRequestV1>.size),
                        offset: offset, limit: 1, sort: sort.rawValue)
}
func start(_ root: String) -> UInt64 {
    var handle: UInt64 = 0
    Array(root.utf8).withUnsafeBufferPointer { bytes in
        var request = SayakaInstallerRequestV1(
            abi_version: 1, struct_size: UInt32(MemoryLayout<SayakaInstallerRequestV1>.size),
            root: SayakaPathV1(encoding: SAYAKA_PATH_UNIX_BYTES_V1, bytes: bytes.baseAddress, byte_length: bytes.count)
        )
        check(sayaka_installer_start_v1(&request, &handle))
    }
    return handle
}
func finish(_ handle: UInt64, _ expected: SayakaScanStateV1) {
    let deadline = ProcessInfo.processInfo.systemUptime + 30
    var previous: UInt64 = 0
    while true {
        var snapshot = SayakaInstallerSnapshotV1()
        check(sayaka_installer_poll_v1(handle, &snapshot))
        precondition(snapshot.progress_sequence >= previous)
        previous = snapshot.progress_sequence
        if snapshot.state != SAYAKA_SCAN_RUNNING.rawValue {
            precondition(snapshot.state == expected.rawValue)
            return
        }
        precondition(ProcessInfo.processInfo.systemUptime < deadline)
        Thread.sleep(forTimeInterval: 0.001)
    }
}
func release(_ handle: UInt64) {
    let deadline = ProcessInfo.processInfo.systemUptime + 30
    while true {
        let status = sayaka_installer_release_v1(handle)
        if status == Int32(SAYAKA_OK.rawValue) { return }
        precondition(status == Int32(SAYAKA_BUSY.rawValue))
        precondition(ProcessInfo.processInfo.systemUptime < deadline)
        Thread.sleep(forTimeInterval: 0.001)
    }
}
func select(_ handle: UInt64, _ candidates: [Candidate]) -> UInt64 {
    var selection: UInt64 = 0
    candidates.map(\.reference.native).withUnsafeBufferPointer {
        check(sayaka_installer_selection_start_v1(handle, $0.baseAddress, $0.count, &selection))
    }
    return selection
}
func result(_ handle: UInt64) -> Data {
    copyJSON { sayaka_installer_result_v1(handle, $0, $1, $2) }
}

precondition(CommandLine.arguments.count == 2, "Supply an absolute owned installer fixture root")
let handle = start(CommandLine.arguments[1])
finish(handle, SAYAKA_SCAN_COMPLETE)
let discoveryData = result(handle)
var candidates: [Candidate] = []
var offset: UInt64 = 0
repeat {
    var request = pageRequest(offset, SAYAKA_SORT_NAME)
    let page: Query<Page> = try decode(copyJSON {
        sayaka_installer_candidates_v1(handle, &request, $0, $1, $2)
    })
    precondition(page.schemaVersion == 1 && page.taskHandle == String(handle))
    precondition(page.status == "complete" && page.complete && !page.executionAuthority && !page.effectsPerformed)
    precondition(page.data.offset == offset && page.data.total == 3)
    for candidate in page.data.candidates {
        var reference = candidate.reference.native
        let detail: Query<Candidate> = try decode(copyJSON {
            sayaka_installer_candidate_v1(handle, &reference, $0, $1, $2)
        })
        precondition(detail.data == candidate)
        candidates.append(candidate)
    }
    guard let next = page.data.nextOffset else { break }
    precondition(next > offset)
    offset = next
} while true
precondition(candidates.count == 3 && Set(candidates.map(\.reference.candidateId)).count == 3)
precondition(candidates.map(\.path.raw) == candidates.map(\.path.raw).sorted())
for sort in [SAYAKA_SORT_LOGICAL_SIZE, SAYAKA_SORT_ALLOCATED_SIZE] {
    let expected = candidates.sorted {
        let left = sort == SAYAKA_SORT_LOGICAL_SIZE ? $0.logicalBytes : $0.allocatedBytes
        let right = sort == SAYAKA_SORT_LOGICAL_SIZE ? $1.logicalBytes : $1.allocatedBytes
        if left != right {
            guard let left else { return false }
            guard let right else { return true }
            return left > right
        }
        return $0.path.raw < $1.path.raw
    }
    var sorted: [Candidate] = []
    for index in 0..<3 {
        var request = pageRequest(UInt64(index), sort)
        let page: Query<Page> = try decode(copyJSON {
            sayaka_installer_candidates_v1(handle, &request, $0, $1, $2)
        })
        sorted.append(contentsOf: page.data.candidates)
    }
    precondition(sorted == expected)
}
let recognized = candidates.filter(\.selectionCheckEligible)
precondition(recognized.count == 2)
let refused = select(handle, candidates)
finish(refused, SAYAKA_SCAN_PARTIAL)
let refusal = try JSONSerialization.jsonObject(with: result(refused)) as! [String: Any]
let refusalData = refusal["data"] as! [String: Any]
precondition(refusalData["status"] as? String == "refused")
precondition((refusalData["selected"] as! [Any]).count == candidates.count)
precondition(refusalData["batch_checks_passed"] as? Bool == false)
release(refused)
let selection = select(handle, recognized)
let refreshed = start(CommandLine.arguments[1])
var oldReference = recognized[0].reference.native
var invalid: UInt64 = 99
precondition(sayaka_installer_selection_start_v1(refreshed, &oldReference, 1, &invalid) ==
             Int32(SAYAKA_INVALID_CANDIDATE.rawValue) && invalid == 0)
release(refreshed)
release(handle)
finish(selection, SAYAKA_SCAN_COMPLETE)
let selectionData = result(selection)
let selected = try JSONSerialization.jsonObject(with: selectionData) as! [String: Any]
let checked = selected["data"] as! [String: Any]
precondition(checked["status"] as? String == "checked")
precondition(checked["execution_authority"] as? Bool == false && checked["effects_performed"] as? Bool == false)
precondition(checked["plan"] == nil && checked["approval"] == nil)
precondition((checked["selected"] as! [Any]).count == recognized.count)
release(selection)
let discovery = try JSONSerialization.jsonObject(with: discoveryData)
let output = try JSONSerialization.data(withJSONObject: ["discovery": discovery, "selection": selected])
try FileHandle.standardOutput.write(contentsOf: output)
