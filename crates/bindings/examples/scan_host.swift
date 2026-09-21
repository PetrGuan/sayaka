// SPDX-License-Identifier: MPL-2.0
import Foundation

func check(_ code: Int32) {
    precondition(code == Int32(SAYAKA_OK.rawValue), String(cString: sayaka_status_message_v1(code)))
}

struct NodeReference: Decodable, Equatable {
    let taskHandle: String
    let nodeId: String
    var native: SayakaNodeRefV1 {
        guard let handle = UInt64(taskHandle), let id = UInt64(nodeId) else {
            preconditionFailure("Invalid native node reference")
        }
        return SayakaNodeRefV1(task_handle: handle, node_id: id)
    }
}

struct NativePath: Decodable, Equatable {
    let encoding: String
    let raw: String
}

struct DirectorySummary: Decodable, Equatable {
    let uniqueFiles: UInt64
    let logicalBytesKnown: UInt64
    let logicalBytesUnknownFiles: UInt64
    let allocatedBytesKnown: UInt64
    let allocatedBytesUnknownFiles: UInt64
    let complete: Bool
}

struct Node: Decodable, Equatable {
    let reference: NodeReference
    let resourceId: String
    let parent: NodeReference?
    let path: NativePath
    let kind: String
    let logicalBytes: UInt64?
    let allocatedBytes: UInt64?
    let directorySummary: DirectorySummary?
    let childCount: Int?
    let dataless: Bool
}

struct Page: Decodable {
    let offset: UInt64
    let total: Int
    let nextOffset: UInt64?
    let nodes: [Node]
}

struct Query<T: Decodable>: Decodable {
    let schemaVersion: Int
    let taskHandle: String
    let scanTaskId: String
    let scanStatus: String
    let scanComplete: Bool
    let observedIssues: Int
    let issuesOmitted: Int
    let data: T
}

struct DiagnosticIssue: Decodable, Equatable {
    let path: NativePath?
    let code: String
    let message: String
    let osCode: Int?
}

struct IssuePage: Decodable {
    let offset: UInt64
    let total: Int
    let nextOffset: UInt64?
    let issues: [DiagnosticIssue]
}

func query<T: Decodable>(
    _ operation: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>) -> Int32
) throws -> Query<T> {
    var needed = 0
    precondition(operation(nil, 0, &needed) == Int32(SAYAKA_BUFFER_TOO_SMALL.rawValue))
    precondition(needed > 0 && needed <= Int(SAYAKA_MAX_QUERY_BYTES_V1))
    var data = Data(count: needed)
    data.withUnsafeMutableBytes { bytes in
        check(operation(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &needed))
    }
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let result = try decoder.decode(Query<T>.self, from: data)
    precondition(result.schemaVersion == 1 && result.scanStatus == "complete" && result.scanComplete)
    return result
}

func pageRequest(offset: UInt64, sort: SayakaSortV1) -> SayakaPageRequestV1 {
    SayakaPageRequestV1(
        abi_version: 1,
        struct_size: UInt32(MemoryLayout<SayakaPageRequestV1>.size),
        offset: offset, limit: 17, sort: sort.rawValue
    )
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
precondition(MemoryLayout<SayakaIssuePageRequestV1>.size == 24)
var issueOffset: UInt64 = 0
var issuePages: [DiagnosticIssue] = []
var issueMetadata: Query<IssuePage>?
repeat {
    var request = SayakaIssuePageRequestV1(
        abi_version: 1, struct_size: UInt32(MemoryLayout<SayakaIssuePageRequestV1>.size),
        offset: issueOffset, limit: 17, reserved: 0
    )
    let page: Query<IssuePage> = try query { sayaka_scan_issues_v1(handle, &request, $0, $1, $2) }
    precondition(page.taskHandle == String(handle) && page.data.offset == issueOffset)
    precondition(page.data.total == page.observedIssues && page.data.issues.count <= 17)
    if let first = issueMetadata {
        precondition(page.scanTaskId == first.scanTaskId && page.observedIssues == first.observedIssues
                     && page.issuesOmitted == first.issuesOmitted)
    } else {
        issueMetadata = page
    }
    issuePages.append(contentsOf: page.data.issues)
    guard let next = page.data.nextOffset else { break }
    precondition(next == issueOffset + UInt64(page.data.issues.count) && next > issueOffset)
    issueOffset = next
} while true
precondition(issuePages.count == issueMetadata?.observedIssues)
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
let issueDecoder = JSONDecoder()
issueDecoder.keyDecodingStrategy = .convertFromSnakeCase
let reportIssues = try issueDecoder.decode(
    [DiagnosticIssue].self, from: JSONSerialization.data(withJSONObject: result["issues"]!)
)
precondition(issuePages == reportIssues)
precondition(issueMetadata?.scanTaskId == result["task_id"] as? String)
precondition(issueMetadata?.issuesOmitted == result["issues_omitted"] as? Int)
var rootsRequest = pageRequest(offset: 0, sort: SAYAKA_SORT_NAME)
let roots: Query<Page> = try query {
    sayaka_scan_roots_v1(handle, &rootsRequest, $0, $1, $2)
}
precondition(roots.taskHandle == String(handle) && roots.data.total == 1 && roots.data.nextOffset == nil)
let rootNode = roots.data.nodes[0]
precondition(rootNode.parent == nil && rootNode.kind == "directory")
precondition(rootNode.path.encoding == "unix_bytes_hex")
precondition(rootNode.path.raw == pathBytes.map { String(format: "%02x", $0) }.joined())
let totals = result["totals"] as! [String: Any]
precondition(rootNode.logicalBytes == (totals["logical_bytes_known"] as! NSNumber).uint64Value)
precondition(rootNode.directorySummary?.uniqueFiles == (totals["unique_files"] as! NSNumber).uint64Value)
let entries = result["entries"] as! [[String: Any]]
let byID = Dictionary(uniqueKeysWithValues: entries.map { ($0["resource_id"] as! String, $0) })
var directories = [rootNode]
var observed = Set([rootNode.resourceId])
while let directory = directories.popLast() {
    var parent = directory.reference.native
    var namedNodes: [Node] = []
    var offset: UInt64 = 0
    repeat {
        var request = pageRequest(offset: offset, sort: SAYAKA_SORT_NAME)
        let page: Query<Page> = try query {
            sayaka_scan_children_v1(handle, &parent, &request, $0, $1, $2)
        }
        precondition(page.data.offset == offset && page.data.total == directory.childCount)
        precondition(page.taskHandle == roots.taskHandle && page.scanTaskId == roots.scanTaskId)
        for node in page.data.nodes {
            precondition(node.parent == directory.reference && observed.insert(node.resourceId).inserted)
            let entry = byID[node.resourceId]!
            let path = entry["path"] as! [String: Any]
            precondition(node.path.raw == path["raw"] as? String && node.kind == entry["kind"] as? String)
            var reference = node.reference.native
            let detail: Query<Node> = try query { sayaka_scan_node_v1(handle, &reference, $0, $1, $2) }
            precondition(detail.data == node)
            if node.kind == "directory" { directories.append(node) }
            namedNodes.append(node)
        }
        guard let next = page.data.nextOffset else { break }
        precondition(next > offset)
        offset = next
    } while true
    precondition(namedNodes.map(\.path.raw) == namedNodes.map(\.path.raw).sorted())
    for sort in [SAYAKA_SORT_LOGICAL_SIZE, SAYAKA_SORT_ALLOCATED_SIZE] {
        let expected = namedNodes.sorted {
            let left = sort == SAYAKA_SORT_LOGICAL_SIZE ? $0.logicalBytes : $0.allocatedBytes
            let right = sort == SAYAKA_SORT_LOGICAL_SIZE ? $1.logicalBytes : $1.allocatedBytes
            if left != right {
                guard let left else { return false }
                guard let right else { return true }
                return left > right
            }
            return $0.path.raw < $1.path.raw
        }
        var sortedNodes: [Node] = []
        offset = 0
        repeat {
            var request = pageRequest(offset: offset, sort: sort)
            let page: Query<Page> = try query {
                sayaka_scan_children_v1(handle, &parent, &request, $0, $1, $2)
            }
            sortedNodes.append(contentsOf: page.data.nodes)
            guard let next = page.data.nextOffset else { break }
            precondition(next > offset)
            offset = next
        } while true
        precondition(sortedNodes == expected)
    }
}
precondition(observed == Set(byID.keys))
check(sayaka_scan_release_v1(handle))
precondition(sayaka_scan_poll_v1(handle, &snapshot) == Int32(SAYAKA_INVALID_HANDLE.rawValue))
var staleRoot = rootNode.reference.native
precondition(sayaka_scan_node_v1(handle, &staleRoot, nil, 0, &required) == Int32(SAYAKA_INVALID_HANDLE.rawValue))
var staleIssues = SayakaIssuePageRequestV1(
    abi_version: 1, struct_size: UInt32(MemoryLayout<SayakaIssuePageRequestV1>.size),
    offset: 0, limit: 1, reserved: 0
)
precondition(sayaka_scan_issues_v1(handle, &staleIssues, nil, 0, &required) ==
             Int32(SAYAKA_INVALID_HANDLE.rawValue) && required == 0)
try FileHandle.standardOutput.write(contentsOf: data)
