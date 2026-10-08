import Foundation
import XCTest
@testable import QuoternCore

final class SentinelTests: XCTestCase {
    static let sentinel = "QTN-SENTINEL-7f3a9c"
    static let now: Int64 = 1_775_124_000_000

    /// One record whose numeric fields are fixed and whose text sits where `placement` says.
    private func hostileRows(placement: String) -> [[String: Any]] {
        let hostile = Self.sentinel
        var data: [String: Any] = [
            "role": "assistant",
            "tokens": ["input": 10, "output": 20, "reasoning": 3, "cache": ["read": 4, "write": 5]],
        ]
        var identifier = "message-1"
        var session = "session-1"
        switch placement {
        case "content": data["content"] = "api_key=\(hostile)"
        case "model": data["modelID"] = hostile
        case "provider": data["providerID"] = hostile
        case "path": data["path"] = ["cwd": "/Users/\(hostile)", "root": "/\(hostile)"]
        case "id": identifier = "id-\(hostile)"
        case "session": session = "session-\(hostile)"
        default: XCTFail("unknown placement \(placement)")
        }
        return [["id": identifier, "session_id": session, "time_created": Self.now, "data": data]]
    }

    private func contains(_ bytes: Data) -> Bool {
        bytes.range(of: Data(Self.sentinel.utf8)) != nil
    }

    private func durableFiles(_ directory: String) throws -> [(name: String, bytes: Data)] {
        guard let walk = FileManager.default.enumerator(atPath: directory) else { return [] }
        var files: [(name: String, bytes: Data)] = []
        while let name = walk.nextObject() as? String {
            var isDirectory: ObjCBool = false
            let path = directory + "/" + name
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else { continue }
            files.append((name, try Data(contentsOf: URL(fileURLWithPath: path))))
        }
        return files
    }

    func testNoSentinelInLogResponsesErrorsOrDurableFiles() async throws {
        // Record and session identifiers are stored by design (event keys, session id <= 256 B),
        // so only text fields the store never persists are hostile placements here.
        for placement in ["content", "model", "provider", "path"] {
            try await run(placement: placement)
        }
    }

    private func run(placement: String) async throws {
        QuoternLog.reset()
        let world = try World(rows: hostileRows(placement: placement))
        let client = EngineClient()
        var observed: [String] = []
        func note(_ value: some Encodable) throws {
            observed.append(String(decoding: try JSONEncoder().encode(value), as: UTF8.self))
        }
        try await client.open(world.config)
        try note(try await client.setSourceSelection(world.selection()))
        try note(try await client.ingest(nowMs: Self.now))
        try note(try await client.listSources())
        let snapshot = try await client.todaySnapshot(tz: "UTC", nowMs: Self.now)
        try note(snapshot)
        XCTAssertEqual(snapshot.sourceReported.first?.input.value, 10, "\(placement): counted by numbers only")

        // Hostile request fields never echo into an error message.
        let source = world.source
        let rejected: [(String, () async throws -> Void)] = [
            ("tz", { _ = try await client.todaySnapshot(tz: "\(Self.sentinel)/Zone", nowMs: Self.now) }),
            ("harness", { _ = try await client.setSourceSelection(.init(harness: Self.sentinel, root: source, selected: true)) }),
            ("root", { _ = try await client.setSourceSelection(.init(harness: "opencode", root: "relative/\(Self.sentinel)", selected: true)) }),
            ("now", { _ = try await client.ingest(nowMs: -1) }),
        ]
        for (label, action) in rejected {
            do {
                try await action()
                XCTFail("\(label) must be rejected")
            } catch let error as BridgeError {
                observed.append(error.code + " " + error.message)
            }
        }
        await client.close()

        XCTAssertLessThan(QuoternLog.captured.count, 256, "\(placement): the capture stayed below its bound")
        for text in observed + QuoternLog.captured {
            XCTAssertFalse(text.contains(Self.sentinel), "\(placement): a sink leaked the sentinel: \(text.prefix(80))")
        }
        XCTAssertFalse(QuoternLog.captured.isEmpty, "the log capture is a scanned, non-empty sink")
        for line in QuoternLog.captured {
            XCTAssertEqual(line.split(separator: " ").count, 2, "operation and fixed code only: \(line)")
        }
        let files = try durableFiles(world.data)
        XCTAssertGreaterThan(files.count, 0, "at least the history file was scanned")
        for file in files {
            XCTAssertFalse(contains(file.bytes), "\(placement): \(file.name) holds the sentinel")
        }
    }

    func testCapturedLogIsBounded() {
        QuoternLog.reset()
        for index in 0..<257 {
            QuoternLog.record("line", code: "\(index)")
        }
        XCTAssertEqual(QuoternLog.captured, (1..<257).map { "line \($0)" }, "the 256 most recent lines, in order")
        QuoternLog.reset()
    }

    func testScannerRejectsAPlantedSentinel() {
        // Mutant control: the scan above is not vacuous.
        XCTAssertTrue(contains(Data("x \(Self.sentinel) y".utf8)))
        XCTAssertFalse(contains(Data("clean".utf8)))
    }
}
