import CQuotern
import Foundation
import os
import XCTest
@testable import QuoternCore

// MARK: - Shared support (internal to the test target)

enum Support {
    static let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    static func data(_ relative: String) throws -> Data {
        try Data(contentsOf: root.appendingPathComponent(relative))
    }

    static func json(_ relative: String) throws -> Any {
        try JSONSerialization.jsonObject(with: data(relative))
    }

    static func text(_ relative: String) throws -> String {
        try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
    }

    static func dailyRows() throws -> [[String: Any]] {
        let file = try json("Fixtures/harness/opencode/daily/rows.json") as? [String: Any]
        return try XCTUnwrap(file?["legacy_messages"] as? [[String: Any]])
    }

    static func expectedCase(_ name: String) throws -> [String: Any] {
        let file = try XCTUnwrap(json("Fixtures/harness/opencode/daily/expected.json") as? [String: Any])
        let cases = try XCTUnwrap(file["cases"] as? [[String: Any]])
        return try XCTUnwrap(cases.first { $0["name"] as? String == name }, "case \(name)")
    }

    static func expectedCaseNames() throws -> [String] {
        let file = try XCTUnwrap(json("Fixtures/harness/opencode/daily/expected.json") as? [String: Any])
        return try XCTUnwrap(file["cases"] as? [[String: Any]]).compactMap { $0["name"] as? String }
    }

    static let fields = ["input", "output", "reasoning", "cache_read", "cache_write", "total"]

    /// The hand-written four-key oracle of a case in the full observation shape: its acquired
    /// status becomes completeness (current → complete, partial → partial, unavailable → null).
    /// `status` and `last_good_ms` are Rust's lifecycle at the request instant; the oracle
    /// fixes them only through the arguments.
    static func oracle(_ name: String, sourceId: String, status: String, lastGoodMs: Int64?) throws -> SourceReported {
        let entry = try expectedCase(name)
        var reported = try XCTUnwrap(entry["source_reported"] as? [String: Any])
        reported["source_id"] = sourceId
        for field in fields {
            var observation = try XCTUnwrap(reported[field] as? [String: Any], field)
            let acquired = try XCTUnwrap(observation["status"] as? String, field)
            let completeness: Any = ["current": "complete", "partial": "partial"][acquired] ?? NSNull()
            observation["completeness"] = completeness
            observation["status"] = observation["value"] is NSNull ? "unavailable" : status
            observation["last_good_ms"] = lastGoodMs.map { NSNumber(value: $0) } ?? NSNull()
            reported[field] = observation
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(SourceReported.self, from: JSONSerialization.data(withJSONObject: reported))
    }

    /// The oracle as a snapshot at the instant of the source's last success presents it: present
    /// values `current`, last good at the case's own `now_ms`.
    static func reported(_ name: String, sourceId: String) throws -> SourceReported {
        try oracle(name, sourceId: sourceId, status: "current", lastGoodMs: nowMs(name))
    }

    /// Only what Rust acquired: every observation without its lifecycle status and last-good
    /// instant, for comparisons across request instants.
    static func acquired(_ reported: SourceReported) -> [String] {
        let observations = [reported.input, reported.output, reported.reasoning, reported.cacheRead, reported.cacheWrite, reported.total]
        return ["\(reported.sourceId) \(reported.records) \(reported.sourceConvention ?? "-") \(reported.acquisitionConsistency ?? "-") \(reported.originUncertainty) \(reported.totalMismatch) \(reported.mirrorConflict) \(reported.pendingPartial)"]
            + observations.map { "\($0.value.map(String.init) ?? "null") \($0.unit) \($0.provenance?.rawValue ?? "null") \($0.completeness?.rawValue ?? "null")" }
    }

    static func acquired(_ name: String, sourceId: String) throws -> [String] {
        acquired(try oracle(name, sourceId: sourceId, status: "current", lastGoodMs: nil))
    }

    /// The error an error golden of `Contracts/bridge-v1` decodes to.
    static func decodedError(_ golden: String) throws -> BridgeError {
        let bytes = Array(try data("Contracts/bridge-v1/\(golden)"))
        do throws(BridgeError) {
            _ = try Envelope.decode(bytes, as: TodaySnapshot.self)
        } catch {
            return error
        }
        struct NotAnErrorGolden: Error {}
        throw NotAnErrorGolden()
    }

    static func nowMs(_ name: String) throws -> Int64 {
        try XCTUnwrap(expectedCase(name)["now_ms"] as? Int64)
    }

    static func canonicalTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("quotern-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url.resolvingSymlinksInPath()
    }

    /// SHA-256 of a file, through `/usr/bin/shasum`.
    static func sha256(of path: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        process.arguments = ["-a", "256", path]
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        return String(text.prefix(64))
    }

    static func remove(_ url: URL) {
        let manager = FileManager.default
        if let walk = manager.enumerator(atPath: url.path) {
            for case let name as String in walk {
                _ = chmod(url.appendingPathComponent(name).path, 0o755)
            }
        }
        _ = chmod(url.path, 0o755)
        try? manager.removeItem(at: url)
    }

    static func schema(keepPragmas: Bool) throws -> String {
        try text("Fixtures/harness/opencode/wal/schema.sql")
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { keepPragmas || !$0.trimmingCharacters(in: .whitespaces).hasPrefix("PRAGMA") }
            .joined(separator: "\n")
    }

    static func inserts(_ rows: [[String: Any]]) throws -> String {
        try rows.map { row in
            let payload = try JSONSerialization.data(withJSONObject: row["data"] as Any, options: [.sortedKeys])
            let hex = payload.map { String(format: "%02x", $0) }.joined()
            let id = try XCTUnwrap(row["id"] as? String)
            let session = try XCTUnwrap(row["session_id"] as? String)
            let created = try XCTUnwrap(row["time_created"] as? Int64)
            return "INSERT INTO message(id, session_id, time_created, data) VALUES('\(id)', '\(session)', \(created), X'\(hex)');"
        }.joined(separator: "\n")
    }

    /// Runs `/usr/bin/sqlite3` on `database` to completion.
    static func sqlite(_ database: String, script: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [database]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output
        try process.run()
        input.fileHandleForWriting.write(Data(script.utf8))
        try input.fileHandleForWriting.close()
        let log = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: log, as: UTF8.self))
    }

    static func bulkRows(_ count: Int, base: Int64) -> [[String: Any]] {
        (0..<count).map { index in
            [
                "id": "m\(index)", "session_id": "s", "time_created": base + Int64(index),
                "data": ["role": "assistant", "tokens": ["input": 1, "output": 0, "reasoning": 0, "cache": ["read": 0, "write": 0], "total": 1]],
            ] as [String: Any]
        }
    }
}

/// An isolated base directory holding `data` (never created by the test), `home` and `opencode`.
final class World {
    let base: URL
    var data: String { base.appendingPathComponent("data").path }
    var home: String { base.appendingPathComponent("home").path }
    var source: String { base.appendingPathComponent("opencode").path }
    var config: EngineConfig { EngineConfig(dataDir: data, home: home) }

    init(rows: [[String: Any]]) throws {
        base = try Support.canonicalTemporaryDirectory()
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(atPath: source, withIntermediateDirectories: false)
        try Support.sqlite(
            source + "/opencode.db",
            script: Support.schema(keepPragmas: false) + "\nBEGIN;\n" + Support.inserts(rows) + "\nCOMMIT;\n"
        )
    }

    deinit { Support.remove(base) }

    func selection(_ selected: Bool = true) -> SourceSelection {
        SourceSelection(harness: "opencode", root: source, selected: selected)
    }
}

/// A real selected Codex source in an isolated home, shared by client, watcher and sink tests.
final class CodexWorld {
    let base: URL
    var home: String { base.appendingPathComponent("home").path }
    var source: String { base.appendingPathComponent("codex-home").path }
    var data: String { base.appendingPathComponent("data").path }
    var config: EngineConfig { EngineConfig(dataDir: data, home: home) }
    var selection: SourceSelection { SourceSelection(harness: "codex", root: source, selected: true) }
    var rollout: URL { URL(fileURLWithPath: source + "/sessions/2026/09/30/rollout-2026-09-30T09-00-00-journey.jsonl") }

    init() throws {
        base = try Support.canonicalTemporaryDirectory()
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: false)
        try FileManager.default.copyItem(at: Support.root.appendingPathComponent("Fixtures/journey-home/.codex"), to: URL(fileURLWithPath: source))
    }

    deinit { Support.remove(base) }
}

/// A controlled `/usr/bin/sqlite3` writer child: stdin piped, applies the schema in WAL mode and
/// stays open, so `-wal` and `-shm` exist until `quit()`.
final class WalWriter: Sendable {
    let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let seen = OSAllocatedUnfairLock(initialState: Data())

    init(database: String, rows: [[String: Any]]) throws {
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [database]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output
        let ready = DispatchSemaphore(value: 0)
        let marker = Data("QUOTERN_WRITER_READY".utf8)
        output.fileHandleForReading.readabilityHandler = { [self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            let found = seen.withLock { seen in
                seen.append(chunk)
                return seen.range(of: marker) != nil
            }
            if found { ready.signal() }
        }
        try process.run()
        let script = try Support.schema(keepPragmas: true) + "\nBEGIN;\n" + Support.inserts(rows)
            + "\nCOMMIT;\n.print QUOTERN_WRITER_READY\n"
        input.fileHandleForWriting.write(Data(script.utf8))
        guard ready.wait(timeout: .now() + 20) == .success else {
            process.terminate()
            throw BridgeError(code: "test", message: "writer did not become ready", retryable: false)
        }
    }

    var running: Bool { process.isRunning }

    /// Ends the writer cleanly and returns its exit status.
    @discardableResult
    func quit() -> Int32 {
        guard process.isRunning else { return process.terminationStatus }
        input.fileHandleForWriting.write(Data(".quit\n".utf8))
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
        output.fileHandleForReading.readabilityHandler = nil
        return process.terminationStatus
    }
}

/// A raw engine handle for tests that call the exports directly.
final class RawEngine {
    private(set) var engine: OpaquePointer?

    init(config: EngineConfig) throws {
        let (_, out) = RawEngine.open(EngineClient.encode(config))
        engine = out
    }

    deinit { quotern_engine_close(engine) }

    /// Opens with an arbitrary config and returns the envelope and the out handle.
    static func open(_ config: String) -> ([String: Any], OpaquePointer?) {
        var out: OpaquePointer? = OpaquePointer(bitPattern: 1)
        let pointer = config.withCString { quotern_engine_open($0, &out) }
        return (envelope(take(pointer)), out)
    }

    static func take(_ pointer: UnsafeMutablePointer<CChar>?) -> [UInt8] {
        guard let pointer else {
            XCTFail("an export returned NULL")
            return []
        }
        let bytes = Array(UnsafeBufferPointer(start: UnsafeRawPointer(pointer).assumingMemoryBound(to: UInt8.self), count: strlen(pointer)))
        quotern_string_free(pointer)
        return bytes
    }

    static func envelope(_ bytes: [UInt8]) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any])
            ?? ["unparsed": String(decoding: bytes, as: UTF8.self)]
    }

    static func errorTriple(_ envelope: [String: Any]) -> String {
        guard let error = envelope["error"] as? [String: Any] else { return "<no error: \(envelope)>" }
        return "\(error["code"] ?? "?")|\(error["message"] ?? "?")|\((error["retryable"] as? Bool).map(String.init) ?? "?")"
    }

    /// `nil` passes NULL; otherwise the bytes are passed NUL-terminated.
    func callPointer(_ method: [UInt8]?, _ request: [UInt8]?, cancel: OpaquePointer? = nil) -> UnsafeMutablePointer<CChar>? {
        func withBytes<R>(_ bytes: [UInt8]?, _ body: (UnsafePointer<CChar>?) -> R) -> R {
            guard let bytes else { return body(nil) }
            let terminated = bytes + [0]
            return terminated.withUnsafeBufferPointer { buffer in
                buffer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: terminated.count) { body($0) }
            }
        }
        return withBytes(method) { methodPointer in
            withBytes(request) { requestPointer in
                quotern_call(engine, methodPointer, requestPointer, cancel)
            }
        }
    }

    func call(_ method: [UInt8]?, _ request: [UInt8]?, cancel: OpaquePointer? = nil) -> [String: Any] {
        RawEngine.envelope(RawEngine.take(callPointer(method, request, cancel: cancel)))
    }

    func call(_ method: String, _ request: String) -> [String: Any] {
        call(Array(method.utf8), Array(request.utf8))
    }
}

// swiftlint:disable identifier_name
// The README example fixes the names d, h, r, t, z, c and s; they are kept verbatim.
// MARK: - Live round trips

final class BridgeRoundTripTests: XCTestCase {
    /// The lines strictly between two marker lines of `text`, with their common indentation
    /// removed.
    static func region(_ text: String, from begin: String, to end: String) throws -> String {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let trimmed = lines.map { $0.trimmingCharacters(in: .whitespaces) }
        let first = try XCTUnwrap(trimmed.firstIndex(of: begin), begin)
        let last = try XCTUnwrap(trimmed[first...].firstIndex(of: end), end)
        let body = lines[(first + 1)..<last]
        let indent = body.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .map { $0.prefix { $0 == " " }.count }.min() ?? 0
        return body.map { String($0.dropFirst(min(indent, $0.prefix { $0 == " " }.count))) }
            .joined(separator: "\n")
    }

    func testFirstUseExample() async throws {
        // The executed regions below equal the README's setup and calls blocks.
        let readme = try Support.text("Contracts/bridge-v1/README.md")
        let heading = try XCTUnwrap(readme.range(of: "## First success"))
        let firstSuccess = String(readme[heading.lowerBound...])
        let blocks = firstSuccess.components(separatedBy: "```swift\n").dropFirst()
            .map { String($0[..<($0.range(of: "\n```")?.lowerBound ?? $0.endIndex)]) }
        XCTAssertEqual(blocks.count, 2, "the README has a setup and a calls block")
        let own = try String(contentsOfFile: #filePath, encoding: .utf8)
        XCTAssertEqual(try Self.region(own, from: "// README setup {", to: "// } README setup"), blocks.first)
        XCTAssertEqual(try Self.region(own, from: "// README calls {", to: "// } README calls"), blocks.last)

        // README setup {
        let base = try Support.canonicalTemporaryDirectory()  // a fresh temporary directory
        let d = base.appendingPathComponent("data").path      // absent; the caller never creates it
        let h = base.appendingPathComponent("home").path      // created empty
        let r = base.appendingPathComponent("opencode").path  // the sanitized daily fixture source
        let t: Int64 = 1_775_124_000_000                      // now_ms of utc_counters
        let z = "UTC"                                         // tz of utc_counters
        try FileManager.default.createDirectory(atPath: h, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(atPath: r, withIntermediateDirectories: false)
        let writer = try WalWriter(database: r + "/opencode.db", rows: Support.dailyRows())
        defer {
            writer.quit()
            Support.remove(base)
        }
        // } README setup

        // README calls {
        func firstUse(_ r: String) async throws -> TodaySnapshot {
            let c = EngineClient()
            do {
                try await c.open(.init(dataDir: d, home: h))
                _ = try await c.setSourceSelection(.init(harness: "opencode", root: r, selected: true))
                _ = try await c.ingest(nowMs: t)
                let s = try await c.todaySnapshot(tz: z, nowMs: t)
                await c.close()
                return s
            } catch {
                await c.close()
                throw error
            }
        }
        // } README calls

        let oracleName = "utc_counters"
        XCTAssertEqual(try Support.nowMs(oracleName), t, "t is the case's now_ms")
        XCTAssertEqual(try Support.expectedCase(oracleName)["tz"] as? String, z, "z is the case's tz")
        XCTAssertTrue(writer.running)
        XCTAssertFalse(FileManager.default.fileExists(atPath: d), "the caller never creates the data dir")

        let before = FFICounters.shared.current
        // A relative root throws invalid_request yet closes the handle.
        do {
            _ = try await firstUse("relative")
            XCTFail("a relative root must throw")
        } catch let error as BridgeError {
            XCTAssertEqual(error, BridgeError(code: "invalid_request", message: "invalid request: root", retryable: false))
        }
        let afterThrow = FFICounters.shared.current
        XCTAssertEqual(afterThrow.handlesOpened - before.handlesOpened, 1)
        XCTAssertEqual(afterThrow.handlesClosed - before.handlesClosed, 1)

        XCTAssertTrue(writer.running, "the writer runs before ingest")
        XCTAssertTrue(FileManager.default.fileExists(atPath: r + "/opencode.db-wal"), "-wal present before ingest")
        XCTAssertTrue(FileManager.default.fileExists(atPath: r + "/opencode.db-shm"), "-shm present before ingest")
        let s = try await firstUse(r)
        XCTAssertTrue(writer.running, "the writer runs through ingest")
        XCTAssertTrue(FileManager.default.fileExists(atPath: r + "/opencode.db-wal"))
        let after = FFICounters.shared.current
        XCTAssertEqual(after.handlesOpened - before.handlesOpened, 2)
        XCTAssertEqual(after.handlesClosed - before.handlesClosed, 2, "opened == closed")
        XCTAssertEqual(s.sourceReported.count, 1)
        XCTAssertEqual(s.sourceReported, [try Support.reported(oracleName, sourceId: s.sourceReported[0].sourceId)])
        XCTAssertEqual(writer.quit(), 0, "writer exit 0")
    }

    func testWriterStoppedBeforeIngestGivesSourceIdleNeverTheOracle() async throws {
        let base = try Support.canonicalTemporaryDirectory()
        defer { Support.remove(base) }
        let home = base.appendingPathComponent("home").path
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: false)
        let source = base.appendingPathComponent("opencode").path
        try FileManager.default.createDirectory(atPath: source, withIntermediateDirectories: false)
        let database = source + "/opencode.db"
        let fixtureRows = try Support.dailyRows()
        let writer = try WalWriter(database: database, rows: fixtureRows)
        XCTAssertEqual(writer.quit(), 0, "the writer stopped under control with exit 0")

        // The stopped database is in WAL format: bytes 18 and 19 of the main header are 2.
        let header = try Data(contentsOf: URL(fileURLWithPath: database)).prefix(100)
        XCTAssertEqual(Array(header[18...19]), [2, 2], "write and read format versions are WAL")

        // The macOS sqlite3 leaves empty sidecars after a clean stop. `-wal` is asserted absent
        // or empty before any removal, each sidecar is removed only if it exists, and the result
        // is the S2 file state: no `-wal`, `-shm` or `-journal`.
        let manager = FileManager.default
        let wal = database + "-wal"
        if manager.fileExists(atPath: wal) {
            let size = try XCTUnwrap(manager.attributesOfItem(atPath: wal)[.size] as? Int)
            XCTAssertEqual(size, 0, "-wal holds no frames before its removal")
        }
        for sidecar in ["-wal", "-shm", "-journal"] where manager.fileExists(atPath: database + sidecar) {
            try manager.removeItem(atPath: database + sidecar)
        }
        func fileState() -> [Bool] {
            ["-wal", "-shm", "-journal"].map { manager.fileExists(atPath: database + $0) }
        }
        let digest = try Support.sha256(of: database)
        XCTAssertEqual(fileState(), [false, false, false], "no sidecar before ingest")
        let t = try Support.nowMs("utc_counters")

        let client = EngineClient()
        try await client.open(.init(dataDir: base.path + "/data", home: home))
        _ = try await client.setSourceSelection(.init(harness: "opencode", root: source, selected: true))
        let entries = try await client.ingest(nowMs: t)
        let snapshot = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        await client.close()
        XCTAssertEqual(fileState(), [false, false, false], "no sidecar recreated by ingest")
        XCTAssertEqual(try Support.sha256(of: database), digest, "the main database is byte-unchanged")
        XCTAssertEqual(entries.first?.outcome, "unavailable")
        XCTAssertEqual(entries.first?.lastErrorCode, "source_idle")
        XCTAssertEqual(snapshot.bySource.first?.lastErrorCode, "source_idle")
        let reported = try XCTUnwrap(snapshot.sourceReported.first)
        XCTAssertEqual(reported.records, 0)
        XCTAssertGreaterThan(fixtureRows.count, 0, "the source really holds records")
        XCTAssertNotEqual(reported, try Support.reported("utc_counters", sourceId: reported.sourceId), "not the oracle")
    }

    func testLiveDailyCasesEqualOracles() async throws {
        let world = try World(rows: Support.dailyRows())
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        let names = try Support.expectedCaseNames()
        XCTAssertGreaterThanOrEqual(names.count, 5)
        _ = try await client.ingest(nowMs: Support.nowMs("utc_counters"))
        for name in names {
            let entry = try Support.expectedCase(name)
            let zone = try XCTUnwrap(entry["tz"] as? String)
            let now = try XCTUnwrap(entry["now_ms"] as? Int64)
            let snapshot = try await client.todaySnapshot(tz: zone, nowMs: now)
            let window = try XCTUnwrap(entry["window"] as? [String: Any])
            XCTAssertEqual(snapshot.window.startMs, window["start_ms"] as? Int64, name)
            XCTAssertEqual(snapshot.window.endMs, window["end_ms"] as? Int64, name)
            XCTAssertEqual(snapshot.window.tz, zone, name)
            let reported = try XCTUnwrap(snapshot.sourceReported.first, name)
            XCTAssertEqual(Support.acquired(reported), try Support.acquired(name, sourceId: reported.sourceId), name)
        }
        await client.close()
    }

    func testLiveCloseReopenRetainsTotals() async throws {
        let world = try World(rows: Support.dailyRows())
        let t = try Support.nowMs("utc_counters")
        let before = FFICounters.shared.current
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        _ = try await client.ingest(nowMs: t)
        let first = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        let id = try XCTUnwrap(first.sourceReported.first?.sourceId)
        XCTAssertEqual(first.sourceReported, [try Support.reported("utc_counters", sourceId: id)])

        try await client.reopen()
        let reopened = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        XCTAssertEqual(reopened.sourceReported, first.sourceReported, "reopen retains the exact totals before any ingest")
        XCTAssertEqual(reopened.bySource.first?.lastSuccessMs, first.bySource.first?.lastSuccessMs)
        _ = try await client.ingest(nowMs: t + 600_000)
        let replayed = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        XCTAssertEqual(replayed.sourceReported.map(Support.acquired), first.sourceReported.map(Support.acquired), "replay adds zero")
        XCTAssertEqual(replayed.sourceReported.first?.total.status, .stale, "a success after the request instant is never current")
        await client.close()
        await client.close()
        let after = FFICounters.shared.current
        XCTAssertEqual(after.handlesOpened - before.handlesOpened, 2)
        XCTAssertEqual(after.handlesClosed - before.handlesClosed, 2)
    }

    /// A durable unattached source reads its whole history. The ABI has no read by source id,
    /// so the unknown-id half (`StoreError::InvalidRoot`) is proven only in Rust
    /// `reported_today::durable_unattached_reads_history_unknown_id_rejected`.
    private func assertDurableUnattachedReadsHistory() async throws {
        let world = try World(rows: Support.dailyRows())
        let t = try Support.nowMs("utc_counters")
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        _ = try await client.ingest(nowMs: t)
        let durable = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        await client.close()

        let parked = world.base.appendingPathComponent("parked").path
        try FileManager.default.moveItem(atPath: world.source, toPath: parked)
        try await client.open(world.config)
        let unattached = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        let entry = try XCTUnwrap(unattached.bySource.first)
        XCTAssertEqual(entry.outcome, "unavailable")
        XCTAssertEqual(entry.lastErrorCode, "root_invalid")
        XCTAssertNil(entry.lastAttemptMs)
        XCTAssertEqual(entry.lastSuccessMs, durable.bySource.first?.lastSuccessMs)
        XCTAssertEqual(unattached.sourceReported.map(Support.acquired), durable.sourceReported.map(Support.acquired), "durable unattached reads history")
        XCTAssertEqual(unattached.sourceReported.first?.total.status, .error, "an unattached failure is never current")
        XCTAssertEqual(unattached.sourceReported.first?.total.lastGoodMs, t)

        _ = try await client.ingest(nowMs: t + 5)
        let retried = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        XCTAssertEqual(retried.bySource.first?.lastAttemptMs, t + 5)
        try FileManager.default.moveItem(atPath: parked, toPath: world.source)
        _ = try await client.ingest(nowMs: t + 10)
        let back = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        XCTAssertNil(back.bySource.first?.lastErrorCode)
        XCTAssertEqual(back.sourceReported.map(Support.acquired), durable.sourceReported.map(Support.acquired))
        await client.close()
    }
}

extension BridgeRoundTripTests {
    func testSelectionOutsideImplementedSetLeavesStoreUnchanged() async throws {
        let world = try World(rows: Support.dailyRows())
        let client = EngineClient()
        try await client.open(world.config)
        for selection in [
            SourceSelection(harness: "cursor", root: world.source, selected: true),
            SourceSelection(harness: "opencode", root: "relative", selected: true),
            SourceSelection(harness: "opencode", root: world.source, selected: false),
        ] {
            do {
                _ = try await client.setSourceSelection(selection)
                XCTFail("must throw")
            } catch {
                XCTAssertEqual(error.code, "invalid_request")
                XCTAssertFalse(error.retryable)
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: world.data), "nothing created")
        let empty = try await client.listSources()
        XCTAssertTrue(empty.isEmpty)
        let snapshot = try await client.todaySnapshot(tz: "UTC", nowMs: 1_775_124_000_000)
        XCTAssertTrue(snapshot.bySource.isEmpty)
        XCTAssertTrue(snapshot.sourceReported.isEmpty)
        await client.close()
    }

    func testReturnedStringsAndTokensFreedOnce() async throws {
        let world = try World(rows: Support.dailyRows())
        let t = try Support.nowMs("utc_counters")
        let before = FFICounters.shared.current
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        _ = try await client.ingest(nowMs: t)
        _ = try await client.listSources()
        _ = try await client.todaySnapshot(tz: "UTC", nowMs: t)
        do {
            _ = try await client.todaySnapshot(tz: "Nowhere/Zone", nowMs: t)
            XCTFail("an unknown zone must throw")
        } catch {
            XCTAssertEqual(error.code, "invalid_request")
        }
        await client.close()
        let after = FFICounters.shared.current
        XCTAssertEqual(after.openCalls - before.openCalls, 1)
        XCTAssertEqual(after.calls - before.calls, 5)
        XCTAssertEqual(after.entries - before.entries, 6, "one open string and five call strings")
        XCTAssertEqual(after.frees - before.frees, after.entries - before.entries, "returned == freed")
        XCTAssertEqual(after.tokensNew - before.tokensNew, 5)
        XCTAssertEqual(after.tokensFree - before.tokensFree, 5, "cancel new == free")
        XCTAssertEqual(after.handlesOpened - before.handlesOpened, 1)
        XCTAssertEqual(after.handlesClosed - before.handlesClosed, 1)
    }

    func testFirstUseWireSizeBoundary() throws {
        let world = try World(rows: [])
        /// A config of exactly `total` bytes whose `data_dir` takes the padding.
        func config(_ total: Int) -> String {
            let fixed = "{\"data_dir\":\"/\",\"home\":\"/h\"}".utf8.count
            return "{\"data_dir\":\"/\(String(repeating: "a", count: total - fixed))\",\"home\":\"/h\"}"
        }
        XCTAssertEqual(config(65_536).utf8.count, 65_536)
        XCTAssertEqual(config(65_537).utf8.count, 65_537)
        // 65,536 B reaches field validation (its data_dir is over 4,096 B); 65,537 B does not.
        var (response, out) = RawEngine.open(config(65_536))
        XCTAssertNil(out)
        XCTAssertEqual(RawEngine.errorTriple(response), "invalid_request|invalid request: data_dir|false")
        (response, out) = RawEngine.open(config(65_537))
        XCTAssertNil(out)
        XCTAssertEqual(RawEngine.errorTriple(response), "limit_exceeded|limit exceeded: config_bytes|false")
        (response, out) = RawEngine.open("{\"data_dir\":\"/x\",\"home\":\"/h\",\"extra\":1}")
        XCTAssertNil(out)
        XCTAssertEqual(RawEngine.errorTriple(response), "invalid_request|invalid request: config|false")
        let field = "/" + String(repeating: "a", count: 4_096)
        XCTAssertEqual(field.utf8.count, 4_097)
        (response, out) = RawEngine.open("{\"data_dir\":\"\(field)\",\"home\":\"/h\"}")
        XCTAssertNil(out)
        XCTAssertEqual(RawEngine.errorTriple(response), "invalid_request|invalid request: data_dir|false")

        let engine = try RawEngine(config: world.config)
        XCTAssertNotNil(engine.engine)
        func padded(_ count: Int) -> [UInt8] {
            Array("{\"pad\":\"".utf8) + [UInt8](repeating: UInt8(ascii: "a"), count: count - 10) + Array("\"}".utf8)
        }
        let list = Array("list_sources".utf8)
        let empty = Array("{}".utf8)
        // 65,536 B reaches field validation; 65,537 B does not.
        XCTAssertEqual(padded(65_536).count, 65_536)
        XCTAssertEqual(RawEngine.errorTriple(engine.call(list, padded(65_536))), "invalid_request|invalid request: request|false")
        XCTAssertEqual(
            RawEngine.errorTriple(engine.call(list, padded(65_537))), "limit_exceeded|limit exceeded: request_bytes|false")
        // A 64 B unregistered method reaches recognition; 65 B does not, whatever else is wrong.
        XCTAssertEqual(
            RawEngine.errorTriple(engine.call([UInt8](repeating: UInt8(ascii: "m"), count: 64), empty)),
            "unknown_method|unknown method|false")
        let method65 = [UInt8](repeating: UInt8(ascii: "m"), count: 65)
        let methodBytes = "limit_exceeded|limit exceeded: method_bytes|false"
        XCTAssertEqual(RawEngine.errorTriple(engine.call(method65, empty)), methodBytes)
        XCTAssertEqual(RawEngine.errorTriple(engine.call(method65, padded(65_537))), methodBytes)
        XCTAssertEqual(RawEngine.errorTriple(engine.call(method65, [0xFF])), methodBytes)
        // 4,097 B field, invalid UTF-8 and an unknown key are invalid_request.
        let zone = "{\"tz\":\"\(field)\",\"now_ms\":1775124000000}"
        let request = "invalid_request|invalid request: request|false"
        XCTAssertEqual(RawEngine.errorTriple(engine.call("today_snapshot", zone)), "invalid_request|invalid request: tz|false")
        XCTAssertEqual(RawEngine.errorTriple(engine.call(list, [0xFF])), request)
        XCTAssertEqual(RawEngine.errorTriple(engine.call(list, Array("{\"x\":1}".utf8))), request)
        XCTAssertFalse(FileManager.default.fileExists(atPath: world.data), "every rejection leaves the store unchanged")
    }

    func testNullArgumentsAndErrorTable() throws {
        let world = try World(rows: [])
        let engine = try RawEngine(config: world.config)
        func invalid(_ field: String) -> String { "invalid_request|invalid request: \(field)|false" }
        XCTAssertEqual(RawEngine.errorTriple(engine.call(nil, Array("{}".utf8))), invalid("method"))
        XCTAssertEqual(RawEngine.errorTriple(engine.call(Array("list_sources".utf8), nil)), invalid("request_json"))
        XCTAssertEqual(RawEngine.errorTriple(engine.call("nope", "{}")), "unknown_method|unknown method|false")
        let nullConfig = RawEngine.envelope(RawEngine.take(quotern_engine_open(nil, nil)))
        XCTAssertEqual(RawEngine.errorTriple(nullConfig), invalid("config_json"))
        var out: OpaquePointer?
        let nullConfigWithOut = RawEngine.envelope(RawEngine.take(quotern_engine_open(nil, &out)))
        XCTAssertEqual(RawEngine.errorTriple(nullConfigWithOut), invalid("config_json"))
        XCTAssertNil(out)
        let noOut = "{\"data_dir\":\"/x\",\"home\":\"/h\"}".withCString {
            RawEngine.envelope(RawEngine.take(quotern_engine_open($0, nil)))
        }
        XCTAssertEqual(RawEngine.errorTriple(noOut), invalid("out"))
        let nullEngine = "list_sources".withCString { method in
            "{}".withCString { request in
                RawEngine.envelope(RawEngine.take(quotern_call(nil, method, request, nil)))
            }
        }
        XCTAssertEqual(RawEngine.errorTriple(nullEngine), invalid("engine"))
        // NULL is a no-op for every release export.
        quotern_engine_close(nil)
        quotern_cancel_trigger(nil)
        quotern_cancel_free(nil)
        quotern_string_free(nil)
        XCTAssertEqual(quotern_abi_version(), 1)

        // The fixed code table: each golden equals its code/message/retryable and decodes to it.
        let table: [(file: String, error: BridgeError)] = [
            ("error-invalid-request.json", BridgeError(code: "invalid_request", message: "invalid request: request", retryable: false)),
            ("error-limit-exceeded.json", BridgeError(code: "limit_exceeded", message: "limit exceeded: request_bytes", retryable: false)),
            ("error-cancelled.json", BridgeError(code: "cancelled", message: "cancelled", retryable: true)),
            ("error-internal-panic.json", BridgeError(code: "internal_panic", message: "internal panic", retryable: false)),
            ("error-engine-failed.json", BridgeError(code: "engine_failed", message: "engine failed", retryable: false)),
        ]
        for (file, expected) in table {
            let bytes = Array(try Support.data("Contracts/bridge-v1/\(file)"))
            do {
                _ = try Envelope.decode(bytes, as: SourceList.self)
                XCTFail("\(file) must throw")
            } catch {
                XCTAssertEqual(error, expected, file)
            }
        }
    }

    func testSecondOwnerStoreBusy() async throws {
        let world = try World(rows: Support.dailyRows())
        let t = try Support.nowMs("utc_counters")
        let first = EngineClient()
        try await first.open(world.config)
        _ = try await first.setSourceSelection(world.selection())
        _ = try await first.ingest(nowMs: t)

        let second = EngineClient()
        do {
            try await second.open(world.config)
            XCTFail("a second native owner must be refused")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "store_busy", message: "store busy", retryable: true))
        }
        let snapshot = try await first.todaySnapshot(tz: "UTC", nowMs: t)
        let id = try XCTUnwrap(snapshot.sourceReported.first?.sourceId)
        XCTAssertEqual(snapshot.sourceReported, [try Support.reported("utc_counters", sourceId: id)])
        await first.close()
        try await second.open(world.config)
        let reopened = try await second.todaySnapshot(tz: "UTC", nowMs: t)
        XCTAssertEqual(reopened.sourceReported, snapshot.sourceReported)
        await second.close()

        try await assertDurableUnattachedReadsHistory()
        try await assertFailedLazyFirstStoreOpenIsExact()
    }

    /// The hand-written `validation_cases` of the daily oracle through the real EngineClient and
    /// the real Rust exports, store-less and acquired. Swift validates nothing: every window and
    /// every refusal comes from Rust.
    func testTodaySnapshotValidationCasesMatchSharedOracle() async throws {
        let file = try XCTUnwrap(Support.json("Fixtures/harness/opencode/daily/expected.json") as? [String: Any])
        let cases = try XCTUnwrap(file["validation_cases"] as? [[String: Any]])
        XCTAssertTrue(cases.contains { $0["window"] != nil }, "positive rows")
        XCTAssertTrue(cases.contains { $0["error"] != nil }, "rejected rows")

        let storeLess = try World(rows: [])
        let acquired = try World(rows: Support.dailyRows())
        let t = try Support.nowMs("utc_counters")
        for (mode, world) in [("store-less", storeLess), ("acquired", acquired)] {
            let client = EngineClient()
            try await client.open(world.config)
            if mode == "acquired" {
                _ = try await client.setSourceSelection(world.selection())
                _ = try await client.ingest(nowMs: t)
                // Settled: the nonempty daily oracle holds before any row runs.
                let zone = try XCTUnwrap(Support.expectedCase("utc_counters")["tz"] as? String)
                let settled = try await client.todaySnapshot(tz: zone, nowMs: t)
                let id = try XCTUnwrap(settled.sourceReported.first?.sourceId)
                XCTAssertEqual(settled.sourceReported, [try Support.reported("utc_counters", sourceId: id)])
                XCTAssertGreaterThan(settled.sourceReported[0].records, 0, "the oracle is nonempty")
            }
            var windows = 0
            var refusals = 0
            for row in cases {
                let name = "\(mode) \(row["name"] as? String ?? "?")"
                let tz = try XCTUnwrap(row["tz"] as? String, name)
                let now = try XCTUnwrap(row["now_ms"] as? Int64, name)
                if let window = row["window"] as? [String: Any] {
                    let snapshot = try await client.todaySnapshot(tz: tz, nowMs: now)
                    XCTAssertEqual(snapshot.window.startMs, window["start_ms"] as? Int64, name)
                    XCTAssertEqual(snapshot.window.endMs, window["end_ms"] as? Int64, name)
                    XCTAssertEqual(snapshot.window.tz, window["tz"] as? String, name)
                    windows += 1
                } else {
                    let error = try XCTUnwrap(row["error"] as? [String: Any], name)
                    let expected = BridgeError(
                        code: try XCTUnwrap(error["code"] as? String, name),
                        message: try XCTUnwrap(error["message"] as? String, name),
                        retryable: try XCTUnwrap(error["retryable"] as? Bool, name)
                    )
                    do {
                        let snapshot = try await client.todaySnapshot(tz: tz, nowMs: now)
                        XCTFail("\(name) returned a window \(snapshot.window)")
                    } catch {
                        XCTAssertEqual(error, expected, name)
                    }
                    refusals += 1
                }
            }
            XCTAssertGreaterThan(windows, 0, mode)
            XCTAssertGreaterThan(refusals, 0, mode)
            await client.close()
        }
    }

    /// A failed lazy first store open is exact, keeps the store None and creates no source row.
    private func assertFailedLazyFirstStoreOpenIsExact() async throws {
        let world = try World(rows: Support.dailyRows())
        // user_version 99 history placed after open: store_newer_version, bytes unchanged.
        let newerParent = world.base.appendingPathComponent("newer")
        try FileManager.default.createDirectory(at: newerParent, withIntermediateDirectories: false)
        let newerData = newerParent.path + "/data"
        let config = EngineConfig(dataDir: newerData, home: world.home)
        let other = EngineClient()
        try await other.open(config)
        try FileManager.default.createDirectory(atPath: newerData, withIntermediateDirectories: false)
        let historyPath = newerData + "/history.sqlite"
        try Support.sqlite(historyPath, script: "PRAGMA user_version=99;\nCREATE TABLE foreign_table(x);\n")
        let history = try Data(contentsOf: URL(fileURLWithPath: historyPath))
        do {
            _ = try await other.setSourceSelection(world.selection())
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "store_newer_version", message: "store newer version", retryable: false))
        }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: historyPath)), history)
        let still = try await other.listSources()
        XCTAssertTrue(still.isEmpty)
        // The failed handle keeps its owner claim until close.
        let rival = EngineClient()
        do {
            try await rival.open(config)
            XCTFail("the owner is retained")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "store_busy", message: "store busy", retryable: true))
        }
        await other.close()
        do {
            try await rival.open(config)
            XCTFail("the history is newer")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "store_newer_version", message: "store newer version", retryable: false))
        }

        // 0555 data-dir parent: first selection fails store_corrupt, nothing is created.
        XCTAssertNotEqual(geteuid(), 0, "the 0555 parent case requires euid != 0")
        let locked = world.base.appendingPathComponent("locked")
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(locked.path, 0o555), 0)
        let client = EngineClient()
        try await client.open(EngineConfig(dataDir: locked.path + "/data", home: world.home))
        do {
            _ = try await client.setSourceSelection(world.selection())
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "store_corrupt", message: "store corrupt", retryable: false))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: locked.path + "/data"))
        let none = try await client.listSources()
        XCTAssertTrue(none.isEmpty)
        await client.close()
    }
}
