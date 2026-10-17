import AppKit
import Foundation
import Darwin
import XCTest
@testable import QuoternCore

final class SentinelTests: XCTestCase {
    static let sentinel = "QTN-SENTINEL-7f3a9c"
    static let now: Int64 = 1_775_124_000_000

    /// Every place hostile source text could reach on the Swift side. Each one is scanned below,
    /// and the scanned set must equal this one: a new sink is declared here and scanned, or the
    /// inventory check fails.
    static let declaredSinks: Set<String> = [
        "log capture", "accessibility tree", "decoded responses", "data-directory files",
        "UserDefaults domain",
    ]

    /// What each sink held, as scanned.
    typealias Scan = [String: [Data]]

    /// Everything wrong with a scan: a declared sink left unscanned, a scanned sink that is not
    /// declared, an empty sink (a vacuous scan), or the sentinel in any sink.
    static func problems(_ scan: Scan, declared: Set<String> = declaredSinks) -> [String] {
        var problems = declared.subtracting(scan.keys).sorted().map { "declared but not scanned: \($0)" }
        problems += Set(scan.keys).subtracting(declared).sorted().map { "scanned but not declared: \($0)" }
        for (sink, payloads) in scan.sorted(by: { $0.key < $1.key }) {
            if payloads.allSatisfy(\.isEmpty) { problems.append("empty sink: \(sink)") }
            if payloads.contains(where: contains) { problems.append("sentinel in \(sink)") }
        }
        return problems
    }

    private static func contains(_ bytes: Data) -> Bool {
        bytes.range(of: Data(sentinel.utf8)) != nil
    }

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

    private func durableFiles(_ directory: String) throws -> [Data] {
        func read(_ directory: URL) throws -> [Data] {
            var files: [Data] = []
            for url in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey]) {
                if try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true {
                    files += try read(url)
                } else {
                    files.append(try Data(contentsOf: url))
                }
            }
            return files
        }
        let files = try read(URL(fileURLWithPath: directory))
        guard !files.isEmpty else { throw NSError(domain: "QuoternTests.Inventory", code: 1) }
        return files
    }

    @MainActor
    private func waitForExit(_ process: Process, deadline: ContinuousClock.Instant) async throws {
        defer {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
        }
        while process.isRunning, ContinuousClock().now < deadline {
            try Task.checkCancellation()
            try await Task.sleep(for: .milliseconds(50))
        }
        try Task.checkCancellation()
        guard !process.isRunning else { throw NSError(domain: "QuoternTests.Child", code: 1) }
    }

    func testDurableInventoryRejectsMissingEmptyAndInaccessibleSubtree() throws {
        let base = try Support.canonicalTemporaryDirectory()
        defer { Support.remove(base) }
        XCTAssertThrowsError(try durableFiles(base.appendingPathComponent("missing").path))
        XCTAssertThrowsError(try durableFiles(base.path))
        try Data("clean".utf8).write(to: base.appendingPathComponent("visible"))
        let nested = base.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data(Self.sentinel.utf8).write(to: nested.appendingPathComponent("hidden"))
        XCTAssertEqual(try durableFiles(base.path).count, 2)
        XCTAssertNotEqual(geteuid(), 0, "the permission discriminator requires non-root")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: nested.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: nested.path) }
        XCTAssertThrowsError(try durableFiles(base.path), "a readable sibling cannot mask a skipped subtree")
    }

    @MainActor
    func testOwnedChildTimeoutKillsAndJoinsHungProcess() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["60"]
        try process.run()
        do {
            try await waitForExit(process, deadline: ContinuousClock().now)
            XCTFail("a running child past its deadline must fail")
        } catch let error as NSError {
            XCTAssertEqual(error.domain, "QuoternTests.Child")
            XCTAssertEqual(error.code, 1)
        }
        XCTAssertFalse(process.isRunning)
        XCTAssertEqual(process.terminationReason, .uncaughtSignal)
        XCTAssertEqual(process.terminationStatus, SIGKILL)
        let completed = Process()
        completed.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try completed.run()
        try await waitForExit(completed, deadline: ContinuousClock().now.advanced(by: .seconds(5)))
        XCTAssertEqual(completed.terminationStatus, 0)
    }

    @MainActor
    func testOwnedChildCancellationKillsAndJoins() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["60"]
        try process.run()
        let task = Task { try await waitForExit(process, deadline: ContinuousClock().now.advanced(by: .seconds(90))) }
        task.cancel()
        do {
            try await task.value
            XCTFail("cancellation must fail the owned child")
        } catch is CancellationError {}
        XCTAssertFalse(process.isRunning)
        XCTAssertEqual(process.terminationReason, .uncaughtSignal)
        XCTAssertEqual(process.terminationStatus, SIGKILL)
    }

    @MainActor
    func testNoSentinelInAnyDeclaredSink() async throws {
        // Record and session identifiers are stored by design (event keys, session id <= 256 B),
        // so only text fields the store never persists are hostile placements here.
        var scan: Scan = [:]
        for placement in ["content", "model", "provider", "path"] {
            try await run(placement: placement, into: &scan)
        }
        try await codex(into: &scan)
        XCTAssertEqual(Self.problems(scan), [], "every declared sink scanned, non-empty and clean")
    }

    @MainActor
    private func run(placement: String, into scan: inout Scan) async throws {
        QuoternLog.reset()
        let world = try World(rows: hostileRows(placement: placement))
        let client = EngineClient()
        func note(_ value: some Encodable) throws {
            scan["decoded responses", default: []].append(try JSONEncoder().encode(value))
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
                scan["decoded responses", default: []].append(Data((error.code + " " + error.message).utf8))
            }
        }
        await client.close()

        // The rendered popover's accessibility text.
        let rendered = Render.render(Render.model(.success(snapshot), nowMs: Self.now), dark: false)
        rendered.window.orderOut(nil)
        scan["accessibility tree", default: []] += rendered.texts.map { Data(($0.label + " " + $0.value).utf8) }

        // The folder list the app keeps for its file-event stream.
        let suite = "app.quotern.tests.sentinel.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        WatchedRoots(defaults: defaults).add(world.source)
        let domain = try XCTUnwrap(defaults.persistentDomain(forName: suite))
        scan["UserDefaults domain", default: []].append(try PropertyListSerialization.data(fromPropertyList: domain, format: .xml, options: 0))
        defaults.removePersistentDomain(forName: suite)

        XCTAssertLessThan(QuoternLog.captured.count, 256, "\(placement): the capture stayed below its bound")
        for line in QuoternLog.captured {
            XCTAssertEqual(line.split(separator: " ").count, 2, "operation and fixed code only: \(line)")
        }
        scan["log capture", default: []] += QuoternLog.captured.map { Data($0.utf8) }
        scan["data-directory files", default: []] += try durableFiles(world.data)
    }

    @MainActor
    private func codex(into scan: inout Scan) async throws {
        QuoternLog.reset()
        let world = try CodexWorld()
        let lines = try String(contentsOf: world.rollout, encoding: .utf8).split(separator: "\n")
        let hostile = try lines.map { line -> String in
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            var payload = try XCTUnwrap(object["payload"] as? [String: Any])
            for field in ["content", "model", "provider", "cwd", "instructions"] { payload[field] = Self.sentinel }
            object["payload"] = payload
            return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        }.joined(separator: "\n") + "\n"
        XCTAssertTrue(hostile.contains(Self.sentinel))
        try Data(hostile.utf8).write(to: world.rollout)
        let client = EngineClient()
        let now: Int64 = 1_790_769_600_000
        try await client.open(world.config)
        scan["decoded responses", default: []].append(try JSONEncoder().encode(try await client.setSourceSelection(world.selection)))
        scan["decoded responses", default: []].append(try JSONEncoder().encode(try await client.ingest(nowMs: now)))
        scan["decoded responses", default: []].append(try JSONEncoder().encode(try await client.listSources()))
        let snapshot = try await client.todaySnapshot(tz: "UTC", nowMs: now)
        XCTAssertEqual(snapshot.bySource.first?.harness, "codex")
        XCTAssertEqual(snapshot.sourceReported.first?.total.value, 10)
        scan["decoded responses", default: []].append(try JSONEncoder().encode(snapshot))
        await client.close()
        let rendered = Render.render(Render.model(.success(snapshot), nowMs: now), dark: false)
        XCTAssertEqual(rendered.text("Total, Codex reported tokens")?.value, "10 tokens, Reported, Current, Updated just now")
        rendered.window.orderOut(nil)
        scan["accessibility tree", default: []] += rendered.texts.map { Data(($0.label + " " + $0.value).utf8) }
        scan["log capture", default: []] += QuoternLog.captured.map { Data($0.utf8) }
        scan["data-directory files", default: []] += try durableFiles(world.data)
        let suite = "app.quotern.tests.codex-sentinel.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        WatchedRoots(defaults: defaults).add(world.source)
        let domain = try XCTUnwrap(defaults.persistentDomain(forName: suite))
        scan["UserDefaults domain", default: []].append(try PropertyListSerialization.data(fromPropertyList: domain, format: .xml, options: 0))
        defaults.removePersistentDomain(forName: suite)
    }

    /// Mutants of the inventory check: each one is reported, and a clean full scan is not.
    func testInventoryCheckRejectsEachMutant() {
        var clean: Scan = [:]
        for sink in Self.declaredSinks { clean[sink] = [Data("clean".utf8)] }
        XCTAssertEqual(Self.problems(clean), [], "control: a clean full scan")

        var leak = clean
        leak["log capture"]?.append(Data("x \(Self.sentinel) y".utf8))
        XCTAssertEqual(Self.problems(leak), ["sentinel in log capture"])

        var undeclared = clean
        undeclared["export file"] = [Data("clean".utf8)]
        XCTAssertEqual(Self.problems(undeclared), ["scanned but not declared: export file"])

        var unscanned = clean
        unscanned["UserDefaults domain"] = nil
        XCTAssertEqual(Self.problems(unscanned), ["declared but not scanned: UserDefaults domain"])

        var vacuous = clean
        vacuous["accessibility tree"] = []
        XCTAssertEqual(Self.problems(vacuous), ["empty sink: accessibility tree"])
    }

    func testCapturedLogIsBounded() {
        QuoternLog.reset()
        for index in 0..<257 {
            QuoternLog.record("line", code: "\(index)")
        }
        XCTAssertEqual(QuoternLog.captured, (1..<257).map { "line \($0)" }, "the 256 most recent lines, in order")
        QuoternLog.reset()
    }
}

/// The self-test command lines refuse the production data directory, anything inside it and
/// anything containing it.
final class SelfTestArgumentsTests: XCTestCase {
    private var base: URL!
    private var production: String { base.appendingPathComponent("Application Support/Quotern").path }

    override func setUpWithError() throws {
        base = try Support.canonicalTemporaryDirectory()
        try FileManager.default.createDirectory(atPath: production, withIntermediateDirectories: true)
    }

    override func tearDown() {
        Support.remove(base)
    }

    private func startup(_ dataDirectory: String) -> Result<SelfTestArguments, SelfTestRefusal>? {
        SelfTestArguments.parse(["Quotern", "--selftest-startup", "--data-dir", dataDirectory, "--out", base.path + "/out"], production: production)
    }

    private func refused(_ result: Result<SelfTestArguments, SelfTestRefusal>?) -> String? {
        guard case .failure(let refusal)? = result else { return nil }
        return refusal.reason
    }

    func testProductionDirectoryEqualChildAndAncestorAreRefused() throws {
        let refusal = "refusing the production data directory"
        XCTAssertEqual(refused(startup(production)), refusal, "equal")
        XCTAssertEqual(refused(startup(production + "/")), refusal, "equal, trailing slash")
        XCTAssertEqual(refused(startup(base.path + "/Application Support/./Quotern")), refusal, "equal, dot segment")
        XCTAssertEqual(refused(startup(production + "/data")), refusal, "child")
        XCTAssertEqual(refused(startup(base.path + "/Application Support")), refusal, "ancestor")
        XCTAssertEqual(refused(startup("/")), refusal, "the filesystem root contains it")
        let link = base.appendingPathComponent("link").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: production)
        XCTAssertEqual(refused(startup(link)), refusal, "a symlink to it")
        // Controls: a sibling that only shares a name prefix, and an unrelated directory.
        XCTAssertNil(refused(startup(production + "-other")), "sibling with the same prefix")
        XCTAssertNil(refused(startup(base.path + "/scratch")))
        // The real production path, by default.
        guard case .failure? = SelfTestArguments.parse(["Quotern", "--selftest-startup", "--data-dir", productionDataDirectory, "--out", base.path]) else {
            return XCTFail("the real production directory is refused")
        }
    }

    func testModesParseAndMalformedLinesAreRefused() {
        let data = base.path + "/scratch"
        XCTAssertEqual(try startup(data)?.get(), .startup(.init(dataDirectory: data, out: base.path + "/out")))
        let journey = SelfTestArguments.parse([
            "Quotern", "--selftest-journey", "--selftest-home", base.path + "/home", "--data-dir", data,
            "--now", "2026-09-30T12:00:00Z", "--phase", "first", "--out", base.path + "/out",
        ], production: production)
        XCTAssertEqual(try journey?.get(), .journey(.init(home: base.path + "/home", dataDirectory: data, nowMs: 1_790_769_600_000, phase: "first", out: base.path + "/out")))
        XCTAssertNil(SelfTestArguments.parse(["Quotern"], production: production), "no self-test: the app")
        XCTAssertNotNil(refused(SelfTestArguments.parse(["Quotern", "--selftest-other"], production: production)), "unknown mode")
        XCTAssertNotNil(refused(SelfTestArguments.parse(["Quotern", "--selftest-startup", "--data-dir", data], production: production)), "missing --out")
        XCTAssertNotNil(refused(SelfTestArguments.parse(["Quotern", "--selftest-startup", "--data-dir", data, "--out", base.path, "--now", "x"], production: production)), "foreign flag")
        XCTAssertNotNil(refused(SelfTestArguments.parse(["Quotern", "--selftest-startup", "--data-dir"], production: production)), "flag without value")
        XCTAssertNotNil(refused(SelfTestArguments.parse(["Quotern", "--selftest-journey", "--selftest-home", base.path, "--data-dir", data, "--now", "2026-09-30T12:00:00Z", "--phase", "third", "--out", base.path], production: production)), "unknown phase")
    }
}
