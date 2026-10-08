import AppKit
import Foundation
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
        "UserDefaults domain", "self-test journey.json", "self-test popover.png",
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
        guard let walk = FileManager.default.enumerator(atPath: directory) else { return [] }
        var files: [Data] = []
        while let name = walk.nextObject() as? String {
            var isDirectory: ObjCBool = false
            let path = directory + "/" + name
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else { continue }
            files.append(try Data(contentsOf: URL(fileURLWithPath: path)))
        }
        return files
    }

    @MainActor
    func testNoSentinelInAnyDeclaredSink() async throws {
        // Record and session identifiers are stored by design (event keys, session id <= 256 B),
        // so only text fields the store never persists are hostile placements here.
        var scan: Scan = [:]
        for placement in ["content", "model", "provider", "path"] {
            try await run(placement: placement, into: &scan)
        }
        try journey(into: &scan)
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

    /// The real self-test journey over a copy of the journey home whose records carry the
    /// sentinel in every text field the adapter skips. Its outputs are scanned whatever its
    /// checks concluded (the status-item click needs a menu bar).
    private func journey(into scan: inout Scan) throws {
        let executable = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("Quotern")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: executable.path), "the Quotern executable is built beside the tests: \(executable.path)")
        let base = try Support.canonicalTemporaryDirectory()
        defer { Support.remove(base) }
        let home = base.appendingPathComponent("home")
        try FileManager.default.copyItem(at: Support.root.appendingPathComponent("Fixtures/journey-home"), to: home)
        let storage = home.appendingPathComponent(".local/share/opencode/storage")
        for (relative, field) in [
            ("message/ses_journey/msg_journey.json", "modelID"),
            ("part/msg_journey/prt_journey.json", "text"),
            ("session/journey/ses_journey.json", "title"),
        ] {
            let url = storage.appendingPathComponent(relative)
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            object[field] = "api_key=\(Self.sentinel)"
            try JSONSerialization.data(withJSONObject: object).write(to: url)
        }
        let out = base.appendingPathComponent("out").path
        let process = Process()
        process.executableURL = executable
        process.arguments = [
            "--selftest-journey", "--selftest-home", home.path, "--data-dir", base.appendingPathComponent("data").path,
            "--now", "2026-09-30T12:00:00Z", "--phase", "first", "--out", out,
        ]
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        let record = try Data(contentsOf: URL(fileURLWithPath: out + "/journey.json"))
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: record) as? [String: Any])
        XCTAssertNotNil(parsed["displayed"], "the journey recorded what it displayed")
        scan["self-test journey.json", default: []].append(record)
        scan["self-test popover.png", default: []].append(try Data(contentsOf: URL(fileURLWithPath: out + "/popover.png")))
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
