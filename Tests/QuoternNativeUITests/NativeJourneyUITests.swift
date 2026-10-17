import AppKit
import CryptoKit
import Darwin
import Foundation
#if !NATIVE011_BINDING_SELF_CHECK
import XCTest
#endif

#if !NATIVE011_BINDING_SELF_CHECK
@MainActor
final class NativeJourneyUITests: XCTestCase {
    func testCodexNeverEntersStatusItem() async throws {
        let record = try await runPickerJourney()
        let checks = try XCTUnwrap(record["checks"] as? [[String: Any]])
        for name in ["status item title", "status item is named", "status item title and accessibility value carry no digit", "Codex source has no error", "actual codex total"] {
            XCTAssertEqual(try XCTUnwrap(checks.first { $0["name"] as? String == name })["pass"] as? Bool, true, name)
        }
        for harness in ["Codex", "OpenCode"] {
            for step in ["native picker", "registered harness"] {
                let name = "Add Folder \(harness) \(step)"
                XCTAssertEqual(try XCTUnwrap(checks.first { $0["name"] as? String == name })["pass"] as? Bool, true, name)
            }
        }
        let picker = try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex native picker" })
        let readiness = try XCTUnwrap(picker["detail"] as? [String: Any])
        XCTAssertEqual(readiness["disabled_present"] as? Bool, true)
        XCTAssertEqual(readiness["enabled_present"] as? Bool, true)
        XCTAssertEqual(readiness["no_premature_panel"] as? Bool, true)
        XCTAssertEqual(readiness["registered_before_readiness"] as? Int, 0)
        XCTAssertEqual(readiness["events"] as? [String], [
            "disabled action observed", "clock advanced before readiness", "readiness released",
            "enabled action observed", "picker deadline armed", "panel visible", "OK attempted", "panel closed",
        ])
        let displayed = try XCTUnwrap(record["displayed"] as? [String: String])
        XCTAssertEqual(displayed["Total, Codex reported tokens in .codex"], "10 tokens, Reported, Current, Updated just now")
    }

    func testWithheldReadinessNeverOpensPickerOrRegistersSource() async throws {
        let record = try await runPickerJourney(fault: "withheld-readiness")
        let checks = try XCTUnwrap(record["checks"] as? [[String: Any]])
        let picker = try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex native picker" })
        XCTAssertEqual(picker["pass"] as? Bool, false)
        let detail = try XCTUnwrap(picker["detail"] as? [String: Any])
        XCTAssertEqual(detail["diagnostic"] as? String, "enabled accessibility action unavailable")
        XCTAssertEqual(detail["disabled_present"] as? Bool, true)
        XCTAssertEqual(detail["enabled_present"] as? Bool, false)
        XCTAssertEqual(detail["no_premature_panel"] as? Bool, true)
        XCTAssertEqual(detail["panel_created"] as? Bool, false)
        XCTAssertEqual(detail["registered_count"] as? Int, 0)
        XCTAssertEqual(detail["submission_finished"] as? Bool, false)
        XCTAssertEqual(detail["events"] as? [String], ["disabled action observed", "clock advanced before readiness", "readiness deadline expired"])
        XCTAssertEqual(try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex registered harness" })["pass"] as? Bool, false)
    }

    func testRefusedNativePickerOKExpiresAndClosesWithoutRegistration() async throws {
        let record = try await runPickerJourney(fault: "refused-ok")
        let checks = try XCTUnwrap(record["checks"] as? [[String: Any]])
        let picker = try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex native picker" })
        XCTAssertEqual(picker["pass"] as? Bool, false)
        let detail = try XCTUnwrap(picker["detail"] as? [String: Any])
        XCTAssertEqual(detail["diagnostic"] as? String, "picker deadline expired")
        XCTAssertEqual(detail["disabled_present"] as? Bool, true)
        XCTAssertEqual(detail["enabled_present"] as? Bool, true)
        XCTAssertEqual(detail["no_premature_panel"] as? Bool, true)
        XCTAssertEqual(detail["validation_rejections"] as? Int, 1)
        XCTAssertEqual(detail["panel_visible_at_rejection"] as? Bool, true)
        XCTAssertEqual(detail["panel_closed"] as? Bool, true)
        XCTAssertEqual(detail["registered_count"] as? Int, 0)
        XCTAssertEqual(detail["submission_finished"] as? Bool, false)
        XCTAssertEqual(detail["events"] as? [String], [
            "disabled action observed", "clock advanced before readiness", "readiness released",
            "enabled action observed", "picker deadline armed", "panel visible", "OK attempted",
            "URL validation rejected", "clock advanced after rejection", "picker deadline expired", "panel closed",
        ])
        XCTAssertEqual(try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex registered harness" })["pass"] as? Bool, false)
    }

    func testLateAcceptedOKIsRejectedBeforeSourceRegistration() async throws {
        let record = try await runPickerJourney(fault: "late-ok")
        let checks = try XCTUnwrap(record["checks"] as? [[String: Any]])
        let picker = try XCTUnwrap(checks.first { $0["name"] as? String == "Add Folder Codex native picker" })
        let detail = try XCTUnwrap(picker["detail"] as? [String: Any])
        XCTAssertEqual(detail["diagnostic"] as? String, "picker deadline expired")
        XCTAssertEqual(detail["validation_rejections"] as? Int, 0, "OK was accepted, not refused")
        XCTAssertEqual(detail["panel_closed"] as? Bool, true)
        XCTAssertEqual(detail["registered_count"] as? Int, 0)
        XCTAssertEqual(detail["submission_finished"] as? Bool, false)
        XCTAssertEqual(detail["events"] as? [String], [
            "disabled action observed", "clock advanced before readiness", "readiness released",
            "enabled action observed", "picker deadline armed", "panel visible", "OK attempted",
            "clock advanced after accepted OK", "picker deadline expired", "panel closed",
        ])
    }

    func testJourneyInventoryRejectsOmittedDuplicateIncompleteAndUnrelatedChecks() {
        for (phase, fault) in [("first", nil), ("restart", nil), ("first", "withheld-readiness"),
                               ("first", "refused-ok"), ("first", "late-ok")] as [(String, String?)] {
            let failures = fault == nil ? [] : ["Add Folder Codex native picker", "Add Folder Codex registered harness"]
            let checks: [[String: Any]] = journeyCheckNames(phase: phase, fault: fault).map {
                ["name": $0, "pass": !failures.contains($0)]
            }
            var record: [String: Any] = ["phase": phase, "complete": true, "result": fault == nil ? "pass" : "fail", "checks": checks]
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), [])
            record["checks"] = Array(checks.dropFirst())
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["unexpected check inventory"])
            record["checks"] = checks + [checks[0]]
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["duplicate checks"])
            record["checks"] = checks + [["name": "extra", "pass": true]]
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["unexpected check inventory"])
            var missingVerdict = checks
            missingVerdict[0]["pass"] = nil
            record["checks"] = missingVerdict
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["missing verdict"])
            var unrelated = checks
            unrelated[0]["pass"] = false
            record["checks"] = unrelated
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["unrelated failure"])
            record["checks"] = checks
            record["complete"] = false
            record["result"] = "running"
            XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), ["incomplete journey"])
        }
    }


    private static let sentinel = Native011RetainedOutput.sentinel
    private static let aggregateDeadline = ContinuousClock().now.advanced(by: .seconds(900))
    private static let aggregateStartMs = Native011LivePlatform.monotonicMilliseconds()
    private static let emptyOutputs = Native011RetainedOutput.emptyNames
    private var caseDeadline = ContinuousClock().now
    private var caseStartMs = Native011LivePlatform.monotonicMilliseconds()
    private let platform = Native011LivePlatform()
    private var session: Native011LaunchSession?
    private var sessions: [Native011LaunchSession] = []
    private var proxy: XCUIApplication?

    private struct Fixture {
        let repository: URL
        let attempt: URL
        let home: URL
        let data: URL
        let output: URL
        let wrapper: URL
        let method: String
        let wrapperIdentity: Native011WrapperIdentity
        let executable: URL
        let original: URL
        let binary: Data
        let archive: URL
        let archiveBytes: Data
        let authPermissions: NSNumber
        var suite: String { "app.quotern.selftest." + data.path.utf8.map { String(format: "%02x", $0) }.joined() }
    }

    func testCancellationRetainsEvidenceAndStopsOnlyOwnedJourney() async throws {
        let context = try beginCase()
        let deadline = caseDeadline
        var evaluations = 0
        for seconds in [-1, 4] {
            caseDeadline = ContinuousClock().now.advanced(by: .seconds(seconds))
            XCTAssertThrowsError(try wait { evaluations += 1; return true }) {
                XCTAssertEqual($0 as? ProofFailure, .workDeadline)
            }
            XCTAssertThrowsError(try checkWork()) {
                XCTAssertEqual($0 as? ProofFailure, .workDeadline)
            }
        }
        XCTAssertEqual(evaluations, 0, "cleanup reserve forbids a satisfied wait or restart")
        caseDeadline = deadline
        let cancelled = Task { @MainActor in
            XCTAssertThrowsError(try self.wait { evaluations += 1; return true }) {
                XCTAssertTrue($0 is CancellationError)
            }
            XCTAssertThrowsError(try self.checkWork()) { XCTAssertTrue($0 is CancellationError) }
        }
        cancelled.cancel()
        try await cancelled.value
        XCTAssertEqual(evaluations, 0, "cancellation precedes an already satisfied condition")

        // A real child held behind a gate: the real EVFILT_PROC observer is installed before it is released, so its status is
        // the kernel's own wait status, decoded independently of the Process status that decodes the launcher. The shared
        // wait that fails before evaluating its condition on an observed application exit is exercised in the self-check.
        let gate = Pipe()
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "read line; exit 7"]
        child.standardInput = gate
        try checkWork()
        try child.run()
        let observer = try Native011LiveExitObserver(pid: child.processIdentifier)
        try gate.fileHandleForWriting.write(contentsOf: Data("\n".utf8))
        let launcher = Native011LiveLauncher(process: child)
        try wait { !launcher.isRunning }
        guard case .exited(let raw) = observer.poll() else { return XCTFail("the installed observer reported no kernel exit") }
        let kernel = try XCTUnwrap(Native011ExitRecord.application(rawWaitStatus: raw))
        XCTAssertEqual([kernel.source, kernel.reason, "\(kernel.status)", "\(kernel.rawWaitStatus ?? -1)"],
                       ["EVFILT_PROC_NOTE_EXITSTATUS", "exit", "7", "1792"], "the kernel status is retained and decoded")
        XCTAssertEqual(launcher.exit?.reason, "exit", "a real early launcher exit is decoded from Process")
        XCTAssertEqual(launcher.exit?.status, 7)
        XCTAssertNil(session, "no launch session exists outside a native phase")
        let record = try await runPickerJourney(cancel: true, context: context)
        XCTAssertEqual(record["complete"] as? Bool, false)
        XCTAssertEqual(record["result"] as? String, "running")
    }

    private static let nativeSinks: Set<String> = ["diagnostics", "accessibility tree", "data-directory files", "UserDefaults domain", "self-test journey.json", "native captures", "wrapper"]

    func testNativeSinkInventoryRejectsEachMutant() throws {
        for (failure, expected) in [
            (ProofFailure.workDeadline, "workDeadline"), (.childExited, "childExited"),
            (.ownerChanged, "ownerChanged"), (.outputInventory, "outputInventory"), (.outputSentinel, "outputSentinel"), (.unexpectedStorage, "unexpectedStorage"),
        ] {
            XCTAssertEqual(failureDiagnostic(failure), expected)
        }
        XCTAssertEqual(failureDiagnostic(CancellationError()), "CancellationError()")
        for (failure, expected) in [
            (Native011WrapperAdmissionFailure.path, "N011-C-PATH"), (.contents, "N011-C-CONTENTS"), (.bytes, "N011-C-BYTES"),
        ] {
            XCTAssertEqual(failureDiagnostic(failure), expected)
        }
        let hostileFailure = NSError(domain: Self.sentinel, code: 17,
                                     userInfo: [NSLocalizedDescriptionKey: Self.sentinel, NSFilePathErrorKey: Self.sentinel])
        XCTAssertEqual(failureDiagnostic(hostileFailure), "native-proof-unclassified-failure")
        let underlying = NSError(domain: NSPOSIXErrorDomain, code: 13, userInfo: [NSLocalizedDescriptionKey: Self.sentinel])
        for (domain, expectedDomain) in [(NSCocoaErrorDomain, "cocoa"), (NSPOSIXErrorDomain, "posix"),
                                         (NSOSStatusErrorDomain, "osstatus"), (NSMachErrorDomain, "mach"),
                                         (Self.sentinel, "redacted")] {
            let failure = NSError(domain: domain, code: 4, userInfo: [NSUnderlyingErrorKey: underlying, NSFilePathErrorKey: Self.sentinel])
            XCTAssertEqual(native011LaunchFailureDiagnostic(failure), "launch primary=\(expectedDomain):4 underlying=posix:13")
        }
        let nested = NSError(domain: NSOSStatusErrorDomain, code: -50, userInfo: [NSLocalizedDescriptionKey: Self.sentinel])
        let unknown = NSError(domain: Self.sentinel, code: 17, userInfo: [NSUnderlyingErrorKey: nested])
        let chained = NSError(domain: NSCocoaErrorDomain, code: 4, userInfo: [NSUnderlyingErrorKey: unknown])
        XCTAssertEqual(native011LaunchFailureDiagnostic(chained), "launch primary=cocoa:4 underlying=redacted:17")
        XCTAssertEqual(native011LaunchFailureDiagnostic(NSError(domain: NSPOSIXErrorDomain, code: 2)), "launch primary=posix:2")
        // The identities must fit the stored 80-character reason unchanged, with extreme codes clamped to the 32-bit range.
        let extreme = NSError(domain: NSOSStatusErrorDomain, code: Int.min, userInfo: [NSUnderlyingErrorKey: NSError(domain: NSMachErrorDomain, code: Int.max)])
        XCTAssertEqual(native011LaunchFailureDiagnostic(extreme), "launch primary=osstatus:-2147483648 underlying=mach:2147483647")
        XCTAssertEqual(Native011LaunchFailure(.launcherStart, stage: "launcher-start", reason: native011LaunchFailureDiagnostic(extreme)).reason,
                       native011LaunchFailureDiagnostic(extreme))
        let context = try beginCase()
        let declared = Self.nativeSinks.union(["self-test popover.png"])
        let clean = Dictionary(uniqueKeysWithValues: declared.map { ($0, [Data("clean".utf8)]) })
        XCTAssertEqual(sinkProblems(clean, declared: declared), [])
        var leak = clean
        leak["diagnostics"] = [Data(Self.sentinel.utf8)]
        XCTAssertEqual(sinkProblems(leak, declared: declared), ["sentinel in diagnostics"])
        var extra = clean
        extra["extra"] = [Data("clean".utf8)]
        XCTAssertEqual(sinkProblems(extra, declared: declared), ["scanned but not declared: extra"])
        var unscanned = clean
        unscanned["wrapper"] = nil
        XCTAssertEqual(sinkProblems(unscanned, declared: declared), ["declared but not scanned: wrapper"])
        var empty = clean
        empty["accessibility tree"] = []
        XCTAssertEqual(sinkProblems(empty, declared: declared), ["empty sink: accessibility tree"])
        let directory = context.attempt.appendingPathComponent("mutation-inputs/" + context.method)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let phase = directory.appendingPathComponent("first")
        try FileManager.default.createDirectory(at: phase, withIntermediateDirectories: true)
        let required = Set(Native011RetainedOutput.phaseFiles(phase: "first", fault: "refused-ok", cancelled: false, sessions: sessions).map { phase.appendingPathComponent($0) })
        for url in required { try Data("clean".utf8).write(to: url) }
        XCTAssertEqual(try Native011RetainedOutput.checked(in: phase, required: required), required)
        let panel = phase.appendingPathComponent("Codex-panel.png")
        try FileManager.default.removeItem(at: panel)
        XCTAssertThrowsError(try Native011RetainedOutput.checked(in: phase, required: required)) { XCTAssertEqual($0 as? ProofFailure, .outputInventory) }
        try Data("clean".utf8).write(to: panel)
        try Data("extra".utf8).write(to: phase.appendingPathComponent("extra.log"))
        XCTAssertThrowsError(try Native011RetainedOutput.checked(in: phase, required: required)) { XCTAssertEqual($0 as? ProofFailure, .outputInventory) }
        let absent = directory.appendingPathComponent("absent-data")
        let absence = try storagePayloads(in: absent, positive: false)
        XCTAssertEqual(try XCTUnwrap(JSONSerialization.jsonObject(with: absence[0]) as? [String: Any])["present"] as? Bool, false)
        try FileManager.default.createDirectory(at: absent, withIntermediateDirectories: true)
        XCTAssertThrowsError(try storagePayloads(in: absent, positive: false)) { XCTAssertEqual($0 as? ProofFailure, .unexpectedStorage) }
        try Data("unexpected write".utf8).write(to: absent.appendingPathComponent("history.sqlite3"))
        XCTAssertThrowsError(try storagePayloads(in: absent, positive: false)) { XCTAssertEqual($0 as? ProofFailure, .unexpectedStorage) }
        XCTAssertEqual(try storagePayloads(in: absent, positive: true), [Data("unexpected write".utf8)])
        let unreadable = directory.appendingPathComponent("unreadable")
        try Data(Self.sentinel.utf8).write(to: unreadable)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: unreadable.path)
        defer {
            do { try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: unreadable.path) }
            catch { XCTFail("scanner mutation cleanup failed: \(error)") }
        }
        XCTAssertThrowsError(try Native011RetainedOutput.files(in: directory).map { try Data(contentsOf: $0) })
    }
}

extension NativeJourneyUITests {
    // native011-source-set:start
    private static let sourceSet = [
        "Tests/QuoternNativeUITests/Native011Receipt.swift",
        "Tests/QuoternNativeUITests/Native011Evidence.swift",
        "Tests/QuoternNativeUITests/Native011LaunchSession.swift",
        "Tests/QuoternNativeUITests/Native011RetainedOutput.swift",
        "Tests/QuoternNativeUITests/NativeJourneyUITests.swift",
        "Tests/QuoternNativeUITests/Native011SelfCheck.swift",
        "Tests/QuoternNativeUITests/Native011SelfCheckCorrections.swift",
        "Tests/QuoternNativeUITests/Native011SelfCheckEvidence.swift"
    ]
    // native011-source-set:end

    private func journeyCheckNames(phase: String = "first", fault: String? = nil) -> [String] {
        var names = ["Codex auth fixture is unreadable", "status-item click opens the popover"]
        if phase == "first" {
            names += ["Add Folder Codex native picker", "Add Folder Codex registered harness"]
            if fault != nil { return names }
            names += ["Add Folder OpenCode native picker", "Add Folder OpenCode registered harness",
                      "one pass per selected folder", "one stream restarted for the added root"]
        } else {
            names += ["one launch pass without a file event", "one file-event stream"]
        }
        names += [
            "selected roots persisted canonically", "enabled sources have a watcher timer",
            "status item title", "status item is named", "status item title and accessibility value carry no digit",
            "popover is 360 pt wide", "AppKit hosting view, no web view",
            "displayed Origin unverified", "displayed header freshness Updated just now",
            "two reported sources", "Codex source has no error", "window start", "window end",
            "Codex auth metadata unchanged", "no web or Python runtime loaded", "no TCP listener",
        ]
        for (harness, folder) in [("Codex", ".codex"), ("OpenCode", "opencode")] {
            for field in ["Total", "Input", "Output", "Reasoning", "Cache read", "Cache write"] {
                names.append("displayed \(field), \(harness) reported tokens in \(folder)")
            }
            for field in ["input", "output", "reasoning", "cache_read", "cache_write", "total"] {
                names.append("actual \(harness.lowercased()) \(field)")
            }
        }
        return names
    }

    private func journeyInventoryProblems(_ record: [String: Any], phase: String = "first", fault: String? = nil) -> [String] {
        guard record["complete"] as? Bool == true, record["phase"] as? String == phase,
              record["result"] as? String == (fault == nil ? "pass" : "fail"),
              let checks = record["checks"] as? [[String: Any]] else { return ["incomplete journey"] }
        let names = checks.compactMap { $0["name"] as? String }
        var problems: [String] = []
        if names.count != checks.count || Set(names) != Set(journeyCheckNames(phase: phase, fault: fault)) {
            problems.append("unexpected check inventory")
        }
        if Set(names).count != names.count { problems.append("duplicate checks") }
        if checks.contains(where: { !($0["pass"] is Bool) }) { problems.append("missing verdict") }
        let failures = checks.filter { $0["pass"] as? Bool == false }.compactMap { $0["name"] as? String }.sorted()
        let expectedFailures = fault == nil ? [] : ["Add Folder Codex native picker", "Add Folder Codex registered harness"]
        if failures != expectedFailures.sorted() { problems.append("unrelated failure") }
        return problems
    }

    private func require(_ condition: Bool, _ message: String) throws {
        guard condition else {
            XCTFail(message)
            throw NSError(domain: "QuoternNativeProof", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    private func beginCase() throws -> (repository: URL, attempt: URL, method: String) {
        executionTimeAllowance = 180
        continueAfterFailure = false
        caseDeadline = min(ContinuousClock().now.advanced(by: .seconds(180)), Self.aggregateDeadline)
        caseStartMs = Native011LivePlatform.monotonicMilliseconds()
        _ = Self.aggregateStartMs
        try require(ContinuousClock().now < caseDeadline, "aggregate native deadline expired")
        let bundle = Bundle(for: Self.self).bundleURL.standardizedFileURL
        try require(bundle == bundle.resolvingSymlinksInPath(), "test bundle has a symlink escape")
        let parts = bundle.pathComponents
        let indices = parts.indices.filter { parts[$0] == "derived-data" }
        try require(indices.count == 1, "test bundle must have one fresh derived-data ancestor")
        let index = try XCTUnwrap(indices.first)
        try require(Array(parts.dropFirst(index + 1).prefix(2)) == ["Build", "Products"], "unexpected product ancestry")
        let attempt = URL(fileURLWithPath: NSString.path(withComponents: Array(parts.prefix(index))), isDirectory: true)
        let proof = attempt.deletingLastPathComponent()
        let repository = proof.deletingLastPathComponent().deletingLastPathComponent()
        try require(proof.lastPathComponent == "proof" && proof.deletingLastPathComponent().lastPathComponent == "build", "attempt is outside repository build/proof")
        try require(FileManager.default.fileExists(atPath: repository.appendingPathComponent("Package.swift").path), "repository manifest missing")
        var ancestor = bundle
        while ancestor.path != "/" {
            let values = try ancestor.resourceValues(forKeys: [.isSymbolicLinkKey, .isAliasFileKey])
            try require(values.isSymbolicLink != true && values.isAliasFile != true, "bundle ancestry contains a link or alias")
            ancestor.deleteLastPathComponent()
        }
        let method = try XCTUnwrap(name.components(separatedBy: " ").last).replacingOccurrences(of: "]", with: "")
        try require(method.hasPrefix("test") && !method.contains("/"), "unexpected test method identity")
        return (repository, attempt, method)
    }

    private func makeFixture(fault: String?, context: (repository: URL, attempt: URL, method: String)) throws -> Fixture {
        let fm = FileManager.default
        let base = context.attempt.appendingPathComponent("fixtures/" + context.method)
        let home = base.appendingPathComponent("home")
        let data = base.appendingPathComponent("data")
        let output = context.attempt.appendingPathComponent("native/" + context.method)
        let wrapper = context.attempt.appendingPathComponent("wrappers/" + context.method + ".app")
        for url in [base, output] {
            var metadata = stat()
            try require(lstat(url.path, &metadata) != 0 && errno == ENOENT, "refusing existing scenario output")
        }
        let original = context.repository.appendingPathComponent(".build/release/Quotern").resolvingSymlinksInPath()
        try require(original.path.hasPrefix(context.repository.appendingPathComponent(".build/").path), "release executable escaped SwiftPM output")
        let archive = context.repository.appendingPathComponent("target/aarch64-apple-darwin/release/libquotern_ffi.a")
        let binary: Data
        let archiveBytes: Data
        let identity: Native011WrapperIdentity
        do {
            _ = try Native011WrapperAdmission.checkedMetadata(original, type: S_IFREG, permissions: 0o755)
            _ = try Native011WrapperAdmission.checkedMetadata(archive, type: S_IFREG, permissions: 0o644)
            do {
                binary = try Data(contentsOf: original)
                archiveBytes = try Data(contentsOf: archive)
            } catch { throw Native011WrapperAdmissionFailure.bytes }
            identity = try Native011WrapperAdmission.admit(attempt: context.attempt, method: context.method,
                                                         original: original, archive: archive, binary: binary, archiveBytes: archiveBytes)
        } catch {
            XCTFail("initial wrapper admission failed: \(failureDiagnostic(error))")
            throw error
        }
        try fm.createDirectory(at: base, withIntermediateDirectories: true)
        try fm.createDirectory(at: output, withIntermediateDirectories: true)
        let sourceHome = context.repository.appendingPathComponent("Fixtures/journey-home")
        _ = try Native011RetainedOutput.files(in: sourceHome)
        try fm.copyItem(at: sourceHome, to: home)
        let expectedURL = home.appendingPathComponent("expected.json")
        let oracle = try json(expectedURL)
        try require((oracle["codex"] as? [String: Any])?["root"] as? String == ".codex", "unexpected Codex fixture")
        try require((oracle["source"] as? [String: Any])?["root"] as? String == ".local/share/opencode", "unexpected OpenCode fixture")
        try require(oracle["now_ms"] as? Int64 == 1_790_769_600_000, "unexpected fixture instant")
        try require((oracle["source_reported"] as? [String: [String: Any]])?["total"]?["value"] as? Int == 42, "unexpected independent OpenCode oracle")
        if let fault {
            var expected = oracle
            expected["picker_fault"] = fault
            try JSONSerialization.data(withJSONObject: expected).write(to: expectedURL, options: .atomic)
        } else {
            try plantHostileFields(home)
            XCTAssertEqual(try Data(contentsOf: expectedURL), try Data(contentsOf: sourceHome.appendingPathComponent("expected.json")))
        }
        let auth = home.appendingPathComponent(".codex/auth.json")
        let permissions = try XCTUnwrap(fm.attributesOfItem(atPath: auth.path)[.posixPermissions] as? NSNumber)
        try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: auth.path)
        let executable = wrapper.appendingPathComponent("Contents/MacOS/Quotern")
        let fixture = Fixture(repository: context.repository, attempt: context.attempt, home: home, data: data, output: output,
                              wrapper: wrapper, method: context.method, wrapperIdentity: identity, executable: executable, original: original, binary: binary,
                              archive: archive, archiveBytes: archiveBytes, authPermissions: permissions)
        try verifyIdentity(fixture)
        try require(UserDefaults(suiteName: fixture.suite)?.persistentDomain(forName: fixture.suite) == nil, "isolated defaults already exist")
        return fixture
    }

    private func failureDiagnostic(_ error: Error) -> String { native011FailureDiagnostic(error) }

    private func verifyIdentity(_ fixture: Fixture) throws {
        do {
            try native011RecheckWrapper(attempt: fixture.attempt, method: fixture.method, original: fixture.original, archive: fixture.archive,
                                        binary: fixture.binary, archiveBytes: fixture.archiveBytes, frozen: fixture.wrapperIdentity)
        } catch {
            XCTFail("wrapper identity recheck failed: \(failureDiagnostic(error))")
            throw error
        }
    }

    private func plantHostileFields(_ home: URL) throws {
        let storage = home.appendingPathComponent(".local/share/opencode/storage")
        for (relative, field) in [
            ("message/ses_journey/msg_journey.json", "modelID"),
            ("part/msg_journey/prt_journey.json", "text"),
            ("session/journey/ses_journey.json", "title"),
        ] {
            let url = storage.appendingPathComponent(relative)
            var object = try json(url)
            object[field] = "api_key=\(Self.sentinel)"
            try JSONSerialization.data(withJSONObject: object).write(to: url, options: .atomic)
        }
        let codexURL = home.appendingPathComponent(".codex/sessions/2026/09/30/rollout-2026-09-30T09-00-00-journey.jsonl")
        let hostile = try String(contentsOf: codexURL, encoding: .utf8).split(separator: "\n").map { line -> String in
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            var payload = try XCTUnwrap(object["payload"] as? [String: Any])
            for field in ["content", "model", "provider", "cwd"] { payload[field] = Self.sentinel }
            object["payload"] = payload
            return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        }.joined(separator: "\n") + "\n"
        XCTAssertTrue(hostile.contains(Self.sentinel))
        try Data(hostile.utf8).write(to: codexURL, options: .atomic)
    }

    private func json(_ url: URL) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func checkWork(until deadline: ContinuousClock.Instant? = nil) throws {
        try Task.checkCancellation()
        guard ContinuousClock().now < min(caseDeadline.advanced(by: .seconds(-5)), deadline ?? caseDeadline) else {
            throw ProofFailure.workDeadline
        }
    }

    private func wait(_ condition: () throws -> Bool, seconds: Int = 60, allowsExit: Bool = false) throws {
        let deadline = min(caseDeadline.advanced(by: .seconds(-5)), ContinuousClock().now.advanced(by: .seconds(seconds)))
        try native011Wait(session, allowsExit: allowsExit, check: { try self.checkWork(until: deadline) },
                          pause: { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }, condition: condition)
    }

    private func unique(_ query: XCUIElementQuery) throws -> XCUIElement {
        try wait { query.count > 0 }
        try checkOwner()
        try require(query.count == 1, "ambiguous native input target")
        let element = query.element
        try wait { element.isHittable }
        try checkOwner()
        try require(!element.frame.isEmpty, "native input has a zero frame")
        return element
    }

    private func checkOwner() throws {
        try checkWork()
        try XCTUnwrap(session).verifyOwners()
    }

    // Native input is admitted only through the launch session: after the exit observer and readiness, never after cancellation.
    private func input(_ action: () throws -> Void) throws {
        try checkWork()
        try XCTUnwrap(session).input(action)
    }

    private func save(_ bytes: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try bytes.write(to: url, options: .atomic)
    }

    private func capture(_ app: XCUIApplication, out: URL, name: String) throws {
        try checkOwner()
        let elements = app.descendants(matching: .any).allElementsBoundByIndex
        try require(!elements.isEmpty, "native accessibility capture is empty")
        let text = try elements.map { element in
            try checkOwner()
            return ["label": element.label, "value": String(describing: element.value ?? ""), "frame": NSStringFromRect(element.frame)]
        }
        try save(try JSONSerialization.data(withJSONObject: text, options: [.sortedKeys]), to: out.appendingPathComponent(name + ".ax.json"))
        try checkOwner()
        let png = app.screenshot().pngRepresentation
        try require(NSImage(data: png) != nil, "native capture does not decode")
        try save(png, to: out.appendingPathComponent(name + ".png"))
        let attachment = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        attachment.name = out.lastPathComponent + "-" + name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func cleanup(_ fixture: Fixture) throws {
        let fm = FileManager.default
        let defaults = try XCTUnwrap(UserDefaults(suiteName: fixture.suite))
        defaults.removePersistentDomain(forName: fixture.suite)
        try require(defaults.persistentDomain(forName: fixture.suite) == nil, "owned defaults cleanup failed")
        try fm.setAttributes([.posixPermissions: fixture.authPermissions], ofItemAtPath: fixture.home.appendingPathComponent(".codex/auth.json").path)
        try fm.removeItem(at: fixture.home.deletingLastPathComponent())
        try save(Data("owned fixture/default cleanup completed\n".utf8), to: fixture.output.appendingPathComponent("cleanup.log"))
    }

    // The candidate identity in every ownership receipt binds the exact frozen bytes of the whole native proof source set:
    // the SHA-256 of one "<file SHA-256>  <repository-relative path>\n" line per file, in `sourceSet` order.
    private func sourceDigest(_ repository: URL) throws -> String {
        var manifest = ""
        for path in Self.sourceSet {
            let source = try Data(contentsOf: repository.appendingPathComponent(path))
            manifest += SHA256.hash(data: source).map { String(format: "%02x", $0) }.joined() + "  " + path + "\n"
        }
        return SHA256.hash(data: Data(manifest.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func probeProxy(_ wrapper: URL) -> Native011ProxyState {
        let application = proxy ?? XCUIApplication(url: wrapper)
        proxy = application
        switch application.state {
        case .runningBackground: return .runningBackground
        case .runningForeground: return .runningForeground
        default: return .other
        }
    }

    private func makeSession(_ fixture: Fixture, phase: String, out: URL) throws -> Native011LaunchSession {
        let runner = try XCTUnwrap(native011ProcessIdentity(pid: getpid()), "runner identity is unobservable")
        let receipt = Native011ReceiptContext(attempt: fixture.attempt.path, method: fixture.method, phase: phase,
                                              candidate: try sourceDigest(fixture.repository), uid: Int(getuid()))
        proxy = nil
        platform.proxyProbe = { [unowned self] in self.probeProxy(fixture.wrapper) }
        platform.statusProbe = { [unowned self] in self.proxy?.statusItems.matching(identifier: "Quotern").count == 1 }
        let context = Native011LaunchContext(receipt: receipt, wrapper: fixture.wrapper.standardizedFileURL,
                                             executable: fixture.executable.standardizedFileURL, runner: runner,
                                             expectedBundleID: "app.quotern.nativeproof." + fixture.method, out: out)
        return Native011LaunchSession(context: context, platform: platform, caseStartMs: caseStartMs,
                                      aggregateStartMs: Self.aggregateStartMs, workCheck: { [unowned self] in try self.checkWork() },
                                      verifyWrapper: { [unowned self] in try self.verifyIdentity(fixture) })
    }

    private final class JourneyProgress {
        var first: [String: Any] = [:]
        var earlyChecks: [[String: Any]] = []
        var controlled = false
    }

    private func deferredCleanup(_ fixture: Fixture, fault: String?, cancel: Bool) {
        Native011DeferredCleanup.run(sessions: sessions, steps: Native011DeferredCleanup.Steps(
            verifyWrapper: { try self.verifyIdentity(fixture) },
            scan: { try self.scanOutputs(fixture, fault: fault, cancelled: cancel) },
            removeFixture: { try self.cleanup(fixture) },
            verifyOutputs: { cleaned in
                try Native011RetainedOutput.final(output: fixture.output, fault: fault, cancelled: cancel, cleaned: cleaned, sessions: self.sessions)
            }), report: { XCTFail($0) })
        session = nil
        sessions = []
    }

    private func runPickerJourney(fault: String? = nil, cancel: Bool = false,
                                  context: (repository: URL, attempt: URL, method: String)? = nil) async throws -> [String: Any] {
        let fixture = try makeFixture(fault: fault, context: context ?? beginCase())
        defer { deferredCleanup(fixture, fault: fault, cancel: cancel) }
        let progress = JourneyProgress()
        for phase in fault == nil && !cancel ? ["first", "restart"] : ["first"] {
            try checkWork()
            let out = fixture.output.appendingPathComponent(phase)
            try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
            let launched = try makeSession(fixture, phase: phase, out: out)
            session = launched
            sessions.append(launched)
            try save(try JSONSerialization.data(withJSONObject: [
                "bundle": Bundle(for: Self.self).bundleURL.path, "wrapper": fixture.wrapper.path, "executable": fixture.executable.path,
                "launcher": launched.context.receipt.argv, "argv": launched.context.receipt.journeyArguments, "archive": fixture.archive.path,
                "original": fixture.original.path, "executable_bytes": fixture.binary.count, "archive_bytes": fixture.archiveBytes.count,
            ], options: [.sortedKeys]), to: out.appendingPathComponent("launch.json"))
            try await launched.runPhase(prelaunch: { try self.verifyIdentity(fixture) }, body: {
                try await self.driveJourney(launched, fixture: fixture, phase: phase, fault: fault, cancel: cancel, out: out, progress: progress)
            }, postexit: {
                if !progress.controlled {
                    try self.assertCompletedPhase(launched, fixture: fixture, phase: phase, fault: fault, out: out, progress: progress)
                }
            })
        }
        return progress.first
    }

    private func driveJourney(_ launched: Native011LaunchSession, fixture: Fixture, phase: String, fault: String?, cancel: Bool,
                              out: URL, progress: JourneyProgress) async throws {
        let proxy = try XCTUnwrap(self.proxy, "exact-URL proxy was never bound")
        try checkOwner()
        let status = try unique(proxy.statusItems.matching(identifier: "Quotern"))
        try capture(proxy, out: out, name: "status")
        try input { status.click() }
        let report = out.appendingPathComponent("journey.json")
        if phase == "first" && (fault == nil || cancel) {
            try wait { FileManager.default.fileExists(atPath: report.path) }
            let early = try json(report)
            XCTAssertFalse(launched.hasExited, "checkpoint observed before child exit")
            XCTAssertEqual(early["result"] as? String, "running")
            XCTAssertEqual(early["complete"] as? Bool, false)
            XCTAssertEqual(early["phase"] as? String, phase)
            XCTAssertEqual(early["application_activation_policy"] as? Int, NSApplication.ActivationPolicy.accessory.rawValue)
            XCTAssertEqual(early["application_active"] as? Bool, true)
            XCTAssertEqual(early["status_item_visible"] as? Bool, true)
            let bounds = try XCTUnwrap(early["status_item_button_bounds"] as? String)
            XCTAssertFalse(NSRectFromString(bounds).isEmpty, bounds)
            XCTAssertEqual(early["status_item_window_visible"] as? Bool, true)
            progress.earlyChecks = try XCTUnwrap(early["checks"] as? [[String: Any]])
            XCTAssertEqual(progress.earlyChecks.compactMap { $0["name"] as? String }, ["Codex auth fixture is unreadable", "status-item click opens the popover"])
            XCTAssertEqual(progress.earlyChecks.first?["pass"] as? Bool, true)
            XCTAssertNotNil(progress.earlyChecks.last?["pass"] as? Bool, "preserve independent click verdict")
            XCTAssertEqual(journeyInventoryProblems(early, phase: phase, fault: fault), ["incomplete journey"])
            try save(try Data(contentsOf: report), to: out.appendingPathComponent("checkpoint.json"))
            progress.first = early
            try capture(proxy, out: out, name: "observed-popover")
        }
        guard phase == "first", fault != "withheld-readiness" else { return }
        for (harness, relative) in [("Codex", ".codex"), ("OpenCode", ".local/share/opencode")] {
            try checkOwner()
            let addFolder = try unique(proxy.buttons.matching(identifier: "Add folder…"))
            try wait { addFolder.isEnabled }
            try input { addFolder.click() }
            let kind = try unique(proxy.popUpButtons.matching(identifier: "Harness"))
            try capture(proxy, out: out, name: harness + "-panel")
            if cancel {
                try await cancellationControl(launched, fixture: fixture, out: out, report: report)
                progress.controlled = true
                return
            }
            try input { kind.click() }
            let item = try unique(proxy.menuItems.matching(identifier: harness))
            try input { item.click() }
            try checkOwner()
            XCTAssertEqual(kind.value as? String, harness)
            try input { proxy.typeKey("g", modifierFlags: [.command, .shift]) }
            let path = try unique(proxy.sheets.textFields)
            try input { path.typeText(fixture.home.appendingPathComponent(relative).path) }
            try input { path.typeKey(XCUIKeyboardKey.return.rawValue, modifierFlags: []) }
            let confirm = try unique(proxy.buttons.matching(identifier: "Read Folder"))
            try checkOwner()
            try input { confirm.click() }
            if fault != nil { break }
            try wait({ launched.hasExited || proxy.popUpButtons.matching(identifier: "Harness").count == 0 }, allowsExit: true)
            if launched.hasExited { break }
            try checkOwner()
            let folderActions = proxy.buttons.matching(identifier: "Add folder…")
            if folderActions.count == 0 || !folderActions.element.isHittable {
                let reopened = try unique(proxy.statusItems.matching(identifier: "Quotern"))
                try input { reopened.click() }
            }
        }
    }

    // Cancellation control: wrong cached owner and wrong executable URL are refused without a signal, input admission
    // closes permanently, then only the verified owners are stopped while the runner survives.
    private func cancellationControl(_ launched: Native011LaunchSession, fixture: Fixture, out: URL, report: URL) async throws {
        XCTAssertEqual(try json(report)["complete"] as? Bool, false)
        XCTAssertNil(UserDefaults(suiteName: fixture.suite)?.persistentDomain(forName: fixture.suite))
        let bystander = Native011LiveApp(NSRunningApplication.current)
        let bystanderPID = bystander.pid
        let bystanderURL = try XCTUnwrap(bystander.executableURL)
        XCTAssertFalse(bystander.isTerminated)
        let owner = try XCTUnwrap(launched.admitted)
        let wrongOwner = Native011AdmittedApplication(app: bystander, identity: owner.identity, executable: owner.executable, bundleURL: owner.bundleURL)
        XCTAssertThrowsError(try launched.signalApplication(wrongOwner)) { XCTAssertEqual(native011FailureDiagnostic($0), "N011-L11") }
        let wrongPIDRefused = !launched.hasExited
        XCTAssertTrue(wrongPIDRefused, "wrong cached owner must not stop the application")
        let wrongURL = Native011AdmittedApplication(app: owner.app, identity: owner.identity, executable: fixture.original, bundleURL: owner.bundleURL)
        XCTAssertThrowsError(try launched.signalApplication(wrongURL)) { XCTAssertEqual(native011FailureDiagnostic($0), "N011-L11") }
        let wrongURLRefused = !launched.hasExited
        XCTAssertTrue(wrongURLRefused, "wrong executable URL must not stop the application")
        launched.cancel(stage: "native-input")
        XCTAssertThrowsError(try launched.input {}) { XCTAssertEqual(native011FailureDiagnostic($0), "N011-L10") }
        let termination = Task { @MainActor in launched.cleanup() }
        termination.cancel()
        await termination.value
        XCTAssertEqual(launched.applicationExit?.reason, "uncaughtSignal")
        XCTAssertNotNil(launched.launcherExit)
        let surviving = try XCTUnwrap(NSRunningApplication(processIdentifier: bystanderPID))
        XCTAssertTrue(surviving.isEqual(bystander.application))
        XCTAssertEqual(surviving.executableURL, bystanderURL)
        XCTAssertFalse(surviving.isTerminated, "unowned runner survives both refusals and exact-owned cancellation")
        try save(try JSONSerialization.data(withJSONObject: ["bystander_pid": Int(bystanderPID), "bystander_executable": bystanderURL.path,
                     "bystander_survived": !surviving.isTerminated, "wrong_pid_refused": wrongPIDRefused, "wrong_url_refused": wrongURLRefused,
                     "cancelled_before_cached_registration": true], options: [.sortedKeys]), to: out.appendingPathComponent("ownership-control.json"))
        try verifyIdentity(fixture)
    }

    private func assertCompletedPhase(_ launched: Native011LaunchSession, fixture: Fixture, phase: String, fault: String?, out: URL,
                                      progress: JourneyProgress) throws {
        XCTAssertEqual(launched.applicationExit?.reason, "exit")
        XCTAssertEqual(launched.applicationExit?.status, fault == nil ? 0 : 1)
        try verifyIdentity(fixture)
        let record = try json(out.appendingPathComponent("journey.json"))
        let checks = try XCTUnwrap(record["checks"] as? [[String: Any]])
        XCTAssertEqual(journeyInventoryProblems(record, phase: phase, fault: fault), [], "complete, unique checks; only injected fault may fail")
        XCTAssertEqual(NSArray(array: Array(checks.prefix(progress.earlyChecks.count))), NSArray(array: progress.earlyChecks), "final preserves actual checkpoint failures")
        for name in ["Codex auth fixture is unreadable", "status-item click opens the popover"] {
            XCTAssertEqual(try XCTUnwrap(checks.first { $0["name"] as? String == name })["pass"] as? Bool, true, name)
        }
        let failures = try checks.filter { try XCTUnwrap($0["pass"] as? Bool) == false }.map { try XCTUnwrap($0["name"] as? String) }
        XCTAssertEqual(failures.sorted(), (fault == nil ? [] : ["Add Folder Codex native picker", "Add Folder Codex registered harness"]).sorted())
        XCTAssertEqual(record["defaults_suite"] as? String, fixture.suite)
        if fault == nil {
            let persisted = try XCTUnwrap(record["persisted_roots"] as? [String])
            XCTAssertEqual(persisted.count, 2)
            XCTAssertEqual(Set(persisted), Set([".codex", ".local/share/opencode"].map { fixture.home.appendingPathComponent($0).standardizedFileURL.path }))
            try assertOracle(record, fixture: fixture)
            let png = try Data(contentsOf: out.appendingPathComponent("popover.png"))
            let image = try XCTUnwrap(NSImage(data: png))
            XCTAssertGreaterThan(image.size.width, 0)
            XCTAssertGreaterThan(image.size.height, 0)
            let attachment = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
            attachment.name = phase + "-completed-popover"
            attachment.lifetime = .keepAlways
            add(attachment)
        }
        if phase == "first" { progress.first = record }
    }

    private func assertOracle(_ record: [String: Any], fixture: Fixture) throws {
        let oracle = try json(fixture.repository.appendingPathComponent("Fixtures/journey-home/expected.json"))
        XCTAssertEqual(NSDictionary(dictionary: try XCTUnwrap(record["expected"] as? [String: Any])), NSDictionary(dictionary: oracle))
        XCTAssertEqual(record["displayed"] as? [String: String], oracle["displayed"] as? [String: String])
        let actual = try XCTUnwrap(record["actual"] as? [String: Any])
        XCTAssertEqual(NSDictionary(dictionary: try XCTUnwrap(actual["window"] as? [String: Any])), NSDictionary(dictionary: try XCTUnwrap(oracle["window"] as? [String: Any])))
        let sources = try XCTUnwrap(actual["by_source"] as? [[String: Any]])
        let reports = try XCTUnwrap(actual["source_reported"] as? [[String: Any]])
        XCTAssertEqual(sources.count, 2)
        XCTAssertEqual(reports.count, 2)
        for harness in ["codex", "opencode"] {
            let source = try XCTUnwrap(sources.first { $0["harness"] as? String == harness })
            let report = try XCTUnwrap(reports.first { $0["source_id"] as? String == source["source_id"] as? String })
            let expected = try XCTUnwrap(harness == "codex" ? (oracle["codex"] as? [String: Any])?["source_reported"] as? [String: Any] : oracle["source_reported"] as? [String: Any])
            for field in ["input", "output", "reasoning", "cache_read", "cache_write", "total"] {
                XCTAssertEqual(NSDictionary(dictionary: try XCTUnwrap(report[field] as? [String: Any])),
                               NSDictionary(dictionary: try XCTUnwrap(expected[field] as? [String: Any])), harness + " " + field)
            }
        }
    }

    private func sinkProblems(_ scan: [String: [Data]], declared: Set<String>) -> [String] {
        var problems = declared.subtracting(scan.keys).sorted().map { "declared but not scanned: \($0)" }
        problems += Set(scan.keys).subtracting(declared).sorted().map { "scanned but not declared: \($0)" }
        for (sink, payloads) in scan.sorted(by: { $0.key < $1.key }) {
            if payloads.allSatisfy(\.isEmpty) { problems.append("empty sink: \(sink)") }
            if payloads.contains(where: { $0.range(of: Data(Self.sentinel.utf8)) != nil }) { problems.append("sentinel in \(sink)") }
        }
        return problems
    }

    private func requiredOutputFiles(_ fixture: Fixture, fault: String?, cancelled: Bool, cleaned: Bool) -> Set<URL> {
        Native011RetainedOutput.requiredFiles(output: fixture.output, fault: fault, cancelled: cancelled, cleaned: cleaned, sessions: sessions)
    }

    private func storagePayloads(in directory: URL, positive: Bool) throws -> [Data] {
        if positive { return try Native011RetainedOutput.files(in: directory).map { try Data(contentsOf: $0) } }
        var metadata = stat()
        guard lstat(directory.path, &metadata) != 0 else { throw ProofFailure.unexpectedStorage }
        guard errno == ENOENT else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        return [try JSONSerialization.data(withJSONObject: ["path": directory.path, "present": false], options: [.sortedKeys])]
    }

    private func scanOutputs(_ fixture: Fixture, fault: String?, cancelled: Bool) throws {
        let positive = fault == nil && !cancelled
        var declared = Self.nativeSinks
        if positive { declared.insert("self-test popover.png") }
        var scan: [String: [Data]] = [:]
        let required = requiredOutputFiles(fixture, fault: fault, cancelled: cancelled, cleaned: false)
        let receipts = Set(Native011RetainedOutput.receiptNames.map { fixture.output.appendingPathComponent($0) })
        let actualFiles = try Native011RetainedOutput.checked(in: fixture.output, required: required.subtracting(receipts))
        for url in actualFiles {
            let bytes = try Data(contentsOf: url)
            try require(!bytes.isEmpty || Self.emptyOutputs.contains(url.lastPathComponent), "empty native output file")
            let bucket = Native011RetainedOutput.bucket(url)
            if url.pathExtension == "png" { _ = try XCTUnwrap(NSImage(data: bytes), "every native image must decode") }
            scan[bucket, default: []].append(bytes)
        }
        scan["data-directory files"] = try storagePayloads(in: fixture.data, positive: positive)
        if !positive { try save(try XCTUnwrap(scan["data-directory files"]?.first), to: fixture.output.appendingPathComponent("data-absence.json")) }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: fixture.suite))
        let domain = defaults.persistentDomain(forName: fixture.suite)
        if positive { _ = try XCTUnwrap(domain, "positive journey must persist actual roots") }
        else { XCTAssertNil(domain, "fault/cancellation must not persist roots") }
        let domainBytes = try PropertyListSerialization.data(fromPropertyList: ["suite": fixture.suite, "present": domain != nil, "domain": domain ?? [:]], format: .xml, options: 0)
        try save(domainBytes, to: fixture.output.appendingPathComponent("defaults.plist"))
        scan["UserDefaults domain"] = [domainBytes]
        scan["wrapper"] = try Native011RetainedOutput.files(in: fixture.wrapper).map { try Data(contentsOf: $0) }
        XCTAssertEqual(sinkProblems(scan, declared: declared), [], "all native sinks must be nonempty, readable and clean")
        let inventory = fixture.output.appendingPathComponent("sink-inventory.json")
        try save(try Native011RetainedOutput.receipt(files: required, buckets: scan.mapValues { $0.count }, cancelled: cancelled), to: inventory)
        _ = try Native011RetainedOutput.checked(in: fixture.output, required: required)
    }
}
#endif
