import AppKit
import CryptoKit
import Darwin
import Foundation

#if NATIVE011_BINDING_SELF_CHECK
extension SelfCheck {
    func expectedPrimaryRecord(_ scenario: Scenario) -> Data {
        guard let primary = scenario.session.retention.primary else { return Data() }
        return Data(("{\"boundary\":\"\(primary.boundary)\",\"observed_elapsed_ms\":\(primary.observedMs),\"producer\":\"native\",\"reason\":\"\(primary.reason)\"," +
                     "\"source_sha256\":\"\(candidate)\",\"stage\":\"\(primary.stage)\",\"v\":1}\n").utf8)
    }

    func retention() async throws {
        let plain = try scenario(configure: { platform, _ in platform.arrivals = [] })
        expect("retention.primary-result", "N011-L04", await run(plain))
        expect("retention.primary-bytes", true, plain.file("primary.json") == expectedPrimaryRecord(plain))
        expect("retention.primary-bound", true, (plain.file("primary.json")?.count ?? Int.max) <= 4_096)
        expect("retention.primary-disposition", "primary", plain.session.retention.disposition.rawValue)
        let first = plain.file("primary.json")
        plain.session.recordFailure(Native011LaunchFailure(.readiness, stage: "secondary", reason: "later"))
        plain.session.cleanup()
        expect("retention.first-primary-survives", true, plain.file("primary.json") == first && plain.primary == "N011-L04")
        let outcomes = plain.session.retention.outcomes.map(\.boundary)
        expect("retention.secondary-outcomes-distinct", true, outcomes.contains("N011-L09") && outcomes.contains("N011-L13"))

        let primaryFaults: [(String, (FaultOps, String, String, Int) -> Bool)] = [
            ("primary-create", { _, op, path, _ in op == "open" && path.hasSuffix("primary.json.tmp") }),
            ("primary-write", { _, op, path, _ in op == "write" && path.hasSuffix("primary.json.tmp") }),
            ("primary-file-sync", { _, op, path, _ in op == "fsync" && path.hasSuffix("primary.json.tmp") }),
            ("primary-close", { _, op, path, _ in op == "close" && path.hasSuffix("primary.json.tmp") }),
            ("primary-replace", { _, op, path, _ in op == "rename" && path.hasSuffix("primary.json") }),
            ("primary-directory-sync", { faults, op, path, _ in op == "fsync" && faults.publishingPrimary && path.hasSuffix("/first") }),
            ("primary-readback", { _, op, path, _ in op == "open" && path.hasSuffix("/primary.json") }),
        ]
        for (name, fails) in primaryFaults {
            let faults = FaultOps(fails)
            let faulted = try scenario(ops: faults.ops, configure: { platform, _ in platform.arrivals = [] })
            expect("retention.\(name).result", "N011-L04", await run(faulted))
            let error = faulted.session.retention.errors.first
            expect("retention.\(name)", "fallback N011-L14 \(name) true",
                   "\(faulted.session.retention.disposition.rawValue) \(error?.boundary ?? "none") \(error?.stage ?? "none") \(faulted.file("primary-fallback.log") == expectedPrimaryRecord(faulted))")
            expect("retention.\(name).fallback-never-passes", true, !faulted.session.retention.errors.isEmpty)
        }

        let both = FaultOps { _, op, path, _ in
            (op == "open" && path.hasSuffix("primary.json.tmp")) || (op == "lseek" && path.hasSuffix("primary-fallback.log"))
        }
        let unknown = try scenario(ops: both.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("retention.both-fail.result", "N011-L09", await run(unknown))
        expect("retention.both-fail.unknown", "unknown", unknown.session.retention.disposition.rawValue)
        expect("retention.both-fail.admission", "closed", unknown.session.admission.rawValue)
        unknown.session.cleanup()
        expect("retention.both-fail.no-signals-no-deletion", "0 0 false false",
               "\(unknown.app.terminations) \(unknown.platform.launcher?.terminations ?? -1) \(unknown.session.mayDelete) \(unknown.session.mayScan)")
        let stages = unknown.session.retention.errors.map(\.stage)
        expect("retention.both-fail.attribution", true, stages.contains("primary-create") && stages.contains("fallback-write"))
        var calls: [String] = []
        var reports: [String] = []
        Native011DeferredCleanup.run(sessions: [unknown.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: { calls.append("wrapper") }, scan: { calls.append("scan") }, removeFixture: { calls.append("remove") },
            verifyOutputs: { _ in calls.append("outputs") }), report: { reports.append($0) })
        expect("retention.both-fail.deferred-withholds", "wrapper,outputs", calls.joined(separator: ","))
        expect("retention.both-fail.deferred-reports", true, reports.contains { $0.contains("withheld") })

        var disturbed = false
        let drift = FaultOps { _, op, path, _ in op == "open" && path.hasSuffix("primary.json.tmp") }
        let identityScenario = try scenario(ops: drift.ops, configure: { platform, _ in platform.arrivals = [] })
        let fallbackURL = identityScenario.out.appendingPathComponent("primary-fallback.log")
        identityScenario.platform.workCheckHook = {
            guard !disturbed, identityScenario.platform.log.contains("launcher-start") else { return }
            disturbed = true
            try FileManager.default.removeItem(at: fallbackURL)
            FileManager.default.createFile(atPath: fallbackURL.path, contents: Data(), attributes: [.posixPermissions: 0o600])
        }
        expect("retention.fallback-identity.result", "N011-L04", await run(identityScenario))
        let identityStages = identityScenario.session.retention.errors.map(\.stage)
        expect("retention.fallback-identity", "unknown true", "\(identityScenario.session.retention.disposition.rawValue) \(identityStages.contains("fallback-identity"))")

        try await retentionOwnership()
    }

    func retentionOwnership() async throws {
        let ownership: [(String, (FaultOps, String, String, Int) -> Bool)] = [
            ("ownership-write", { _, op, path, _ in op == "write" && path.hasSuffix("ownership.json.tmp") }),
            ("ownership-readback", { _, op, path, _ in op == "read-short" && path.hasSuffix("/ownership.json") }),
            ("ownership-readback", { _, op, path, _ in op == "read-drift" && path.hasSuffix("/ownership.json") }),
        ]
        for (index, (stage, fails)) in ownership.enumerated() {
            let faulted = try scenario(ops: FaultOps(fails).ops)
            expect("retention.ownership-\(index)", "N011-L14 \(stage) false",
                   "\(await run(faulted)) \(faulted.session.retention.primary?.stage ?? "none") \(faulted.platform.log.contains("launcher-start"))")
        }
        let preparation: [(String, (FaultOps, String, String, Int) -> Bool)] = [
            ("fallback-create", { _, op, path, _ in op == "open" && path.hasSuffix("primary-fallback.log") }),
            ("fallback-prepare-file-sync", { _, op, path, _ in op == "fsync" && path.hasSuffix("primary-fallback.log") }),
            ("fallback-prepare-directory-sync", { _, op, path, count in op == "fsync" && path.hasSuffix("/first") && count == 1 }),
            ("fallback-prepare-readback", { _, op, path, count in op == "open" && path.hasSuffix("primary-fallback.log") && count == 2 }),
        ]
        for (stage, fails) in preparation {
            let faulted = try scenario(ops: FaultOps(fails).ops)
            expect("retention.\(stage)", "N011-L14 \(stage) false", "\(await run(faulted)) \(faulted.session.retention.primary?.stage ?? "none") \(faulted.platform.log.contains("launcher-start"))")
        }
        let shortWrites = FaultOps { _, _, _, _ in false }
        shortWrites.shortWrites = true
        let short = try scenario(ops: shortWrites.ops)
        var captured: Data?
        let shortResult = await run(short, body: { captured = short.file("ownership.json"); try short.session.input {} })
        expect("retention.short-writes-complete", "pass true none", "\(shortResult) \(captured == Data(native011OwnershipFixture.utf8)) \(short.primary)")

        // The first destructive cleanup effect (application termination) must find the exact record already durable.
        var snapshot: Data?
        var location: URL?
        let probe = try scenario(configure: { platform, app in
            platform.proxy = [.unavailable]
            app.onTerminate = { [unowned platform] in
                if let location { snapshot = try? Data(contentsOf: location.appendingPathComponent("primary.json")) }
                platform.observer.exitAtMs = platform.clock
                platform.observer.exit = .exited(rawWaitStatus: 9)
                platform.launcher?.exitAtMs = platform.clock + 50
            }
        })
        location = probe.out
        _ = await run(probe)
        probe.session.cleanup()
        expect("retention.durable-before-first-signal", true, snapshot != nil && snapshot == expectedPrimaryRecord(probe))
    }

    func deferredCleanup() async throws {
        let failing = try scenario(configure: { platform, _ in platform.arrivals = [] })
        _ = await run(failing)
        let primaryBytes = failing.file("primary.json")
        var order: [String] = []
        var reports: [String] = []
        var ownerCleanupFirst = false
        Native011DeferredCleanup.run(sessions: [failing.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: {
                ownerCleanupFirst = failing.session.events.contains { $0.stage == "cleanup-begin" }
                order.append("wrapper")
                throw Native011WrapperAdmissionFailure.path
            },
            scan: { order.append("scan"); throw ProofFailure.outputInventory },
            removeFixture: { order.append("remove") },
            verifyOutputs: { _ in order.append("outputs"); throw ProofFailure.unexpectedStorage }), report: { reports.append($0) })
        expect("deferred.owner-cleanup-first", true, ownerCleanupFirst)
        expect("deferred.order", "wrapper,scan,outputs,outputs", order.joined(separator: ","))
        expect("deferred.primary-survives", true, failing.file("primary.json") == primaryBytes && failing.primary == "N011-L04")
        expect("deferred.secondary-outcomes", "N011-L13,N011-C-PATH,outputInventory,unexpectedStorage",
               failing.session.retention.outcomes.map(\.boundary).joined(separator: ","))
        expect("deferred.reports", "4", String(reports.filter { $0.hasPrefix("deferred-") }.count))
        expect("deferred.confirmation-reported", true, reports.contains("deferred-outputs-final: unexpectedStorage"))
        expect("deferred.unresolved-launch-reported", true, reports.contains("pending-launch: N011-L13"))
        expect("deferred.receipt-survives", "unknown app[nil] launcher[uncaughtSignal 15]", failing.summary)
        expect("deferred.diagnostic-survives", true, String(decoding: failing.file("diagnostic.json") ?? Data(), as: UTF8.self).contains("\"boundary\":\"N011-L04\""))
        expect("deferred.no-false-join", false, failing.session.mayDelete)

        let unresolved = try scenario(configure: { platform, _ in platform.arrivals = [] })
        _ = await run(unresolved)
        order = []
        reports = []
        Native011DeferredCleanup.run(sessions: [unresolved.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: { order.append("wrapper") }, scan: { order.append("scan") }, removeFixture: { order.append("remove") },
            verifyOutputs: { _ in order.append("outputs") }), report: { reports.append($0) })
        expect("deferred.unresolved-never-deletes", "wrapper,scan,outputs", order.joined(separator: ","))
        expect("deferred.unresolved-reported", true, reports.contains { $0.contains("deletion withheld") })

        let clean = try scenario()
        _ = await run(clean)
        order = []
        Native011DeferredCleanup.run(sessions: [clean.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: { order.append("wrapper") }, scan: { order.append("scan") }, removeFixture: { order.append("remove") },
            verifyOutputs: { cleaned in order.append("outputs:\(cleaned)") }), report: { _ in order.append("report") })
        expect("deferred.resolved-deletes", "wrapper,scan,outputs:false,remove,outputs:true", order.joined(separator: ","))

        let only = try scenario()
        _ = await run(only)
        order = []
        reports = []
        Native011DeferredCleanup.run(sessions: [only.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: {}, scan: { throw ProofFailure.outputInventory }, removeFixture: { order.append("remove") },
            verifyOutputs: { _ in }), report: { reports.append($0) })
        expect("deferred.cleanup-only-fails", "outputInventory 1 false", "\(only.primary) \(reports.count) \(order.contains("remove"))")
        expect("deferred.cleanup-only-primary-file", true, only.file("primary.json") == expectedPrimaryRecord(only))

        let faults = FaultOps { _, op, path, _ in op == "rename" && path.hasSuffix("primary.json") }
        let fallback = try scenario(ops: faults.ops, configure: { platform, _ in platform.arrivals = [] })
        _ = await run(fallback)
        reports = []
        Native011DeferredCleanup.run(sessions: [fallback.session], steps: Native011DeferredCleanup.Steps(
            verifyWrapper: {}, scan: {}, removeFixture: {}, verifyOutputs: { _ in }), report: { reports.append($0) })
        expect("deferred.retention-error-never-passes", true, reports.contains { $0.contains("retention") })
    }

    func bounds() async throws {
        let flood = try scenario(configure: { platform, _ in
            platform.proxy = (0..<2_600).map { $0 % 2 == 0 ? Native011ProxyState.other : .unavailable }
        })
        expect("bound.events.result", "N011-L15", await run(flood))
        expect("bound.events", "256 N011-L15 none", "\(flood.session.events.count) \(flood.primary) \(flood.session.retention.outcomes.first?.boundary ?? "none")")
        let limited = try scenario(configure: { platform, _ in platform.arrivals = [] })
        _ = await run(limited)
        for index in 0..<40 { limited.session.recordFailure(Native011LaunchFailure(.readiness, stage: "bounded", reason: "\(index)")) }
        expect("bound.outcomes", "32 N011-L15", "\(limited.session.retention.outcomes.count) \(limited.session.retention.errors.first?.boundary ?? "none")")
        let slow = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        _ = await run(slow)
        slow.platform.pauseHook = { $0.clock += 6_000 }
        slow.session.cleanup()
        expect("bound.cleanup-elapsed", true, slow.session.retention.outcomes.contains { $0.boundary == "native-deadline" && $0.stage == "cleanup" })
        let old = try scenario(caseStartMs: -200_000, configure: { platform, _ in platform.proxy = [.unavailable] })
        _ = await run(old)
        old.session.cleanup()
        expect("bound.case-elapsed", true, old.session.retention.outcomes.contains { $0.boundary == "native-deadline" && $0.stage == "case" })
    }

    // Real OS leaves with real children only: no native application, no shell on the product launch path.
    func liveLeaves() {
        let identity = native011ProcessIdentity(pid: getpid())
        let name = URL(fileURLWithPath: CommandLine.arguments[0]).lastPathComponent
        expect("live.self-identity", true, identity.map {
            $0.pid == Int(getpid()) && $0.uid == Int(getuid()) && URL(fileURLWithPath: $0.path).lastPathComponent == name &&
                $0.sec > 0 && (0...999_999).contains($0.usec)
        } ?? false)
        let platform = Native011LivePlatform()
        func observe(_ argv: [String], terminate: Bool = false) -> String {
            do {
                let launcher = try platform.startLauncher(argv: argv)
                let observer = try platform.observeExit(pid: launcher.pid)
                if terminate { launcher.terminate() }
                let deadline = Date().addingTimeInterval(10)
                while Date() < deadline {
                    if case .exited(let raw) = observer.poll() {
                        let kernel = Native011ExitRecord.application(rawWaitStatus: raw).map { "\($0.reason) \($0.status)" } ?? "invalid"
                        while launcher.isRunning, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
                        return kernel + " / " + (launcher.exit.map { "\($0.reason) \($0.status)" } ?? "running")
                    }
                    Thread.sleep(forTimeInterval: 0.02)
                }
                return "timeout"
            } catch { return "error \(error)" }
        }
        expect("live.kernel-exit-0", "exit 0 / exit 0", observe(["/bin/sleep", "1"]))
        expect("live.kernel-exit-1", "exit 1 / exit 1", observe(["/bin/sh", "-c", "sleep 1; exit 1"]))
        expect("live.kernel-signal-15", "uncaughtSignal 15 / uncaughtSignal 15", observe(["/bin/sleep", "30"], terminate: true))
        var late = "registered"
        do {
            let launcher = try platform.startLauncher(argv: ["/usr/bin/true"])
            let deadline = Date().addingTimeInterval(10)
            while launcher.isRunning, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
            _ = launcher.exit
            _ = try platform.observeExit(pid: launcher.pid)
        } catch { late = "\(error)" }
        expect("live.exited-before-observation", "alreadyExited", late)
        var denied = "registered"
        do { _ = try platform.observeExit(pid: 1) } catch { denied = "\(error)" }
        expect("live.observer-denied-for-foreign-owner", "denied", denied)
    }
}

// MARK: launch-build correction regressions: each drives the actual session, retention and deferred-cleanup code.

@MainActor struct WrapperFixture {
    let attempt: URL, original: URL, archive: URL, binary: Data, archiveBytes: Data, method: String, frozen: Native011WrapperIdentity
    var plist: URL { frozen.wrapper.appendingPathComponent("Contents/Info.plist") }
    var executable: URL { frozen.wrapper.appendingPathComponent("Contents/MacOS/Quotern") }

    func verify() throws {
        try native011RecheckWrapper(attempt: attempt, method: method, original: original, archive: archive, binary: binary,
                                    archiveBytes: archiveBytes, frozen: frozen)
    }
}

extension SelfCheck {
    // Independent expectation of a retained primary: literal fields, never read back from the actual retention.
    func primaryBytes(_ boundary: String, _ stage: String, _ reason: String, elapsed: Int) -> Data {
        Data(("{\"boundary\":\"\(boundary)\",\"observed_elapsed_ms\":\(elapsed),\"producer\":\"native\",\"reason\":\"\(reason)\"," +
              "\"source_sha256\":\"\(candidate)\",\"stage\":\"\(stage)\",\"v\":1}\n").utf8)
    }

    func twin(of app: ScriptedApp, _ platform: ScriptedPlatform) -> ScriptedApp {
        let second = ScriptedApp(pid: 14, token: 2, bundleURL: app.bundleURL, executableURL: app.executableURL, bundleIdentifier: app.bundleIdentifier)
        platform.lookups[14] = second
        return second
    }

    func runDeferred(_ subject: Scenario, with others: [Scenario] = [], wrapper: @escaping () throws -> Void = {}, scan: @escaping () throws -> Void = {},
                     remove: @escaping () throws -> Void = {}, outputs: @escaping () throws -> Void = {}) -> (order: [String], reports: [String]) {
        var order: [String] = []
        var reports: [String] = []
        Native011DeferredCleanup.run(sessions: ([subject] + others).map(\.session), steps: Native011DeferredCleanup.Steps(
            verifyWrapper: { order.append("wrapper"); try wrapper() }, scan: { order.append("scan"); try scan() },
            removeFixture: { order.append("remove"); try remove() },
            verifyOutputs: { cleaned in self.deferredCleaned = cleaned; order.append("outputs"); try outputs() }),
                                        report: { reports.append($0) })
        return (order, reports)
    }

    func inputCount(_ subject: Scenario) -> String { String(subject.platform.log.filter { $0 == "input" }.count) }

    // Independent readback of the bounded second evidence file: parsed from the disk bytes, never from the actual retention.
    func secondaryRecord(_ subject: Scenario) -> (head: String, errors: [String], outcomes: [String]) {
        guard let data = subject.file("secondary.json"), data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return ("absent", [], []) }
        func rows(_ key: String) -> [String] {
            ((object[key] as? [[String: String]]) ?? []).map { "\($0["boundary"] ?? ""):\($0["stage"] ?? ""):\($0["reason"] ?? "")" }
        }
        let primary = object["primary"] as? [String: Any]
        let head = ["\(object["v"] ?? "-")", object["producer"] as? String ?? "-", object["method"] as? String ?? "-",
                    object["phase"] as? String ?? "-", object["source_sha256"] as? String == candidate ? "candidate" : "other",
                    "\(primary?["boundary"] ?? ""):\(primary?["stage"] ?? ""):\(primary?["reason"] ?? ""):\(primary?["observed_elapsed_ms"] ?? "")"]
        return (head.joined(separator: " "), rows("errors"), rows("outcomes"))
    }

    // MARK: early application exit: the wait fails before evaluating its condition, retains the exit, then reaps the launcher

    func earlyExit() async throws {
        let gate = Pipe()
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "read line; exit 7"]
        child.standardInput = gate
        try child.run()
        // The real EVFILT_PROC observer is installed before the held child is released.
        let observer = try Native011LiveExitObserver(pid: child.processIdentifier)
        let subject = try scenario(configure: { platform, _ in platform.observerOverride = { _ in observer } })
        var evaluations = 0, checks = 0
        var thrown = "none", retained = "none", launcherOwned = false
        let result = await run(subject, body: {
            try gate.fileHandleForWriting.write(contentsOf: Data("\n".utf8))
            let deadline = Date().addingTimeInterval(10)
            while child.isRunning, Date() < deadline { usleep(10_000) }
            do {
                try native011Wait(subject.session, allowsExit: false, check: { checks += 1; if checks > 3 { throw ProofFailure.workDeadline } },
                                  pause: { subject.platform.pause() }, condition: { evaluations += 1; return false })
            } catch { thrown = native011FailureDiagnostic(error) }
            retained = subject.summary
            launcherOwned = subject.platform.launcher?.isRunning == true && subject.session.launcherExit == nil
        })
        expect("earlyexit.wait-fails-before-condition", "childExited 0", "\(thrown) \(evaluations)")
        expect("earlyexit.exit-retained-before-finalization", "app-exited app[exit 7] launcher[nil]", retained)
        expect("earlyexit.launcher-still-separately-owned", true, launcherOwned)
        expect("earlyexit.result", "pass", result)
        subject.session.cleanup()
        expect("earlyexit.final-receipt", "closed app[exit 7] launcher[exit 0]", subject.summary)
        let exit = subject.session.applicationExit
        expect("earlyexit.kernel-status", "EVFILT_PROC_NOTE_EXITSTATUS exit 7 1792", "\(exit?.source ?? "") \(exit?.reason ?? "") \(exit?.status ?? -1) \(exit?.rawWaitStatus ?? -1)")
        expect("earlyexit.reaped-without-signal", "false 0", "\(child.isRunning) \(subject.app.terminations)")
    }

    // MARK: frozen wrapper, plist and executable are rechecked before every native input

    // The wrapper admission refuses any symlinked ancestor, and the temporary directory lives under the /var symlink, so these
    // fixtures live in a uniquely named directory under the home directory and are removed when the self-check ends.
    var wrapperParent: URL { URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".native011-wrapper-" + root.lastPathComponent) }

    func wrapperFixture(_ label: String) throws -> WrapperFixture {
        let fm = FileManager.default
        let base = wrapperParent.appendingPathComponent(label)
        let attempt = base.appendingPathComponent("attempt")
        let wrapper = attempt.appendingPathComponent("wrappers/" + method + ".app")
        let originals = base.appendingPathComponent("original")
        try fm.createDirectory(at: base, withIntermediateDirectories: true)
        for (directory, mode) in [(attempt, 0o755), (attempt.appendingPathComponent("wrappers"), 0o755), (wrapper, 0o700),
                                  (wrapper.appendingPathComponent("Contents"), 0o700), (wrapper.appendingPathComponent("Contents/MacOS"), 0o700),
                                  (originals, 0o755)] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: false)
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: directory.path)
        }
        func put(_ url: URL, _ data: Data, _ mode: Int) throws {
            try data.write(to: url)
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        }
        // A 64-bit ARM Mach-O executable header with exactly one macOS 14.0 build-version command.
        var binary = Data()
        for word: UInt32 in [0xfeedfacf, 0x0100000c, 0, 2, 1, 24, 0, 0, 0x32, 24, 1, 14 << 16, 0, 0] {
            for shift: UInt32 in [0, 8, 16, 24] { binary.append(UInt8((word >> shift) & 0xff)) }
        }
        let archiveBytes = Data("!<arch>\n".utf8) + Data(repeating: 0x20, count: 8)
        let plist = try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleExecutable": "Quotern", "CFBundleIdentifier": "app.quotern.nativeproof." + method, "LSUIElement": true,
        ] as [String: Any], format: .xml, options: 0)
        let original = originals.appendingPathComponent("Quotern")
        let archive = originals.appendingPathComponent("libquotern_ffi.a")
        try put(original, binary, 0o755)
        try put(archive, archiveBytes, 0o644)
        try put(wrapper.appendingPathComponent("Contents/Info.plist"), plist, 0o600)
        try put(wrapper.appendingPathComponent("Contents/MacOS/Quotern"), binary, 0o755)
        let frozen = try Native011WrapperAdmission.admit(attempt: attempt, method: method, original: original, archive: archive,
                                                         binary: binary, archiveBytes: archiveBytes)
        return WrapperFixture(attempt: attempt, original: original, archive: archive, binary: binary, archiveBytes: archiveBytes,
                              method: method, frozen: frozen)
    }

    func wrapperDrift() async throws {
        func rewritePlist(_ target: WrapperFixture, _ extra: [String: Any]) throws {
            let object = ["CFBundleExecutable": "Quotern", "CFBundleIdentifier": "app.quotern.nativeproof." + method, "LSUIElement": true] as [String: Any]
            try PropertyListSerialization.data(fromPropertyList: object.merging(extra) { $1 }, format: .xml, options: 0).write(to: target.plist)
        }
        struct DriftCase {
            let name: String
            let expected: String
            let inputsBeforeDrift: Int
            let drift: (WrapperFixture) throws -> Void
        }
        let cases: [DriftCase] = [
            DriftCase(name: "control", expected: "pass", inputsBeforeDrift: 0,
                      drift: { _ in }),
            DriftCase(name: "plist-rewritten", expected: "N011-C-PATH", inputsBeforeDrift: 0,
                      drift: { try (Data(contentsOf: $0.plist) + Data("\n".utf8)).write(to: $0.plist) }),
            DriftCase(name: "plist-extra-key", expected: "N011-C-CONTENTS", inputsBeforeDrift: 0,
                      drift: { try rewritePlist($0, ["Extra": "key"]) }),
            DriftCase(name: "executable-bytes", expected: "N011-C-BYTES", inputsBeforeDrift: 0,
                      drift: { try (Data(contentsOf: $0.executable) + Data([0])).write(to: $0.executable) }),
            DriftCase(name: "executable-replaced-same-bytes", expected: "N011-C-PATH", inputsBeforeDrift: 0, drift: { target in
                try FileManager.default.removeItem(at: target.executable)
                try target.binary.write(to: target.executable)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: target.executable.path)
            }),
            DriftCase(name: "executable-mode", expected: "N011-C-PATH", inputsBeforeDrift: 0,
                      drift: { try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: $0.executable.path) }),
            DriftCase(name: "between-inputs", expected: "N011-C-PATH", inputsBeforeDrift: 1,
                      drift: { try (Data(contentsOf: $0.plist) + Data("\n".utf8)).write(to: $0.plist) }),
        ]
        for driftCase in cases {
            let name = driftCase.name
            let expected = driftCase.expected
            let before = driftCase.inputsBeforeDrift
            let target = try wrapperFixture(name)
            let subject = try scenario(verifyWrapper: { try target.verify() })
            let result = await run(subject, body: {
                for _ in 0..<before { try subject.session.input { subject.platform.log.append("input") } }
                try driftCase.drift(target)
                try subject.session.input { subject.platform.log.append("input") }
            })
            expect("wrapper.\(name).result", expected, result)
            expect("wrapper.\(name).input-effects", String(name == "control" ? 1 : before), inputCount(subject))
            expect("wrapper.\(name).primary", expected == "pass" ? "none" : expected, subject.primary)
            expect("wrapper.\(name).untouched", true, subject.untouched)
        }
    }

    // MARK: a staggered second exact application is ambiguity through readiness, input and closure; it is never signalled

    func staggeredArrivals() async throws {
        func ambiguity(_ name: String, _ subject: Scenario, _ twin: ScriptedApp, result: String, inputs: Int, receipt: String, ownerSignals: Int = 1) {
            let primary = subject.session.retention.primary
            expect("stagger.\(name).result", "N011-L04", result)
            expect("stagger.\(name).primary", "N011-L04 arrival ambiguous", "\(subject.primary) \(primary?.stage ?? "none") \(primary?.reason ?? "none")")
            expect("stagger.\(name).input-effects", String(inputs), inputCount(subject))
            expect("stagger.\(name).unadmitted-never-signalled", "0 0", "\(twin.terminations) \(subject.bystander.terminations)")
            subject.session.cleanup()
            expect("stagger.\(name).owner-cleaned-only-while-running", String(ownerSignals), String(subject.app.terminations))
            expect("stagger.\(name).unresolved", "\(receipt) false", "\(subject.summary) \(subject.session.mayDelete)")
            expect("stagger.\(name).input-closed", "N011-L10", inputOutcome(subject))
        }
        var readinessTwin: ScriptedApp?
        let readiness = try scenario(configure: { platform, app in
            app.isFinishedLaunching = false
            let second = self.twin(of: app, platform)
            readinessTwin = second
            platform.arrivals.append((150, second))
            platform.pauseHook = { platform in if platform.clock >= 200 { app.isFinishedLaunching = true } }
        })
        ambiguity("during-readiness", readiness, readinessTwin!, result: await run(readiness), inputs: 0, receipt: "unknown app[uncaughtSignal 9] launcher[exit 0]")

        // Readiness that never completes still ends as ambiguity, not as a readiness timeout.
        var pendingTwin: ScriptedApp?
        let pending = try scenario(configure: { platform, app in
            platform.proxy = [.unavailable]
            let second = self.twin(of: app, platform)
            pendingTwin = second
            platform.arrivals.append((150, second))
        })
        ambiguity("readiness-pending", pending, pendingTwin!, result: await run(pending), inputs: 0, receipt: "unknown app[uncaughtSignal 9] launcher[exit 0]")

        let before = try scenario()
        let beforeTwin = twin(of: before.app, before.platform)
        let beforeResult = await run(before, body: {
            before.platform.arrivals.append((before.platform.clock, beforeTwin))
            try before.session.input { before.platform.log.append("input") }
        })
        ambiguity("before-input", before, beforeTwin, result: beforeResult, inputs: 0, receipt: "unknown app[uncaughtSignal 9] launcher[exit 0]")

        let after = try scenario()
        let afterTwin = twin(of: after.app, after.platform)
        let afterResult = await run(after, body: {
            try after.session.input { after.platform.log.append("input") }
            after.platform.arrivals.append((after.platform.clock, afterTwin))
        })
        ambiguity("after-input", after, afterTwin, result: afterResult, inputs: 1, receipt: "unknown app[uncaughtSignal 9] launcher[exit 0]")

        let closure = try scenario()
        let closureTwin = twin(of: closure.app, closure.platform)
        let closureResult = await run(closure, body: {
            try closure.session.input { closure.platform.log.append("input") }
            closure.platform.arrivals.append((closure.platform.clock + 120, closureTwin))
        })
        ambiguity("at-closure", closure, closureTwin, result: closureResult, inputs: 1, receipt: "unknown app[exit 0] launcher[exit 0]", ownerSignals: 0)

        // Arrival while an unresolved request is cleaned: the exact owner is stopped, the late app never is.
        let cleanup = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        _ = await run(cleanup)
        let cleanupTwin = twin(of: cleanup.app, cleanup.platform)
        cleanup.platform.arrivals.append((cleanup.platform.clock, cleanupTwin))
        cleanup.session.cleanup()
        expect("stagger.during-cleanup", "1 0 true unknown app[uncaughtSignal 9] launcher[exit 0] false",
               "\(cleanup.app.terminations) \(cleanupTwin.terminations) " +
               "\(cleanup.session.retention.outcomes.contains { $0.boundary == "N011-L04" && $0.reason == "ambiguous" }) \(cleanup.summary) " +
               "\(cleanup.session.mayDelete)")

        // A later phase of the same wrapper after the request closed is a new request, not a late arrival of this one.
        let closed = try scenario()
        _ = await run(closed)
        closed.platform.arrivals.append((closed.platform.clock, twin(of: closed.app, closed.platform)))
        closed.session.cleanup()
        expect("stagger.after-closure-is-next-request", "closed app[exit 0] launcher[exit 0] true", "\(closed.summary) \(closed.session.mayDelete)")
    }

    // MARK: the event cap is terminal for work and input, and never replaces the incoming first failure

    func eventCap() async throws {
        let flip: [Native011ProxyState] = (0..<2_600).map { $0 % 2 == 0 ? .other : .unavailable }
        let recovered = try scenario(configure: { platform, _ in platform.proxy = Array(flip.prefix(300)) + [.runningForeground] })
        expect("cap.overflow-then-ready.result", "N011-L15", await run(recovered))
        let recoveredPrimary = recovered.session.retention.primary
        expect("cap.overflow-then-ready", "N011-L15 readiness events 256 closed 0",
               "\(recovered.primary) \(recoveredPrimary?.stage ?? "none") \(recoveredPrimary?.reason ?? "none") \(recovered.session.events.count) " +
               "\(recovered.session.admission.rawValue) \(inputCount(recovered))")
        expect("cap.overflow-then-ready.stopped-before-recovery", true, recovered.platform.proxyCalls < 300)
        expect("cap.overflow-then-ready.input-closed", "N011-L10", inputOutcome(recovered))

        // The 257th event is the one that reports readiness: the launch itself must fail, not merely find input closed.
        let atReady = try scenario(configure: { platform, _ in platform.proxy = Array(flip.prefix(252)) + [.runningForeground] })
        expect("cap.overflow-at-ready.result", "N011-L15", await run(atReady))
        expect("cap.overflow-at-ready", "N011-L15 256 closed 0 253",
               "\(atReady.primary) \(atReady.session.events.count) \(atReady.session.admission.rawValue) \(inputCount(atReady)) \(atReady.platform.proxyCalls)")

        var cancelBox: Native011LaunchSession?
        var cancelledAt = -1
        let cancelled = try scenario(configure: { platform, _ in
            platform.proxy = flip
            platform.workCheckHook = {
                guard let session = cancelBox, session.events.count >= 256, cancelledAt < 0 else { return }
                cancelledAt = platform.clock
                throw CancellationError()
            }
        })
        cancelBox = cancelled.session
        expect("cap.exact-capacity.cancellation.result", "CancellationError()", await run(cancelled))
        expect("cap.exact-capacity.cancellation", "256 N011-L10 N011-L15 true",
               "\(cancelled.session.events.count) \(cancelled.primary) \(cancelled.session.retention.outcomes.first?.boundary ?? "none") " +
               "\(cancelled.file("primary.json") == primaryBytes("N011-L10", "phase", "cancelled", elapsed: cancelledAt))")

        var ownerBox: Native011LaunchSession?
        var changedAt = -1
        let owner = try scenario(configure: { platform, _ in
            platform.proxy = flip
            platform.workCheckHook = {
                guard let session = ownerBox, session.events.count >= 256, changedAt < 0 else { return }
                changedAt = platform.clock
                platform.identities[13] = platform.identities[13].map { Native011Identity(pid: $0.pid, sec: 999, usec: $0.usec, uid: $0.uid, path: $0.path) }
            }
        })
        ownerBox = owner.session
        expect("cap.exact-capacity.owner.result", "N011-L05", await run(owner))
        expect("cap.exact-capacity.owner", "256 N011-L05 N011-L15 true",
               "\(owner.session.events.count) \(owner.primary) \(owner.session.retention.outcomes.first?.boundary ?? "none") " +
               "\(owner.file("primary.json") == primaryBytes("N011-L05", "owner-refresh", "changed", elapsed: changedAt))")
    }

    // MARK: cleanup, case and aggregate bounds are measured through every final effect; an overrun forbids later signals and deletion

    func deadlines() async throws {
        let late = try scenario()
        expect("deadline.late-scan.phase", "pass", await run(late))
        let lateRun = runDeferred(late, scan: { late.platform.clock += 200_000 })
        expect("deadline.late-scan", "wrapper,scan,outputs native-deadline true false",
               "\(lateRun.order.joined(separator: ",")) \(late.primary) \(lateRun.reports.contains("case: native-deadline")) \(late.session.mayDelete)")
        expect("deadline.late-scan.primary-bytes", true, late.file("primary.json") == primaryBytes("native-deadline", "case", "elapsed", elapsed: late.platform.clock))

        let aggregate = try scenario(caseStartMs: 900_000)
        expect("deadline.aggregate.phase", "pass", await run(aggregate))
        let aggregateRun = runDeferred(aggregate, scan: { aggregate.platform.clock = 1_000_000 })
        expect("deadline.aggregate", "wrapper,scan,outputs aggregate-only",
               "\(aggregateRun.order.joined(separator: ",")) " +
               "\(aggregateRun.reports.contains("aggregate: native-deadline") && !aggregateRun.reports.contains("case: native-deadline") ? "aggregate-only" : "other")")

        let lateDelete = try scenario()
        expect("deadline.late-deletion.phase", "pass", await run(lateDelete))
        let deleteRun = runDeferred(lateDelete, remove: { lateDelete.platform.clock += 200_000 })
        expect("deadline.late-deletion", "wrapper,scan,outputs,remove,outputs true false",
               "\(deleteRun.order.joined(separator: ",")) \(deleteRun.reports.contains("case: native-deadline")) \(lateDelete.session.mayDelete)")

        // An overrun is retained at the effect that caused it, before the next effect can fail: it is the first primary.
        for (name, lateWrapper, expectedLater) in [("wrapper", true, "deferred-scan"), ("deletion", false, "deferred-outputs")] {
            let ordered = try scenario()
            expect("deadline.first-primary.\(name).phase", "pass", await run(ordered))
            // The verification fails only after the deletion, so the deletion's own overrun is what is retained first.
            var removed = false
            let orderedRun = runDeferred(ordered, wrapper: { if lateWrapper { ordered.platform.clock += 200_000 } },
                                         scan: { if lateWrapper { throw ProofFailure.outputInventory } },
                                         remove: { removed = true; ordered.platform.clock += 200_000 },
                                         outputs: { if !lateWrapper && removed { throw ProofFailure.unexpectedStorage } })
            let later = ordered.session.retention.outcomes.first { $0.stage.hasPrefix("deferred-") }?.stage ?? "none"
            expect("deadline.first-primary.\(name)", "native-deadline \(expectedLater)", "\(ordered.primary) \(later)")
            expect("deadline.first-primary.\(name).reported", true, orderedRun.reports.contains("case: native-deadline"))
        }

        // The final publication is measured at the effect that caused the overrun, before the scan can fail: it is the first primary.
        var slowFinal = false
        var slowFinalPlatform: ScriptedPlatform?
        let slowFinalOps = FaultOps { _, op, path, _ in
            if slowFinal, op == "rename", path.hasSuffix("diagnostic.json") { slowFinalPlatform?.clock += 200_000; slowFinal = false }
            return false
        }
        let finalLate = try scenario(ops: slowFinalOps.ops)
        slowFinalPlatform = finalLate.platform
        expect("deadline.first-primary.final-publication.phase", "pass", await run(finalLate))
        let finalLateRun = runDeferred(finalLate, wrapper: { slowFinal = true }, scan: { throw ProofFailure.outputInventory })
        let laterFinal = finalLate.session.retention.outcomes.first { $0.stage.hasPrefix("deferred-") }?.stage ?? "none"
        expect("deadline.first-primary.final-publication", "native-deadline deferred-scan", "\(finalLate.primary) \(laterFinal)")
        expect("deadline.first-primary.final-publication.reported", true, finalLateRun.reports.contains("case: native-deadline"))

        var slowPublication = false
        var slowPlatform: ScriptedPlatform?
        let slow = FaultOps { _, op, path, _ in
            if slowPublication, op == "rename", path.hasSuffix("diagnostic.json") { slowPlatform?.clock += 200_000; slowPublication = false }
            return false
        }
        let last = try scenario(ops: slow.ops)
        slowPlatform = last.platform
        expect("deadline.late-final-publication.phase", "pass", await run(last))
        let lastRun = runDeferred(last, wrapper: { slowPublication = true })
        expect("deadline.late-final-publication", "wrapper,scan,outputs native-deadline true",
               "\(lastRun.order.joined(separator: ",")) \(last.primary) \(lastRun.reports.contains("case: native-deadline"))")

        let slowCleanup = try scenario()
        expect("deadline.cleanup-overrun.phase", "pass", await run(slowCleanup))
        slowCleanup.platform.arrivalsStopHook = { slowCleanup.platform.clock += 6_000 }
        let cleanupRun = runDeferred(slowCleanup)
        expect("deadline.cleanup-overrun", "wrapper,scan,outputs native-deadline true false",
               "\(cleanupRun.order.joined(separator: ",")) \(slowCleanup.primary) \(cleanupRun.reports.contains("cleanup: native-deadline")) \(slowCleanup.session.mayDelete)")

        // Identity checks consume the cleanup budget: neither owner is signalled after the deadline.
        let overdue = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        _ = await run(overdue)
        overdue.platform.identityHook = { _ in overdue.platform.clock += 6_000 }
        overdue.session.cleanup()
        let outcomes = overdue.session.retention.outcomes.map { "\($0.boundary):\($0.stage):\($0.reason)" }
        expect("deadline.no-late-signals", "0 0 true true true false",
               "\(overdue.app.terminations) \(overdue.platform.launcher?.terminations ?? -1) \(outcomes.contains("N011-L11:signal:deadline")) " +
               "\(outcomes.contains("N011-L12:signal:deadline")) \(outcomes.contains("native-deadline:cleanup:elapsed")) " +
               "\(overdue.session.mayDelete)")

        try await cleanupDeadlines()
    }

    func cleanupDeadlines() async throws {
        // D-R1: owner cleanup's own final diagnostic publication is inside the five-second bound. The delay is armed after a
        // clean phase, hits only that publication and keeps the case and aggregate bounds far from exceeded.
        var cleanupPublication = false
        var cleanupPlatform: ScriptedPlatform?
        let slowOwner = FaultOps { _, op, path, _ in
            if cleanupPublication, op == "rename", path.hasSuffix("diagnostic.json") { cleanupPlatform?.clock += 6_000; cleanupPublication = false }
            return false
        }
        let owner = try scenario(ops: slowOwner.ops)
        cleanupPlatform = owner.platform
        expect("deadline.cleanup-publication.phase", "pass", await run(owner))
        cleanupPublication = true
        let ownerRun = runDeferred(owner)
        expect("deadline.cleanup-publication", "wrapper,scan,outputs native-deadline:cleanup true false true",
               "\(ownerRun.order.joined(separator: ",")) \(owner.primary):\(owner.session.retention.primary?.stage ?? "none") " +
               "\(ownerRun.reports.contains("cleanup: native-deadline")) \(owner.session.mayDelete) \(owner.platform.clock < 180_000)")
        expect("deadline.cleanup-publication.primary-bytes", true, owner.file("primary.json") == primaryBytes("native-deadline", "cleanup", "elapsed", elapsed: owner.platform.clock))

        // The same bound holds on the unknown-retention early return, where nothing is signalled or deleted regardless.
        var unknownPublication = false
        var unknownPlatform: ScriptedPlatform?
        let slowUnknown = FaultOps { _, op, path, _ in
            let diagnostic = op == "rename" && path.hasSuffix("diagnostic.json")
            if diagnostic, unknownPublication { unknownPlatform?.clock += 6_000; unknownPublication = false }
            return diagnostic || (op == "open" && path.hasSuffix("primary.json.tmp")) || (op == "lseek" && path.hasSuffix("primary-fallback.log"))
        }
        let unknownOwner = try scenario(ops: slowUnknown.ops)
        unknownPlatform = unknownOwner.platform
        expect("deadline.cleanup-unknown.phase", "N011-L10", await run(unknownOwner))
        unknownPublication = true
        let unknownRun = runDeferred(unknownOwner)
        let unknownOutcomes = unknownOwner.session.retention.outcomes.map { "\($0.boundary):\($0.stage):\($0.reason)" }
        expect("deadline.cleanup-unknown", "N011-L14 unknown true true false true",
               "\(unknownOwner.primary) \(unknownOwner.session.retention.disposition.rawValue) " +
               "\(unknownOutcomes.contains("native-deadline:cleanup:elapsed")) \(unknownRun.reports.contains("cleanup: native-deadline")) " +
               "\(unknownOwner.session.mayDelete) \(unknownOwner.platform.clock < 180_000)")

        // D-R2: a successful but late wrapper verification is rechecked against the work and cancellation deadline before the
        // input effect. No input occurs, the timeout/cancellation is the retained primary, and no owner is signalled before it.
        for (name, cancel) in [("deadline", false), ("cancellation", true)] {
            var verified = false
            var lateClock: ScriptedPlatform?
            let verifier = try scenario(verifyWrapper: { verified = true; if !cancel { lateClock?.clock += 200_000 } }, configure: { platform, _ in
                platform.workCheckHook = {
                    guard verified else { return }
                    if cancel { throw CancellationError() }
                    if platform.clock >= 150_000 { throw ProofFailure.workDeadline }
                }
            })
            lateClock = verifier.platform
            let result = await run(verifier)
            let expected = cancel ? primaryBytes("N011-L10", "phase", "cancelled", elapsed: verifier.platform.clock)
                                  : primaryBytes("workDeadline", "phase", "classified", elapsed: verifier.platform.clock)
            expect("deadline.late-verification.\(name)", "\(cancel ? "CancellationError()" : "workDeadline") 0 true true",
                   "\(result) \(inputCount(verifier)) \(verifier.untouched) \(verifier.file("primary.json") == expected)")
            expect("deadline.late-verification.\(name).no-effect-before-cleanup", "0 0", "\(verifier.app.terminations) \(verifier.platform.launcher?.terminations ?? -1)")
            verifier.session.cleanup()
            expect("deadline.late-verification.\(name).primary-after-cleanup", true, verifier.file("primary.json") == expected)
        }
    }

    // MARK: diagnostic failures at the last deferred publication, the last close and earlier stages are retained and reported

    func diagnosticFailures() async throws {
        var armed = false
        let once = FaultOps { _, op, path, _ in
            guard armed, op == "rename", path.hasSuffix("diagnostic.json") else { return false }
            armed = false
            return true
        }
        let clean = try scenario(ops: once.ops)
        expect("diagnostic.last-publication.phase", "pass", await run(clean))
        let cleanRun = runDeferred(clean, wrapper: { armed = true })
        expect("diagnostic.last-publication", "N011-L14 diagnostic-replace true true",
               "\(clean.primary) \(clean.session.retention.primary?.stage ?? "none") \(cleanRun.reports.contains("native retention error retained: N011-L14 diagnostic-replace")) " +
               "\(clean.file("primary.json") == primaryBytes("N011-L14", "diagnostic-replace", "diagnostic-publication", elapsed: clean.platform.clock))")

        var armedAgain = false
        let again = FaultOps { _, op, path, _ in
            guard armedAgain, op == "rename", path.hasSuffix("diagnostic.json") else { return false }
            armedAgain = false
            return true
        }
        let failed = try scenario(ops: again.ops, configure: { platform, _ in platform.arrivals = [] })
        expect("diagnostic.secondary.phase", "N011-L04", await run(failed))
        let failedRun = runDeferred(failed, wrapper: { armedAgain = true })
        let durable = String(decoding: failed.file("diagnostic.json") ?? Data(), as: UTF8.self).contains("\"stage\":\"diagnostic-replace\"")
        expect("diagnostic.secondary", "true true true",
               "\(durable) \(failedRun.reports.contains("native retention error retained: N011-L14 diagnostic-replace")) " +
               "\(failed.file("primary.json") == primaryBytes("N011-L04", "arrival", "missing", elapsed: 60_000))")

        // A persistent diagnostic failure after a verified primary stays a reported secondary error; the first primary is untouched.
        let always = FaultOps { _, op, path, _ in op == "rename" && path.hasSuffix("diagnostic.json") }
        let stuck = try scenario(ops: always.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("diagnostic.persistent.phase", "N011-L09", await run(stuck))
        let stuckRun = runDeferred(stuck)
        expect("diagnostic.persistent", "primary true true",
               "\(stuck.session.retention.disposition.rawValue) \(stuck.file("primary.json") == primaryBytes("N011-L09", "readiness", "proxy-or-status-item", elapsed: 60_100)) " +
               "\(stuckRun.reports.contains("native retention error retained: N011-L14 diagnostic-replace"))")

        // With no primary yet, the diagnostic failure is the first primary; with neither channel verified nothing is signalled or deleted.
        let neither = FaultOps { _, op, path, _ in
            (op == "rename" && path.hasSuffix("diagnostic.json")) || (op == "open" && path.hasSuffix("primary.json.tmp")) ||
                (op == "lseek" && path.hasSuffix("primary-fallback.log"))
        }
        let lost = try scenario(ops: neither.ops)
        expect("diagnostic.unattributable.phase", "N011-L10", await run(lost))
        expect("diagnostic.unattributable", "N011-L14 diagnostic-replace unknown closed",
               "\(lost.primary) \(lost.session.retention.primary?.stage ?? "none") \(lost.session.retention.disposition.rawValue) \(lost.session.admission.rawValue)")
        let lostRun = runDeferred(lost)
        expect("diagnostic.unattributable.no-signals-no-deletion", "0 0 wrapper,outputs app-observed app[nil] launcher[nil] false",
               "\(lost.app.terminations) \(lost.platform.launcher?.terminations ?? -1) \(lostRun.order.joined(separator: ",")) \(lost.summary) \(lost.session.mayDelete)")
        expect("diagnostic.unattributable.reported", true,
               lostRun.reports.contains("native retention error retained: N011-L14 diagnostic-replace") &&
                   lostRun.reports.contains { $0.contains("withheld") })

        var closing = false
        let closeFault = FaultOps { _, op, path, _ in closing && op == "close" && path.hasSuffix("primary-fallback.log") }
        let closed = try scenario(ops: closeFault.ops)
        expect("diagnostic.close.phase", "pass", await run(closed))
        let closedRun = runDeferred(closed, wrapper: { closing = true })
        expect("diagnostic.close", "N011-L14 fallback-close true true",
               "\(closed.primary) \(closed.session.retention.primary?.stage ?? "none") \(closedRun.reports.contains("fallback-close: N011-L14")) " +
               "\(closed.file("primary.json") == primaryBytes("N011-L14", "fallback-close", "close", elapsed: closed.platform.clock))")

        // D-R3: with an independently verified primary and an older diagnostic record, both final diagnostic replacements fail
        // while the second evidence file stays writable. The later attribution is read back from disk after disposal; the
        // first primary's bytes are unchanged; the fallback-close failure is carried too.
        var finalFailing = false
        let persistentFinal = FaultOps { _, op, path, _ in finalFailing && op == "rename" && path.hasSuffix("diagnostic.json") }
        let kept = try scenario(ops: persistentFinal.ops, configure: { platform, _ in platform.arrivals = [] })
        expect("diagnostic.secondary-file.phase", "N011-L04", await run(kept))
        let keptRun = runDeferred(kept, wrapper: { finalFailing = true })
        let older = String(decoding: kept.file("diagnostic.json") ?? Data(), as: UTF8.self)
        expect("diagnostic.secondary-file.primary-and-older-record", "true true false",
               "\(kept.file("primary.json") == primaryBytes("N011-L04", "arrival", "missing", elapsed: 60_000)) \(older.contains("\"boundary\":\"N011-L04\"")) \(older.contains("diagnostic-replace"))")
        let keptRecord = secondaryRecord(kept)
        let headKept = "1 native testCodexNeverEntersStatusItem first candidate N011-L04:arrival:missing:60000"
        expect("diagnostic.secondary-file", headKept, keptRecord.head)
        let diagnosticRow = "N011-L14:diagnostic-replace:diagnostic-publication"
        expect("diagnostic.secondary-file.errors", [diagnosticRow, diagnosticRow].joined(separator: ","), keptRecord.errors.joined(separator: ","))
        expect("diagnostic.secondary-file.outcomes", "N011-L13:pending-launch:unobserved", keptRecord.outcomes.joined(separator: ","))
        expect("diagnostic.secondary-file.reported", "true secondary.json",
               "\(keptRun.reports.contains("native retention error retained: N011-L14 diagnostic-replace")) \(kept.session.secondaryFile ?? "none")")

        var closingFailing = false
        let closeAndPublish = FaultOps { _, op, path, _ in
            closingFailing && ((op == "close" && path.hasSuffix("primary-fallback.log")) || (op == "rename" && path.hasSuffix("diagnostic.json")))
        }
        let closedKept = try scenario(ops: closeAndPublish.ops, configure: { platform, _ in platform.arrivals = [] })
        expect("diagnostic.secondary-file.close.phase", "N011-L04", await run(closedKept))
        let closedKeptRun = runDeferred(closedKept, wrapper: { closingFailing = true })
        let closedRecord = secondaryRecord(closedKept)
        let closedPrimary = closedKept.file("primary.json") == primaryBytes("N011-L04", "arrival", "missing", elapsed: 60_000)
        let closedReported = closedKeptRun.reports.contains("fallback-close: N011-L14")
        expect("diagnostic.secondary-file.close", "\(headKept) true true true",
               "\(closedRecord.head) \(closedRecord.outcomes.contains("N011-L14:fallback-close:close")) \(closedReported) \(closedPrimary)")
        expect("diagnostic.secondary-file.close.errors", Array(repeating: diagnosticRow, count: 4).joined(separator: ","),
               closedRecord.errors.joined(separator: ","))
        expect("diagnostic.secondary-file.close.outcomes", "N011-L13:pending-launch:unobserved,N011-L14:fallback-close:close",
               closedRecord.outcomes.joined(separator: ","))

        // Persistent from the start: the second file carries the first primary and the retention errors too.
        let stuckRecord = secondaryRecord(stuck)
        let stuckRows = !stuckRecord.errors.isEmpty && stuckRecord.errors.count <= 16 && stuckRecord.errors.allSatisfy { $0 == diagnosticRow }
        expect("diagnostic.persistent.secondary-file",
               "1 native testCodexNeverEntersStatusItem first candidate N011-L09:readiness:proxy-or-status-item:60100 true secondary.json",
               "\(stuckRecord.head) \(stuckRows) \(stuck.session.secondaryFile ?? "none")")

        // With no remaining channel the failure is a retention error and fixture/default deletion is withheld, never memory only.
        let nowhere = FaultOps { _, op, path, _ in op == "rename" && (path.hasSuffix("diagnostic.json") || path.hasSuffix("secondary.json")) }
        let unretained = try scenario(ops: nowhere.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("diagnostic.secondary-lost.phase", "N011-L09", await run(unretained))
        let unretainedRun = runDeferred(unretained)
        let lostPrimary = unretained.file("primary.json") == primaryBytes("N011-L09", "readiness", "proxy-or-status-item", elapsed: 60_100)
        let lostReported = unretainedRun.reports.contains("native retention error retained: N011-L14 secondary-replace")
        expect("diagnostic.secondary-lost", "absent none wrapper,scan,outputs false true true",
               "\(secondaryRecord(unretained).head) \(unretained.session.secondaryFile ?? "none") \(unretainedRun.order.joined(separator: ",")) " +
               "\(unretained.session.mayDelete) \(lostReported) \(lostPrimary)")
    }
}
#endif
