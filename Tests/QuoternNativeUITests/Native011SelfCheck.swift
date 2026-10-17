import AppKit
import CryptoKit
import Darwin
import Foundation

#if NATIVE011_BINDING_SELF_CHECK
// MARK: offline binding self-check (-D NATIVE011_BINDING_SELF_CHECK): no native application and no XCTest.
// Doubles replace only OS/AppKit effect leaves; the receipt, session, retention and cleanup code above is the code under test.

@MainActor final class ScriptedApp: Native011RunningApp {
    let pid: Int32
    let token: Int
    var bundleURL: URL?
    var executableURL: URL?
    var bundleIdentifier: String?
    var isFinishedLaunching = true
    var isTerminated = false
    var terminateRefused = false
    var terminations = 0
    var onSignal: (() -> Void)?
    var onTerminate: (() -> Void)?

    init(pid: Int32, token: Int, bundleURL: URL?, executableURL: URL?, bundleIdentifier: String?) {
        self.pid = pid
        self.token = token
        self.bundleURL = bundleURL
        self.executableURL = executableURL
        self.bundleIdentifier = bundleIdentifier
    }

    func isSameObject(as other: any Native011RunningApp) -> Bool { (other as? ScriptedApp)?.token == token }

    func forceTerminate() -> Bool {
        terminations += 1
        onSignal?()
        guard !terminateRefused else { return false }
        onTerminate?()
        return true
    }
}

@MainActor final class ScriptedLauncher: Native011Launcher {
    let pid: Int32
    private unowned let platform: ScriptedPlatform
    var exitAtMs: Int?
    var exitReason = "exit"
    var exitStatus = 0
    var ignoresTerminate = false
    var terminations = 0

    init(pid: Int32, platform: ScriptedPlatform) {
        self.pid = pid
        self.platform = platform
    }

    var isRunning: Bool { exitAtMs.map { platform.clock < $0 } ?? true }
    var exit: (reason: String, status: Int)? { isRunning ? nil : (exitReason, exitStatus) }

    func terminate() {
        terminations += 1
        platform.launcherTerminateProbe?()
        guard !ignoresTerminate, exitAtMs == nil else { return }
        exitAtMs = platform.clock
        exitReason = "uncaughtSignal"
        exitStatus = 15
    }
}

@MainActor final class ScriptedObserver: Native011ExitObserver {
    private unowned let platform: ScriptedPlatform
    var exitAtMs: Int?
    var exit = Native011ExitObservation.pending

    init(platform: ScriptedPlatform) { self.platform = platform }

    func poll() -> Native011ExitObservation {
        guard let exitAtMs, platform.clock >= exitAtMs else { return .pending }
        return exit
    }
}

@MainActor final class ScriptedArrivals: Native011Arrivals {
    private unowned let platform: ScriptedPlatform

    init(platform: ScriptedPlatform) { self.platform = platform }

    var baseline: [any Native011RunningApp] { platform.baselineApps.map { $0 as any Native011RunningApp } }

    func arrived() -> [any Native011RunningApp] {
        platform.arrivals.filter { $0.atMs <= platform.clock }.map { $0.app as any Native011RunningApp }
    }

    func stop() {
        platform.log.append("arrivals-stop")
        platform.arrivalsStopHook?()
    }
}

@MainActor final class ScriptedPlatform: Native011Platform {
    var clock = 0
    var log: [String] = []
    var baselineApps: [ScriptedApp] = []
    var arrivals: [(atMs: Int, app: ScriptedApp)] = []
    var launchFault: Error?
    var launcherPid: Int32 = 12
    var launcherEarlyExit: (reason: String, status: Int)?
    var launcher: ScriptedLauncher?
    var observer: ScriptedObserver!
    var observerFault: Native011ObserverFailure?
    var identities: [Int32: Native011Identity] = [:]
    var lookups: [Int32: ScriptedApp] = [:]
    var proxy: [Native011ProxyState] = [.runningForeground]
    var statusOwned = true
    var proxyCalls = 0
    var firstProxyClock: Int?
    var pauseHook: ((ScriptedPlatform) -> Void)?
    var workCheckHook: (() throws -> Void)?
    var identityHook: ((Int32) -> Void)?
    var arrivalsStopHook: (() -> Void)?
    var launcherTerminateProbe: (() -> Void)?
    var observerOverride: ((Int32) throws -> any Native011ExitObserver)?

    func now() -> Int { clock }

    func pause() {
        clock += 50
        pauseHook?(self)
    }

    func startArrivalObservation() -> any Native011Arrivals {
        log.append("observe-before-request")
        return ScriptedArrivals(platform: self)
    }

    func startLauncher(argv: [String]) throws -> any Native011Launcher {
        log.append("launcher-start")
        if let launchFault { throw launchFault }
        let started = ScriptedLauncher(pid: launcherPid, platform: self)
        if let early = launcherEarlyExit {
            started.exitAtMs = 0
            started.exitReason = early.reason
            started.exitStatus = early.status
        }
        launcher = started
        return started
    }

    func identity(pid: Int32) -> Native011Identity? {
        identityHook?(pid)
        return identities[pid]
    }

    func application(pid: Int32) -> (any Native011RunningApp)? { lookups[pid] }

    func observeExit(pid: Int32) throws -> any Native011ExitObserver {
        log.append("observe-exit")
        if let observerFault { throw observerFault }
        if let observerOverride { return try observerOverride(pid) }
        return observer
    }

    func proxyState() -> Native011ProxyState {
        log.append("proxy")
        proxyCalls += 1
        if firstProxyClock == nil { firstProxyClock = clock }
        return proxy[min(proxyCalls - 1, proxy.count - 1)]
    }

    func statusItemOwned() -> Bool {
        log.append("status-item")
        return statusOwned
    }

    // Delivers the application exit (kernel raw wait status, or none) and the independent launcher exit.
    func scriptExit(raw: Int?, launcher status: (reason: String, status: Int)) {
        observer.exitAtMs = clock + 100
        observer.exit = raw.map { Native011ExitObservation.exited(rawWaitStatus: $0) } ?? .exitedWithoutStatus
        launcher?.exitAtMs = clock + 150
        launcher?.exitReason = status.reason
        launcher?.exitStatus = status.status
    }
}

// Real-filesystem fault injection at the OS file-effect leaves; counts calls per operation and path.
@MainActor final class FaultOps {
    var counts: [String: Int] = [:]
    var paths: [Int32: String] = [:]
    var publishingPrimary = false
    var shortWrites = false
    let fails: (FaultOps, String, String, Int) -> Bool

    init(_ fails: @escaping (FaultOps, String, String, Int) -> Bool) { self.fails = fails }

    private func hit(_ operation: String, _ path: String) -> Bool {
        let key = operation + "|" + path
        counts[key, default: 0] += 1
        return fails(self, operation, path, counts[key] ?? 0)
    }

    var ops: Native011FileOps {
        let real = Native011FileOps()
        var ops = Native011FileOps()
        ops.open = { [self] path, flags, mode in
            if path.hasSuffix("primary.json.tmp") { publishingPrimary = true }
            if hit("open", path) { errno = EIO; return -1 }
            let descriptor = real.open(path, flags, mode)
            if descriptor >= 0 { paths[descriptor] = path }
            return descriptor
        }
        ops.write = { [self] descriptor, buffer, count in
            if hit("write", paths[descriptor] ?? "") { errno = EIO; return -1 }
            return real.write(descriptor, buffer, shortWrites ? min(count, 3) : count)
        }
        ops.read = { [self] descriptor, buffer, count in
            let path = paths[descriptor] ?? ""
            if hit("read-short", path) { return real.read(descriptor, buffer, 1) }
            let actual = real.read(descriptor, buffer, count)
            if hit("read-drift", path), actual > 0 { buffer.assumingMemoryBound(to: UInt8.self)[0] ^= 1 }
            return actual
        }
        ops.fsync = { [self] descriptor in
            if hit("fsync", paths[descriptor] ?? "") { errno = EIO; return -1 }
            return real.fsync(descriptor)
        }
        ops.close = { [self] descriptor in
            let path = paths[descriptor] ?? ""
            let status = real.close(descriptor)
            paths[descriptor] = nil
            if hit("close", path) { errno = EIO; return -1 }
            return status
        }
        ops.rename = { [self] from, to, exclusive in
            if hit("rename", to) { errno = EIO; return -1 }
            return real.rename(from, to, exclusive)
        }
        ops.lseek = { [self] descriptor, offset, whence in
            if hit("lseek", paths[descriptor] ?? "") { errno = EIO; return -1 }
            return real.lseek(descriptor, offset, whence)
        }
        return ops
    }
}

@MainActor struct Scenario {
    let platform: ScriptedPlatform
    let app: ScriptedApp
    let bystander: ScriptedApp
    let session: Native011LaunchSession
    let receipt: Native011ReceiptContext
    let out: URL

    func file(_ name: String) -> Data? { try? Data(contentsOf: out.appendingPathComponent(name)) }
    var primary: String { session.retention.primary?.boundary ?? "none" }
    var untouched: Bool { app.terminations == 0 && bystander.terminations == 0 }

    var summary: String {
        guard let data = file("ownership.json"), let record = try? Native011Receipt.decode(data, context: receipt) else { return "undecodable" }
        func exit(_ record: Native011ExitRecord?) -> String { record.map { "\($0.reason) \($0.status)" } ?? "nil" }
        return "\(record.requestState.rawValue) app[\(exit(record.applicationExit))] launcher[\(exit(record.launcherExit))]"
    }
}

@MainActor final class SelfCheck {
    var rows: [(name: String, expected: String, actual: String)] = []
    let root: URL
    let method = "testCodexNeverEntersStatusItem"
    let candidate = String(repeating: "0", count: 64)
    // The cleanup flag of the latest deferred verification, so the actual final consumer is called exactly as the native verifier is.
    var deferredCleaned = false
    private var serial = 0

    init() throws {
        root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("native011-selfcheck-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    func expect(_ name: String, _ expected: String, _ actual: String) { rows.append((name, expected, actual)) }
    func expect(_ name: String, _ expected: Bool, _ actual: Bool) { expect(name, String(expected), String(actual)) }

    func scenario(phase: String = "first", sharing sibling: Scenario? = nil, ops: Native011FileOps = Native011FileOps(), caseStartMs: Int = 0,
                  aggregateStartMs: Int = 0, verifyWrapper: @escaping () throws -> Void = {},
                  configure: (ScriptedPlatform, ScriptedApp) -> Void = { _, _ in }) throws -> Scenario {
        serial += 1
        // A sibling phase shares the fixture output directory of the scenario it names.
        let out = (sibling?.out.deletingLastPathComponent() ?? root.appendingPathComponent("s\(serial)/native/\(method)")).appendingPathComponent(phase)
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let receipt = Native011ReceiptContext(attempt: "/fixture/attempt", method: method, phase: phase, candidate: candidate, uid: 501)
        let wrapper = URL(fileURLWithPath: receipt.wrapperPath)
        let executable = URL(fileURLWithPath: receipt.applicationPath)
        let platform = ScriptedPlatform()
        platform.observer = ScriptedObserver(platform: platform)
        let app = ScriptedApp(pid: 13, token: 1, bundleURL: wrapper, executableURL: executable,
                              bundleIdentifier: "app.quotern.nativeproof." + method)
        let bystander = ScriptedApp(pid: 99, token: 99, bundleURL: URL(fileURLWithPath: "/Applications/Other.app"),
                                    executableURL: URL(fileURLWithPath: "/Applications/Other.app/Contents/MacOS/Other"), bundleIdentifier: "org.other")
        platform.baselineApps = [bystander]
        platform.arrivals = [(100, app)]
        platform.lookups = [13: app, 99: bystander]
        platform.identities = [
            12: Native011Identity(pid: 12, sec: 100, usec: 2, uid: 501, path: "/usr/bin/open"),
            13: Native011Identity(pid: 13, sec: 100, usec: 3, uid: 501, path: receipt.applicationPath),
            99: Native011Identity(pid: 99, sec: 90, usec: 0, uid: 501, path: "/Applications/Other.app/Contents/MacOS/Other"),
        ]
        app.onTerminate = { [unowned platform] in
            platform.observer.exitAtMs = platform.clock
            platform.observer.exit = .exited(rawWaitStatus: 9)
            platform.launcher?.exitAtMs = platform.clock + 50
        }
        configure(platform, app)
        let runner = Native011Identity(pid: 11, sec: 100, usec: 1, uid: 501, path: receipt.runnerPath)
        let context = Native011LaunchContext(receipt: receipt, wrapper: wrapper, executable: executable, runner: runner,
                                             expectedBundleID: "app.quotern.nativeproof." + method, out: out)
        let session = Native011LaunchSession(context: context, platform: platform, ops: ops, caseStartMs: caseStartMs,
                                             aggregateStartMs: aggregateStartMs, workCheck: { [unowned platform] in try platform.workCheckHook?() },
                                             verifyWrapper: verifyWrapper)
        return Scenario(platform: platform, app: app, bystander: bystander, session: session, receipt: receipt, out: out)
    }

    // Drives the actual runPhase wiring; the default body is one native input followed by the scripted application exit.
    @discardableResult func run(_ scenario: Scenario, exit raw: Int? = 0, launcher: (reason: String, status: Int) = ("exit", 0),
                                body: (() async throws -> Void)? = nil) async -> String {
        let platform = scenario.platform
        do {
            try await scenario.session.runPhase(prelaunch: { platform.log.append("prelaunch") }, body: {
                if let body { try await body() }
                else { try scenario.session.input { platform.log.append("input") } }
                platform.scriptExit(raw: raw, launcher: launcher)
            }, postexit: { platform.log.append("postexit") })
            return "pass"
        } catch { return native011FailureDiagnostic(error) }
    }

    func order(_ log: [String], _ names: [String]) -> Bool {
        let indices = names.map { log.firstIndex(of: $0) }
        guard !indices.contains(where: { $0 == nil }) else { return false }
        let positions = indices.compactMap { $0 }
        return zip(positions, positions.dropFirst()).allSatisfy { $0 < $1 }
    }

    // MARK: owner receipt codec (same fixed bytes as the root ownership-fixture.json)

    func codec() throws {
        let fixtureData = Data(native011OwnershipFixture.utf8)
        let context = Native011ReceiptContext(attempt: "/fixture/attempt", method: method, phase: "first", candidate: candidate, uid: 501)
        let fixtureReceipt = try Native011Receipt.decode(fixtureData, context: context)
        let object = try XCTUnwrapObject(Native011JSON.parse(fixtureData))
        func outcome(_ record: [String: Native011JSON], previous: Native011Receipt? = nil) -> String {
            do { _ = try Native011Receipt.decode(Data((Native011JSON.object(record).encoded() + "\n").utf8), context: context, previous: previous); return "pass" }
            catch let boundary as Native011OwnerBoundary { return boundary.rawValue }
            catch { return "error" }
        }
        func rawOutcome(_ data: Data) -> String {
            do { _ = try Native011Receipt.decode(data, context: context); return "pass" }
            catch let boundary as Native011OwnerBoundary { return boundary.rawValue }
            catch { return "error" }
        }
        func with(_ key: String, _ value: Native011JSON) -> [String: Native011JSON] { var record = object; record[key] = value; return record }
        func with(role: String, _ key: String, _ value: Native011JSON) -> [String: Native011JSON] {
            var record = object
            var identity = record[role]?.object ?? [:]
            identity[key] = value
            record[role] = .object(identity)
            return record
        }
        expect("codec.fixture-roundtrip", true, fixtureReceipt.encoded() == fixtureData)
        expect("codec.canonical", "pass", outcome(object))
        let bindings: [(String, Native011JSON, String)] = [
            ("v", .bool(true), "N011-S05-RECEIPT-BINDING"), ("candidate_sha256", .string(String(repeating: "1", count: 64)), "N011-S05-RECEIPT-BINDING"),
            ("method", .string("testLateAcceptedOKIsRejectedBeforeSourceRegistration"), "N011-S05-RECEIPT-BINDING"),
            ("phase", .string("restart"), "N011-S05-RECEIPT-BINDING"), ("sequence", .bool(true), "N011-S05-RECEIPT-BINDING"),
            ("sequence", .int(-1), "N011-S05-RECEIPT-BINDING"), ("sequence", .int(257), "N011-S05-RECEIPT-BINDING"),
            ("wrapper_rel", .string("wrappers/../else.app"), "N011-S06-RECEIPT-PATHS"), ("stdout_rel", .string("elsewhere.log"), "N011-S06-RECEIPT-PATHS"),
            ("stderr_rel", .string("elsewhere.log"), "N011-S06-RECEIPT-PATHS"), ("request_state", .string("closed"), "N011-S09-REQUEST-STATE"),
            ("closure", .string("resolved"), "N011-S09-REQUEST-STATE"), ("application", .null, "N011-S09-REQUEST-STATE"),
            ("runner", .null, "N011-S07-RECEIPT-IDENTITY"),
        ]
        for (key, value, expected) in bindings { expect("codec.\(key)-\(value.encoded())", expected, outcome(with(key, value))) }
        for role in ["runner", "launcher", "application"] {
            for (key, value) in [("pid", Native011JSON.bool(true)), ("pid", .int(0)), ("sec", .int(-1)), ("usec", .int(1_000_000)),
                                 ("uid", .int(502)), ("path", .string("/bystander"))] {
                expect("codec.\(role)-\(key)-\(value.encoded())", "N011-S07-RECEIPT-IDENTITY", outcome(with(role: role, key, value)))
            }
        }
        expect("codec.same-pid-two-roles", "N011-S07-RECEIPT-IDENTITY", outcome(with(role: "application", "pid", .int(12))))
        let argv = object["launcher_argv"]?.array ?? []
        for index in argv.indices {
            var changed = argv
            changed[index] = .string((argv[index].stringValue ?? "") + "-mutated")
            expect("codec.argv-\(index)", "N011-S06-RECEIPT-PATHS", outcome(with("launcher_argv", .array(changed))))
        }
        for (label, changed) in [("short", Array(argv.dropLast())), ("extra", argv + [.string("extra")]), ("reversed", Array(argv.reversed()))] {
            expect("codec.argv-\(label)", "N011-S06-RECEIPT-PATHS", outcome(with("launcher_argv", .array(changed))))
        }
        codecExitStatus(object, fixtureReceipt: fixtureReceipt, outcome: outcome)
        var extra = object
        extra["extra"] = .string("no")
        expect("codec.extra-key", "N011-S04-RECEIPT-FIELDS", outcome(extra))
        var missingField = object
        missingField["closure"] = nil
        expect("codec.missing-key", "N011-S04-RECEIPT-FIELDS", outcome(missingField))
        let trimmed = fixtureData.dropLast(2)
        expect("codec.duplicate-json", "N011-S03-RECEIPT-JSON", rawOutcome(trimmed + Data(",\"v\":1}\n".utf8)))
        expect("codec.nan-json", "N011-S03-RECEIPT-JSON", rawOutcome(Data("{\"v\":NaN}".utf8)))
        expect("codec.partial-json", "N011-S03-RECEIPT-JSON", rawOutcome(Data("{\"v\":".utf8)))
        expect("codec.oversize", "N011-S02-RECEIPT-SIZE", rawOutcome(Data(repeating: 0x20, count: 16_385)))
        var back = fixtureReceipt
        back.sequence = 1
        expect("codec.sequence-back", "N011-S10-RECEIPT-CONTINUITY", outcome(back.json.object ?? [:], previous: fixtureReceipt))
        var changedSame = object
        changedSame["closure"] = .string("unknown")
        changedSame["request_state"] = .string("unknown")
        expect("codec.same-sequence-changed", "N011-S10-RECEIPT-CONTINUITY", outcome(changedSame, previous: fixtureReceipt))
        var identityChanged = with(role: "application", "usec", .int(4))
        identityChanged["sequence"] = .int(3)
        expect("codec.identity-changed", "N011-S10-RECEIPT-CONTINUITY", outcome(identityChanged, previous: fixtureReceipt))
        var stateBack = object
        stateBack["sequence"] = .int(3)
        stateBack["request_state"] = .string("issued")
        stateBack["application"] = .null
        expect("codec.state-back", "N011-S10-RECEIPT-CONTINUITY", outcome(stateBack, previous: fixtureReceipt))
        let strict: [(String, Data)] = [
            ("escaped-unicode", Data("{\"v\":\"\\u00e9\"}".utf8)), ("trailing-garbage", fixtureData + Data("x".utf8)),
            ("float", Data("{\"v\":1.0}".utf8)), ("depth", Data(String(repeating: "[", count: 12).utf8)),
        ]
        for (name, bytes) in strict { expect("codec.strict-\(name)", name == "escaped-unicode" ? "N011-S04-RECEIPT-FIELDS" : "N011-S03-RECEIPT-JSON", rawOutcome(bytes)) }
        expect("codec.ascii-escape", "\"\\u00e9\\ud83d\\ude00\"", Native011JSON.string("é😀").encoded())
    }

    func codecExitStatus(_ object: [String: Native011JSON], fixtureReceipt: Native011Receipt,
                         outcome: ([String: Native011JSON], Native011Receipt?) -> String) {
        for (reason, status, raw, launcherStatus) in [("exit", 0, 0, 1), ("exit", 1, 256, 0), ("uncaughtSignal", 15, 15, 0)] {
            var closed = object
            closed["sequence"] = .int(4)
            closed["request_state"] = .string("closed")
            closed["closure"] = .string("resolved")
            let application: [String: Native011JSON] = ["source": .string("EVFILT_PROC_NOTE_EXITSTATUS"), "raw_wait_status": .int(raw),
                                                         "reason": .string(reason), "status": .int(status)]
            closed["application_exit"] = .object(application)
            closed["launcher_exit"] = .object(["source": .string("Process"), "reason": .string("exit"), "status": .int(launcherStatus)])
            expect("codec.independent-app-\(raw)", "pass", outcome(closed, fixtureReceipt))
            var asLauncher = closed
            asLauncher["application_exit"] = .object(application.merging(["source": .string("Process")]) { $1 })
            expect("codec.launcher-as-app-\(raw)", "N011-S08-EXIT-STATUS", outcome(asLauncher, nil))
            var wrong = closed
            wrong["application_exit"] = .object(application.merging(["status": .int(2)]) { $1 })
            expect("codec.wrong-decoded-status-\(raw)", "N011-S08-EXIT-STATUS", outcome(wrong, nil))
            var missing = closed
            missing["application_exit"] = .null
            expect("codec.missing-app-status-\(raw)", "N011-S09-REQUEST-STATE", outcome(missing, nil))
        }
        for raw in [Native011JSON.bool(true), .int(-1), .int(65_536), .int(127), .int(255), .int(511)] {
            var invalid = object
            invalid["application_exit"] = .object(["source": .string("EVFILT_PROC_NOTE_EXITSTATUS"), "raw_wait_status": raw,
                                                   "reason": .string("exit"), "status": .int(0)])
            expect("codec.invalid-raw-\(raw.encoded())", "N011-S08-EXIT-STATUS", outcome(invalid, nil))
        }
    }

    func XCTUnwrapObject(_ json: Native011JSON) throws -> [String: Native011JSON] {
        guard let object = json.object else { throw Native011OwnerBoundary.json }
        return object
    }
}
#endif

#if NATIVE011_BINDING_SELF_CHECK
extension SelfCheck {
    func inputOutcome(_ scenario: Scenario) -> String {
        do { try scenario.session.input {}; return "admitted" } catch { return native011FailureDiagnostic(error) }
    }

    func happyPath() async throws {
        let subject = try scenario()
        var captured: Data?
        let result = await run(subject, body: {
            captured = subject.file("ownership.json")
            try subject.session.input { subject.platform.log.append("input") }
        })
        expect("lifecycle.result", "pass", result)
        expect("lifecycle.provider-bytes-equal-fixture", true, captured == Data(native011OwnershipFixture.utf8))
        expect("lifecycle.order", true, order(subject.platform.log, ["observe-before-request", "prelaunch", "launcher-start", "observe-exit", "proxy",
                                                               "status-item", "input", "postexit"]))
        expect("lifecycle.final-receipt", "closed app[exit 0] launcher[exit 0]", subject.summary)
        let fixtureReceipt = try Native011Receipt.decode(Data(native011OwnershipFixture.utf8), context: subject.receipt)
        let final = try Native011Receipt.decode(subject.file("ownership.json") ?? Data(), context: subject.receipt, previous: fixtureReceipt)
        expect("lifecycle.separate-owners", true, final.launcher != nil && final.launcher?.pid != final.application?.pid)
        expect("lifecycle.no-primary", "none", subject.primary)
        expect("lifecycle.no-primary-file", true, subject.file("primary.json") == nil)
        expect("lifecycle.fallback-stays-empty", true, subject.file("primary-fallback.log")?.isEmpty == true)
        expect("lifecycle.deletion-allowed", true, subject.session.mayDelete)
        expect("lifecycle.diagnostic-published", true, (subject.file("diagnostic.json")?.count ?? 0) > 0)
        let early = try scenario()
        var beforeReady = "admitted"
        do { try early.session.input {} } catch { beforeReady = native011FailureDiagnostic(error) }
        expect("lifecycle.no-input-before-launch", "N011-L10", beforeReady)
    }

    func admissionRejections() async throws {
        func changed(_ platform: ScriptedPlatform, _ app: ScriptedApp, _ mutate: @escaping (ScriptedApp) -> Void) {
            app.isFinishedLaunching = false
            platform.pauseHook = { platform in
                guard platform.clock >= 150 else { return }
                mutate(app)
                app.isFinishedLaunching = true
            }
        }
        let cases: [(String, String, (ScriptedPlatform, ScriptedApp) -> Void)] = [
            ("reused-owner", "N011-L01", { platform, app in platform.baselineApps.append(app); platform.arrivals = [] }),
            ("two-arrivals", "N011-L04", { platform, app in
                let twin = ScriptedApp(pid: 14, token: 2, bundleURL: app.bundleURL, executableURL: app.executableURL, bundleIdentifier: app.bundleIdentifier)
                platform.arrivals.append((100, twin))
                platform.lookups[14] = twin
            }),
            ("missing-arrival", "N011-L04", { platform, _ in platform.arrivals = [] }),
            ("wrong-identifier", "N011-L05", { _, app in app.bundleIdentifier = "app.other" }),
            ("empty-identifier", "N011-L05", { _, app in app.bundleIdentifier = "" }),
            ("wrong-url", "N011-L05", { _, app in app.bundleURL = URL(fileURLWithPath: "/fixture/other.app") }),
            ("aliased-wrapper", "N011-L05", { _, app in app.bundleURL = URL(fileURLWithPath: "/fixture/alias/testCodexNeverEntersStatusItem.app") }),
            ("missing-url", "N011-L05", { _, app in app.bundleURL = nil }),
            ("changed-executable", "N011-L05", { _, app in app.executableURL = URL(fileURLWithPath: "/fixture/other") }),
            ("terminated-arrival", "N011-L07", { _, app in app.isTerminated = true }),
            ("object-changed-before-readiness", "N011-L05", { platform, app in
                changed(platform, app) { current in
                    platform.lookups[13] = ScriptedApp(pid: 13, token: 7, bundleURL: current.bundleURL, executableURL: current.executableURL,
                                                       bundleIdentifier: current.bundleIdentifier)
                }
            }),
            ("start-changed-before-readiness", "N011-L05", { platform, app in
                changed(platform, app) { _ in
                    platform.identities[13] = Native011Identity(pid: 13, sec: 101, usec: 3, uid: 501, path: platform.identities[13]?.path ?? "")
                }
            }),
            ("executable-changed-before-readiness", "N011-L05", { platform, app in
                changed(platform, app) { $0.executableURL = URL(fileURLWithPath: "/fixture/other") }
            }),
            ("url-changed-before-readiness", "N011-L05", { platform, app in
                changed(platform, app) { $0.bundleURL = URL(fileURLWithPath: "/fixture/other.app") }
            }),
        ]
        let admissionStages = [
            "reused-owner": "preexisting-application", "two-arrivals": "arrival", "missing-arrival": "arrival",
            "wrong-identifier": "bundle-identifier", "empty-identifier": "bundle-identifier", "wrong-url": "bundle-url",
            "aliased-wrapper": "bundle-url", "missing-url": "bundle-url", "changed-executable": "executable", "terminated-arrival": "arrival",
            "object-changed-before-readiness": "owner-refresh", "start-changed-before-readiness": "owner-refresh",
            "executable-changed-before-readiness": "owner-refresh", "url-changed-before-readiness": "owner-refresh",
        ]
        for (name, expected, configure) in cases {
            let subject = try scenario(configure: configure)
            let result = await run(subject)
            subject.session.cleanup()
            expect("admission.\(name)", expected, result)
            expect("admission.\(name).primary", expected, subject.primary)
            expect("admission.\(name).no-input-no-application-signal", true, !subject.platform.log.contains("input") && subject.untouched)
            expect("admission.\(name).input-closed", "N011-L10", inputOutcome(subject))
            expect("admission.\(name).stage", admissionStages[name] ?? "unlisted", subject.session.retention.primary?.stage ?? "none")
        }
        let reused = try scenario(configure: { platform, app in platform.baselineApps.append(app); platform.arrivals = [] })
        _ = await run(reused)
        expect("admission.reused-owner.no-launch", true, !reused.platform.log.contains("launcher-start") && !reused.session.requested)
    }

    func readiness() async throws {
        let late = try scenario(configure: { platform, app in
            app.bundleIdentifier = nil
            app.isFinishedLaunching = false
            platform.pauseHook = { platform in if platform.clock >= 200 { app.isFinishedLaunching = true } }
        })
        expect("readiness.nil-identifier-and-late-finish", "pass", await run(late))
        expect("readiness.no-early-proxy", true, (late.platform.firstProxyClock ?? -1) >= 200)
        let unavailable = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("readiness.proxy-unavailable", "N011-L09", await run(unavailable))
        expect("readiness.no-input", true, !unavailable.platform.log.contains("input"))
        expect("readiness.bounded", true, unavailable.platform.clock <= 100 + Native011Bounds.readinessMs + 200)
        expect("readiness.no-synthetic-ready", "closed", unavailable.session.admission.rawValue)
        let noItem = try scenario(configure: { platform, _ in platform.statusOwned = false })
        expect("readiness.status-item-not-owned", "N011-L09", await run(noItem))
    }

    func exits() async throws {
        for (name, raw, launcher, expected) in [("normal-0", 0, ("exit", 1), "closed app[exit 0] launcher[exit 1]"),
                                                 ("normal-1", 256, ("exit", 0), "closed app[exit 1] launcher[exit 0]"),
                                                 ("signal-15", 15, ("exit", 3), "closed app[uncaughtSignal 15] launcher[exit 3]")] {
            let subject = try scenario()
            expect("exit.\(name).result", "pass", await run(subject, exit: raw, launcher: launcher))
            expect("exit.\(name).receipt", expected, subject.summary)
        }
        let denied = try scenario(configure: { platform, _ in platform.observerFault = .denied })
        expect("exit.observer-denied", "N011-L06", await run(denied))
        expect("exit.observer-denied.no-input", true, !denied.platform.log.contains("input"))
        let unobserved = try scenario(configure: { platform, _ in platform.observerFault = .alreadyExited })
        expect("exit.exits-before-observation", "N011-L07", await run(unobserved))
        let missing = try scenario()
        expect("exit.missing-status", "N011-L08", await run(missing, exit: nil, launcher: ("exit", 0)))
        missing.session.cleanup()
        expect("exit.launcher-status-never-substituted", true, missing.session.applicationExit == nil && missing.session.launcherExit?.status == 0)
        expect("exit.missing-status.receipt", "unknown app[nil] launcher[exit 0]", missing.summary)
        expect("exit.missing-status.blocks-deletion", false, missing.session.mayDelete)
        let invalid = try scenario()
        expect("exit.invalid-wait-status", "N011-L08", await run(invalid, exit: 70_000))
        expect("exit.invalid-wait-status.no-status", true, invalid.session.applicationExit == nil)
    }

    func launchFaults() async throws {
        let sentinel = "QTN-SENTINEL-7f3a9c"
        let hostile = NSError(domain: sentinel, code: 17, userInfo: [NSLocalizedDescriptionKey: sentinel])
        for (name, error, fragment) in [("posix", NSError(domain: NSPOSIXErrorDomain, code: 2), "launch primary=posix:2"),
                                        ("hostile", hostile, "launch primary=redacted:17")] {
            let subject = try scenario(configure: { platform, _ in platform.launchFault = error })
            expect("launch.throws.\(name)", "N011-L02", await run(subject))
            expect("launch.throws.\(name).class", true, subject.session.retention.primary?.reason.contains(fragment) == true)
            expect("launch.throws.\(name).redacted", true, !String(decoding: subject.file("primary.json") ?? Data(), as: UTF8.self).contains(sentinel))
            subject.session.cleanup()
            expect("launch.throws.\(name).unresolved-blocks-deletion", false, subject.session.mayDelete)
            expect("launch.throws.\(name).receipt", "unknown app[nil] launcher[nil]", subject.summary)
        }
        // The real launch failure path: a Cocoa start error with an underlying POSIX error survives bounded storage and serialization.
        let chain = NSError(domain: NSCocoaErrorDomain, code: 4, userInfo: [
            NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: 13, userInfo: [NSLocalizedDescriptionKey: sentinel]),
            NSFilePathErrorKey: sentinel, NSLocalizedDescriptionKey: sentinel,
        ])
        let chained = try scenario(configure: { platform, _ in platform.launchFault = chain })
        expect("launch.throws.chained", "N011-L02", await run(chained))
        expect("launch.throws.chained.primary-bytes", true,
               chained.file("primary.json") == primaryBytes("N011-L02", "launcher-start", "launch primary=cocoa:4 underlying=posix:13", elapsed: 0))
        let chainedText = [chained.file("primary.json"), chained.file("diagnostic.json")].map { String(decoding: $0 ?? Data(), as: UTF8.self) }
        expect("launch.throws.chained.diagnostic", "true false false",
               "\(chainedText[1].contains("\"reason\":\"launch primary=cocoa:4 underlying=posix:13\"")) \(chainedText[0].contains(sentinel)) \(chainedText[1].contains(sentinel))")
        let early = try scenario(configure: { platform, _ in platform.launcherEarlyExit = ("exit", 3) })
        expect("launch.early-exit", "N011-L03", await run(early))
        expect("launch.early-exit.launcher-outcome", "3", String(early.session.launcherExit?.status ?? -1))
        expect("launch.early-exit.no-application-status", true, early.session.applicationExit == nil)
        early.session.cleanup()
        expect("launch.early-exit.receipt", "unknown app[nil] launcher[exit 3]", early.summary)
        expect("launch.early-exit.blocks-deletion", false, early.session.mayDelete)
        for (name, arrival, reason) in [("late-app", [(60_050, 0)], "late-arrival"), ("never-observed", [], "unobserved")] as [(String, [(Int, Int)], String)] {
            let subject = try scenario(configure: { platform, app in platform.arrivals = arrival.map { ($0.0, app) } })
            expect("launch.\(name)", "N011-L04", await run(subject))
            subject.platform.clock += 100
            subject.session.cleanup()
            expect("launch.\(name).never-admitted", true, subject.session.admitted == nil && subject.app.terminations == 0)
            expect("launch.\(name).outcome", "N011-L13:\(reason)",
                   subject.session.retention.outcomes.first { $0.boundary == "N011-L13" }.map { "\($0.boundary):\($0.reason)" } ?? "none")
            expect("launch.\(name).blocks-deletion", false, subject.session.mayDelete)
            expect("launch.\(name).input-closed", "N011-L10", inputOutcome(subject))
        }
    }

    func cancellation() async throws {
        func facts(_ result: String, _ subject: Scenario) -> String {
            "\(subject.primary) launcher-terminated=\(subject.platform.launcher?.terminations ?? -1) app-terminated=\(subject.app.terminations) " +
            "deletable=\(subject.session.mayDelete) admission=\(subject.session.admission.rawValue)"
        }
        let before = try scenario()
        before.session.cancel(stage: "before-request")
        var launched = "launched"
        do { try before.session.launch(beforeRequest: {}) } catch { launched = native011FailureDiagnostic(error) }
        before.session.cleanup()
        expect("cancel.before-request", "N011-L10 launcher=false deletable=true", "\(launched) launcher=\(before.platform.log.contains("launcher-start")) deletable=\(before.session.mayDelete)")

        let during = try scenario(configure: { platform, _ in
            platform.workCheckHook = { if platform.log.contains("launcher-start") { throw CancellationError() } }
        })
        let duringResult = await run(during)
        during.session.cleanup()
        expect("cancel.launch", "N011-L10 launcher-terminated=1 app-terminated=0 deletable=false admission=closed", facts(duringResult, during))

        let ready = try scenario(configure: { platform, _ in
            platform.proxy = [.unavailable]
            platform.workCheckHook = { if platform.proxyCalls >= 2 { throw CancellationError() } }
        })
        let readyResult = await run(ready)
        ready.session.cleanup()
        expect("cancel.readiness", "N011-L10 launcher-terminated=0 app-terminated=1 deletable=true admission=closed", facts(readyResult, ready))
        expect("cancel.readiness.receipt", "closed app[uncaughtSignal 9] launcher[exit 0]", ready.summary)

        let input = try scenario()
        let inputResult = await run(input, body: { try input.session.input { throw CancellationError() } })
        input.session.cleanup()
        expect("cancel.input", "N011-L10 launcher-terminated=0 app-terminated=1 deletable=true admission=closed", facts(inputResult, input))

        let teardown = try scenario(configure: { platform, _ in
            platform.workCheckHook = { if platform.log.contains("input") { throw CancellationError() } }
        })
        let teardownResult = await run(teardown)
        teardown.session.cleanup()
        expect("cancel.teardown", "N011-L10 launcher-terminated=0 app-terminated=1 deletable=true admission=closed", facts(teardownResult, teardown))

        var cancelled = false
        var reopening: Native011LaunchSession?
        let reopen = try scenario(configure: { platform, app in
            app.isFinishedLaunching = false
            platform.pauseHook = { platform in
                guard platform.clock >= 200 else { return }
                app.isFinishedLaunching = true
                if !cancelled { cancelled = true; reopening?.cancel(stage: "readiness") }
            }
        })
        reopening = reopen.session
        expect("cancel.never-reopens", "N011-L10", await run(reopen))
        expect("cancel.never-reopens.no-input", true, !reopen.platform.log.contains("input"))
        expect("cancel.never-reopens.admission", "closed", reopen.session.admission.rawValue)
    }

    func ownerRefusals() async throws {
        let reuse = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("owner.readiness-failure-keeps-owner", "N011-L09", await run(reuse))
        reuse.platform.identities[13] = Native011Identity(pid: 13, sec: 5_000, usec: 0, uid: 501, path: reuse.receipt.applicationPath)
        reuse.session.cleanup()
        expect("owner.pid-reuse-refused", "0 N011-L11", "\(reuse.app.terminations) \(reuse.session.retention.outcomes.first { $0.boundary == "N011-L11" }?.boundary ?? "none")")
        expect("owner.pid-reuse-not-closed", false, reuse.session.mayDelete)
        expect("owner.pid-reuse.bystander", true, reuse.bystander.terminations == 0)

        let wrong = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        _ = await run(wrong)
        guard let admitted = wrong.session.admitted else { expect("owner.admitted", true, false); return }
        func signalOutcome(_ cached: Native011AdmittedApplication) -> String {
            do { try wrong.session.signalApplication(cached); return "signalled" } catch { return native011FailureDiagnostic(error) }
        }
        expect("owner.wrong-cached-owner", "N011-L11", signalOutcome(Native011AdmittedApplication(app: wrong.bystander, identity: admitted.identity,
                                                                                                   executable: admitted.executable, bundleURL: admitted.bundleURL)))
        expect("owner.wrong-cached-url", "N011-L11", signalOutcome(Native011AdmittedApplication(app: admitted.app, identity: admitted.identity,
                                                                                                 executable: URL(fileURLWithPath: "/fixture/other"), bundleURL: admitted.bundleURL)))
        expect("owner.refused-no-signal", true, wrong.untouched)
        expect("owner.exact-owner-control", "signalled 1", "\(signalOutcome(admitted)) \(wrong.app.terminations)")
        let refused = try scenario(configure: { platform, app in platform.proxy = [.unavailable]; app.terminateRefused = true })
        _ = await run(refused)
        refused.session.cleanup()
        expect("owner.termination-refused", "N011-L11 false", "\(refused.session.retention.outcomes.first { $0.boundary == "N011-L11" }?.boundary ?? "none") \(refused.session.mayDelete)")
        let stuck = try scenario(configure: { platform, app in
            platform.proxy = [.unavailable]
            app.onTerminate = { [unowned platform] in
                platform.observer.exitAtMs = platform.clock
                platform.observer.exit = .exited(rawWaitStatus: 9)
            }
            platform.pauseHook = { platform in platform.launcher?.ignoresTerminate = true }
        })
        _ = await run(stuck)
        stuck.session.cleanup()
        expect("owner.launcher-unconfirmed", "N011-L12 false", "\(stuck.session.retention.outcomes.first { $0.boundary == "N011-L12" }?.boundary ?? "none") \(stuck.session.mayDelete)")
    }
}
#endif
