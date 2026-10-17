import AppKit
import CryptoKit
import Darwin
import Foundation

// The retained-output membership and byte scan. The native test (scan, then the final verification) and the offline self-check
// consume this one source: membership is derived from the sessions' own published artifacts, so a second evidence file that
// a session retained is part of the inventory and is scanned like every other native output.
@MainActor enum Native011RetainedOutput {
    static let sentinel = "QTN-SENTINEL-7f3a9c"
    static let emptyNames: Set<String> = ["application.stdout.log", "application.stderr.log", "primary-fallback.log"]

    static func phaseFiles(phase: String, fault: String?, cancelled: Bool, sessions: [Native011LaunchSession]) -> Set<String> {
        var names: Set<String> = ["application.stdout.log", "application.stderr.log", "primary-fallback.log", "ownership.json", "diagnostic.json",
                                  "launch.json", "journey.json", "status.ax.json", "status.png"]
        if sessions.contains(where: { $0.context.receipt.phase == phase && $0.retention.primary != nil }) { names.insert("primary.json") }
        names.formUnion(sessions.filter { $0.context.receipt.phase == phase }.compactMap(\.secondaryFile))
        if fault == nil && !cancelled { names.insert("popover.png") }
        if phase == "first" {
            if fault == nil || cancelled {
                names.formUnion(["checkpoint.json", "observed-popover.ax.json", "observed-popover.png"])
            }
            if fault != "withheld-readiness" { names.formUnion(["Codex-panel.ax.json", "Codex-panel.png"]) }
            if fault == nil && !cancelled { names.formUnion(["OpenCode-panel.ax.json", "OpenCode-panel.png"]) }
            if cancelled { names.insert("ownership-control.json") }
        }
        return names
    }

    static func files(in directory: URL) throws -> [URL] {
        func read(_ directory: URL) throws -> [URL] {
            var result: [URL] = []
            for url in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isAliasFileKey]) {
                let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isAliasFileKey])
                guard values.isSymbolicLink != true, values.isAliasFile != true else { throw ProofFailure.outputInventory }
                if values.isDirectory == true { result += try read(url) }
                else { result.append(url) }
            }
            return result
        }
        let result = try read(directory)
        guard !result.isEmpty else { throw ProofFailure.outputInventory }
        return result.sorted { $0.path < $1.path }
    }

    static func checked(in directory: URL, required: Set<URL>) throws -> Set<URL> {
        let actual = Set(try files(in: directory))
        guard actual == required else { throw ProofFailure.outputInventory }
        return actual
    }

    // Every retained file is read: a planted sentinel and an unexpectedly empty file are each refused.
    static func verify(_ actual: Set<URL>) throws {
        for url in actual {
            let bytes = try Data(contentsOf: url)
            guard bytes.range(of: Data(sentinel.utf8)) == nil else { throw ProofFailure.outputSentinel }
            guard !bytes.isEmpty || emptyNames.contains(url.lastPathComponent) else { throw ProofFailure.outputInventory }
        }
    }

    static let receiptNames: Set<String> = ["defaults.plist", "sink-inventory.json", "data-absence.json"]
    static let outputBuckets: Set<String> = ["self-test journey.json", "self-test popover.png", "accessibility tree", "native captures", "diagnostics"]

    // The one classification of a retained output file into its scan bucket (scan and receipt reconciliation share it).
    static func bucket(_ url: URL) -> String {
        switch url.lastPathComponent {
        case "journey.json", "checkpoint.json": return "self-test journey.json"
        case "popover.png": return "self-test popover.png"
        default:
            if url.lastPathComponent.hasSuffix(".ax.json") { return "accessibility tree" }
            return url.pathExtension == "png" ? "native captures" : "diagnostics"
        }
    }

    // The exact file set the sessions' own published artifacts and the native test imply; the cleanup receipt exists only once cleaned.
    static func requiredFiles(output: URL, fault: String?, cancelled: Bool, cleaned: Bool, sessions: [Native011LaunchSession]) -> Set<URL> {
        let positive = fault == nil && !cancelled
        var required: Set<URL> = []
        for phase in positive ? ["first", "restart"] : ["first"] {
            let out = output.appendingPathComponent(phase)
            required.formUnion(phaseFiles(phase: phase, fault: fault, cancelled: cancelled, sessions: sessions).map { out.appendingPathComponent($0) })
        }
        required.formUnion(["defaults.plist", "sink-inventory.json"].map { output.appendingPathComponent($0) })
        if !positive { required.insert(output.appendingPathComponent("data-absence.json")) }
        if cleaned { required.insert(output.appendingPathComponent("cleanup.log")) }
        return required
    }

    // The persisted sink-inventory receipt: the files actually present and the scan's bucket counts.
    static func receipt(files: Set<URL>, buckets: [String: Int], cancelled: Bool) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["files": files.map(\.path).sorted(), "buckets": buckets, "cancelled": cancelled], options: [.sortedKeys])
    }

    // The receipt written by the scan predates the evidence that the final publication, the deletion and the terminal checks produce.
    // Every final verification therefore rewrites the file names and output-bucket counts from the files it just admitted (the sinks
    // outside the output directory keep their scanned counts), and refuses a receipt it cannot parse, whose case kind differs or
    // whose `files` or `buckets` is malformed, never sanitizing a malformed required field away.
    static func reconcile(_ actual: Set<URL>, in directory: URL, cancelled: Bool) throws {
        let url = directory.appendingPathComponent("sink-inventory.json")
        guard actual.contains(url) else { return }
        let stored = try Data(contentsOf: url)
        guard let object = (try? JSONSerialization.jsonObject(with: stored)) as? [String: Any], object["cancelled"] as? Bool == cancelled,
              object["files"] is [String], var buckets = object["buckets"] as? [String: Int] else { throw ProofFailure.outputInventory }
        for name in outputBuckets { buckets[name] = nil }
        for file in actual where !receiptNames.contains(file.lastPathComponent) { buckets[bucket(file), default: 0] += 1 }
        let current = try receipt(files: actual, buckets: buckets, cancelled: cancelled)
        if current != stored { try current.write(to: url, options: .atomic) }
    }

    // The final consumer shared by the native deferred cleanup and the offline correction cases. Without a primary other than a
    // cancellation the membership is exact. After one, a native artifact the failing journey never produced may be absent, but no file
    // outside the derived set is ever admitted (a renamed secondary whose directory sync or readback failed is not registered, so it is
    // refused) and a registered secondary must exist. Every admitted byte, the receipt as stored included, is scanned before the
    // receipt is reconciled, and again afterwards so the rewrite is scanned too.
    static func final(output: URL, fault: String?, cancelled: Bool, cleaned: Bool, sessions: [Native011LaunchSession]) throws {
        let required = requiredFiles(output: output, fault: fault, cancelled: cancelled, cleaned: cleaned, sessions: sessions)
        let actual: Set<URL>
        if sessions.contains(where: { $0.retention.primary.map { $0.boundary != Native011LaunchBoundary.cancellation.rawValue } ?? false }) {
            actual = Set(try files(in: output))
            let registered = required.filter { $0.lastPathComponent == Native011LaunchSession.secondaryName }
            guard actual.isSubset(of: required), registered.isSubset(of: actual) else { throw ProofFailure.outputInventory }
        } else { actual = try checked(in: output, required: required) }
        try verify(actual)
        try reconcile(actual, in: output, cancelled: cancelled)
        try verify(actual)
    }
}

// The actual deferred-cleanup ordering shared by every native case: owner cleanup first, then the final evidence
// publication and close, then the read-only scan, then the final output verification, and fixture/default deletion only
// when retention is known, every request is resolved, the final publication kept every channel and that verification
// settled without producing any evidence of its own.
@MainActor enum Native011DeferredCleanup {
    struct Steps {
        var verifyWrapper: () throws -> Void
        var scan: () throws -> Void
        var removeFixture: () throws -> Void
        var verifyOutputs: (Bool) throws -> Void
    }

    // Every failure recorded from cleanup entry on, including cleanup and deadline outcomes, is reported once the last
    // effects are done and before the sessions are disposed; the native caller fails on each. Every evidence-producing
    // check precedes the deletion admission: the final publication, fallback close, scan and the pre-deletion output
    // verification (membership and bytes of everything published so far), so a failure there is published and still
    // verified by the terminal verification, and a secondary or diagnostic loss withholds deletion. Evidence that only
    // the deletion or the terminal checks produce cannot precede the deletion: it is verified by one confirming
    // verification that never publishes again, so nothing is assumed covered by the earlier scan and no loop can arise.
    static func run(sessions: [Native011LaunchSession], steps: Steps, report: (String) -> Void) {
        for session in sessions { session.cleanup() }
        func secondary(_ stage: String, _ error: Error) {
            let failure = native011Failure(error, stage: stage)
            guard let last = sessions.last else { return report("\(stage): \(failure.boundary)") }
            last.recordFailure(Native011LaunchFailure(boundary: failure.boundary, stage: stage, reason: failure.reason))
        }
        // The shared deadline guard follows every effect: an exceeded bound is retained and forbids the next deletion.
        func inBounds() -> Bool { sessions.map { $0.withinBounds() }.allSatisfy { $0 } }
        func evidence() -> Int { sessions.reduce(0) { $0 + $1.evidenceWrites } }
        do { try steps.verifyWrapper() } catch { secondary("deferred-wrapper", error) }
        _ = inBounds()
        for session in sessions { session.finalize() }
        var scanned = false
        if sessions.allSatisfy(\.mayScan) {
            do { try steps.scan(); scanned = true } catch { secondary("deferred-scan", error) }
            _ = inBounds()
        } else { report("native evidence scan withheld: primary retention unknown") }
        var cleaned = false
        if scanned, inBounds(), sessions.allSatisfy(\.mayDelete) {
            var settled = false
            do { try steps.verifyOutputs(false); settled = true } catch { secondary("deferred-outputs", error) }
            if settled, inBounds(), sessions.allSatisfy(\.mayDelete) {
                do { try steps.removeFixture(); cleaned = true } catch { secondary("deferred-fixture", error) }
                _ = inBounds()
            } else { report("fixture/default deletion withheld: final output verification did not settle") }
        } else if scanned { report("fixture/default deletion withheld: unresolved native owner or exceeded bound") }
        let observed = evidence()
        do { try steps.verifyOutputs(cleaned) } catch { secondary("deferred-outputs", error) }
        _ = inBounds()
        if evidence() != observed {
            do { try steps.verifyOutputs(cleaned) } catch { report("deferred-outputs-final: \(native011Failure(error, stage: "deferred-outputs-final").boundary)") }
            let confirmed = evidence()
            _ = inBounds()
            if evidence() != confirmed { report("terminal evidence published after the last output verification is unverified") }
        }
        for session in sessions {
            for problem in session.problems { report(problem) }
            for error in session.retention.errors { report("native retention error retained: \(error.boundary) \(error.stage)") }
        }
    }
}
// native011-launch-binding:end

// MARK: live effect leaves (OS and AppKit only; the XCTest proxy probes are supplied by the native test)

func native011ProcessIdentity(pid: Int32) -> Native011Identity? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_pid == UInt32(pid) else { return nil }
    var path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
    let bytes = path.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return Native011Identity(pid: Int(pid), sec: Int(info.pbi_start_tvsec), usec: Int(info.pbi_start_tvusec), uid: Int(info.pbi_uid),
                             path: String(decoding: bytes, as: UTF8.self))
}

@MainActor final class Native011LiveApp: Native011RunningApp {
    let application: NSRunningApplication

    init(_ application: NSRunningApplication) { self.application = application }

    var pid: Int32 { application.processIdentifier }
    var bundleURL: URL? { application.bundleURL }
    var executableURL: URL? { application.executableURL }
    var bundleIdentifier: String? { application.bundleIdentifier }
    var isFinishedLaunching: Bool { application.isFinishedLaunching }
    var isTerminated: Bool { application.isTerminated }

    func isSameObject(as other: any Native011RunningApp) -> Bool {
        (other as? Native011LiveApp).map { application.isEqual($0.application) } ?? false
    }

    func forceTerminate() -> Bool { application.forceTerminate() }
}

@MainActor final class Native011LiveLauncher: Native011Launcher {
    private let process: Process

    init(process: Process) { self.process = process }

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }

    // The launcher's own Process status; never the application's.
    var exit: (reason: String, status: Int)? {
        guard !process.isRunning else { return nil }
        process.waitUntilExit()
        return (process.terminationReason == .exit ? "exit" : "uncaughtSignal", Int(process.terminationStatus))
    }

    func terminate() { process.terminate() }
}

// EVFILT_PROC with NOTE_EXIT|NOTE_EXITSTATUS, registered for the admitted application's pid before any native input.
@MainActor final class Native011LiveExitObserver: Native011ExitObserver {
    private let queue: Int32

    init(pid: Int32) throws {
        let descriptor = kqueue()
        guard descriptor >= 0 else { throw Native011ObserverFailure.unavailable }
        _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        var change = kevent(ident: UInt(pid), filter: Int16(EVFILT_PROC), flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT | EV_RECEIPT),
                            fflags: UInt32(NOTE_EXIT) | UInt32(NOTE_EXITSTATUS), data: 0, udata: nil)
        var receipt = kevent()
        var immediate = timespec(tv_sec: 0, tv_nsec: 0)
        guard kevent(descriptor, &change, 1, &receipt, 1, &immediate) == 1, receipt.flags & UInt16(EV_ERROR) != 0 else {
            _ = Darwin.close(descriptor)
            throw Native011ObserverFailure.unavailable
        }
        switch Int32(truncatingIfNeeded: receipt.data) {
        case 0: queue = descriptor
        case ESRCH:
            _ = Darwin.close(descriptor)
            throw Native011ObserverFailure.alreadyExited
        case EPERM, EACCES:
            _ = Darwin.close(descriptor)
            throw Native011ObserverFailure.denied
        default:
            _ = Darwin.close(descriptor)
            throw Native011ObserverFailure.unavailable
        }
    }

    deinit { _ = Darwin.close(queue) }

    func poll() -> Native011ExitObservation {
        var event = kevent()
        var immediate = timespec(tv_sec: 0, tv_nsec: 0)
        guard kevent(queue, nil, 0, &event, 1, &immediate) == 1, event.filter == Int16(EVFILT_PROC),
              event.flags & UInt16(EV_ERROR) == 0, event.fflags & UInt32(NOTE_EXIT) != 0 else { return .pending }
        guard event.fflags & UInt32(NOTE_EXITSTATUS) != 0 else { return .exitedWithoutStatus }
        return .exited(rawWaitStatus: Int(event.data))
    }
}

// Applications present before the request form the baseline; arrivals are union of the NSWorkspace launch
// notification (installed before the request) and later enumerations, keyed by pid and kernel start time.
@MainActor final class Native011LiveArrivals: Native011Arrivals {
    private struct Key: Hashable {
        let pid: Int32, sec: Int, usec: Int
    }

    let baseline: [any Native011RunningApp]
    private let known: Set<Key>
    private var notified: [NSRunningApplication] = []
    private var token: NSObjectProtocol?

    private static func key(_ application: NSRunningApplication) -> Key {
        let identity = native011ProcessIdentity(pid: application.processIdentifier)
        return Key(pid: application.processIdentifier, sec: identity?.sec ?? -1, usec: identity?.usec ?? -1)
    }

    init() {
        let current = NSWorkspace.shared.runningApplications
        baseline = current.map { Native011LiveApp($0) }
        known = Set(current.map(Self.key))
        token = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil,
                                                                  queue: .main) { [weak self] note in
            guard let application = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            MainActor.assumeIsolated { self?.notified.append(application) }
        }
    }

    func arrived() -> [any Native011RunningApp] {
        var seen = Set<Int32>()
        var result: [any Native011RunningApp] = []
        for application in notified + NSWorkspace.shared.runningApplications {
            guard !known.contains(Self.key(application)), seen.insert(application.processIdentifier).inserted else { continue }
            result.append(Native011LiveApp(application))
        }
        return result
    }

    func stop() {
        if let token { NSWorkspace.shared.notificationCenter.removeObserver(token) }
        token = nil
    }
}

@MainActor final class Native011LivePlatform: Native011Platform {
    var proxyProbe: () -> Native011ProxyState = { .unavailable }
    var statusProbe: () -> Bool = { false }

    nonisolated static func monotonicMilliseconds() -> Int { Int(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

    func now() -> Int { Self.monotonicMilliseconds() }
    func pause() { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
    func startArrivalObservation() -> any Native011Arrivals { Native011LiveArrivals() }

    // The launcher is a Process with no shell and no inherited stdio.
    func startLauncher(argv: [String]) throws -> any Native011Launcher {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        return Native011LiveLauncher(process: process)
    }

    func identity(pid: Int32) -> Native011Identity? { native011ProcessIdentity(pid: pid) }
    func application(pid: Int32) -> (any Native011RunningApp)? { NSRunningApplication(processIdentifier: pid).map { Native011LiveApp($0) } }
    func observeExit(pid: Int32) throws -> any Native011ExitObserver { try Native011LiveExitObserver(pid: pid) }
    func proxyState() -> Native011ProxyState { proxyProbe() }
    func statusItemOwned() -> Bool { statusProbe() }
}
