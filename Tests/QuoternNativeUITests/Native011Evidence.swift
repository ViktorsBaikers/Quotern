import AppKit
import CryptoKit
import Darwin
import Foundation

// MARK: safe-file publication (OS effect leaves are injectable; the sequencing below is the production code)

struct Native011FileFailure: Error { let stage: String }

struct Native011FileOps {
    var open: (String, Int32, mode_t) -> Int32 = { Darwin.open($0, $1, $2) }
    var write: (Int32, UnsafeRawPointer, Int) -> Int = { Darwin.write($0, $1, $2) }
    var read: (Int32, UnsafeMutableRawPointer, Int) -> Int = { Darwin.read($0, $1, $2) }
    var fsync: (Int32) -> Int32 = { Darwin.fsync($0) }
    var close: (Int32) -> Int32 = { Darwin.close($0) }
    var rename: (String, String, Bool) -> Int32 = { from, to, exclusive in
        exclusive ? Darwin.renamex_np(from, to, UInt32(RENAME_EXCL)) : Darwin.rename(from, to)
    }
    var unlink: (String) -> Int32 = { Darwin.unlink($0) }
    var ftruncate: (Int32, off_t) -> Int32 = { Darwin.ftruncate($0, $1) }
    var lseek: (Int32, off_t, Int32) -> off_t = { Darwin.lseek($0, $1, $2) }
}

enum Native011SafeFile {
    static func writeAll(_ descriptor: Int32, _ bytes: Data, ops: Native011FileOps) -> Bool {
        bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = ops.write(descriptor, buffer.baseAddress! + offset, buffer.count - offset)
                if count < 0 { if errno == EINTR { continue }; return false }
                if count == 0 { return false }
                offset += count
            }
            return true
        }
    }

    static func syncDirectory(_ directory: URL, ops: Native011FileOps) -> Bool {
        let descriptor = ops.open(directory.path, O_RDONLY | O_CLOEXEC, 0)
        guard descriptor >= 0 else { return false }
        let synced = ops.fsync(descriptor) == 0
        return ops.close(descriptor) == 0 && synced
    }

    static func admitted(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG && metadata.st_nlink == 1 && metadata.st_uid == geteuid() && metadata.st_mode & 0o7777 == 0o600
    }

    static func readBack(_ url: URL, expected: Data, stage: String, ops: Native011FileOps) throws {
        let descriptor = ops.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Native011FileFailure(stage: stage) }
        defer { _ = ops.close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, admitted(metadata), Int(metadata.st_size) == expected.count else {
            throw Native011FileFailure(stage: stage)
        }
        var actual = Data(count: expected.count + 1)
        let count = actual.withUnsafeMutableBytes { ops.read(descriptor, $0.baseAddress!, $0.count) }
        guard count == expected.count, actual.prefix(count) == expected else { throw Native011FileFailure(stage: stage) }
    }

    // Exclusive same-directory 0600 temporary, complete write, file sync, close, atomic publication,
    // parent sync and exact no-follow readback.
    static func publish(_ bytes: Data, as name: String, in directory: URL, replace: Bool, bound: Int, ops: Native011FileOps) throws {
        guard bytes.count <= bound else { throw Native011FileFailure(stage: "bound") }
        let final = directory.appendingPathComponent(name)
        let temporary = final.path + ".tmp"
        let descriptor = ops.open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Native011FileFailure(stage: "create") }
        var held = true
        func abandon(_ stage: String) -> Native011FileFailure {
            if held { _ = ops.close(descriptor); held = false }
            _ = ops.unlink(temporary)
            return Native011FileFailure(stage: stage)
        }
        guard writeAll(descriptor, bytes, ops: ops) else { throw abandon("write") }
        guard ops.fsync(descriptor) == 0 else { throw abandon("file-sync") }
        held = false
        guard ops.close(descriptor) == 0 else { throw abandon("close") }
        guard ops.rename(temporary, final.path, !replace) == 0 else { throw abandon("replace") }
        guard syncDirectory(directory, ops: ops) else { throw Native011FileFailure(stage: "directory-sync") }
        try readBack(final, expected: bytes, stage: "readback", ops: ops)
    }

    // The stages after the atomic rename: the pathname already names the new, not yet verified bytes.
    static let renamedStages: Set<String> = ["directory-sync", "readback"]

    static func createEmpty(_ url: URL, ops: Native011FileOps) throws {
        let descriptor = ops.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Native011FileFailure(stage: "create") }
        let synced = ops.fsync(descriptor) == 0
        guard ops.close(descriptor) == 0, synced else { throw Native011FileFailure(stage: "file-sync") }
        guard syncDirectory(url.deletingLastPathComponent(), ops: ops) else { throw Native011FileFailure(stage: "directory-sync") }
        try readBack(url, expected: Data(), stage: "readback", ops: ops)
    }
}

// A preopened descriptor naming an admitted empty file; the second durable channel for the first primary.
@MainActor final class Native011FallbackFile {
    private let url: URL
    private let ops: Native011FileOps
    private var descriptor: Int32 = -1
    private var admittedIdentity = stat()

    init(url: URL, ops: Native011FileOps) {
        self.url = url
        self.ops = ops
    }

    func prepare() throws {
        descriptor = ops.open(url.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Native011FileFailure(stage: "fallback-create") }
        guard fstat(descriptor, &admittedIdentity) == 0 else { throw Native011FileFailure(stage: "fallback-create") }
        guard ops.fsync(descriptor) == 0 else { throw Native011FileFailure(stage: "fallback-prepare-file-sync") }
        guard Native011SafeFile.syncDirectory(url.deletingLastPathComponent(), ops: ops) else {
            throw Native011FileFailure(stage: "fallback-prepare-directory-sync")
        }
        try Native011SafeFile.readBack(url, expected: Data(), stage: "fallback-prepare-readback", ops: ops)
    }

    func write(_ bytes: Data) throws {
        var held = stat(), named = stat()
        guard descriptor >= 0, fstat(descriptor, &held) == 0, lstat(url.path, &named) == 0, Native011SafeFile.admitted(held),
              held.st_dev == admittedIdentity.st_dev, held.st_ino == admittedIdentity.st_ino,
              named.st_dev == held.st_dev, named.st_ino == held.st_ino else { throw Native011FileFailure(stage: "fallback-identity") }
        guard ops.lseek(descriptor, 0, SEEK_SET) == 0, Native011SafeFile.writeAll(descriptor, bytes, ops: ops),
              ops.ftruncate(descriptor, off_t(bytes.count)) == 0 else { throw Native011FileFailure(stage: "fallback-write") }
        guard ops.fsync(descriptor) == 0 else { throw Native011FileFailure(stage: "fallback-sync") }
        try Native011SafeFile.readBack(url, expected: bytes, stage: "fallback-readback", ops: ops)
    }

    func close() -> Bool {
        guard descriptor >= 0 else { return true }
        let closed = ops.close(descriptor) == 0
        descriptor = -1
        return closed
    }
}

// MARK: first-primary retention

struct Native011Primary: Equatable {
    let boundary: String, stage: String, reason: String, observedMs: Int
}

struct Native011Outcome: Equatable {
    let boundary: String, stage: String, reason: String
    init(_ failure: Native011LaunchFailure) { boundary = failure.boundary; stage = failure.stage; reason = failure.reason }
    var json: Native011JSON { .object(["boundary": .string(boundary), "stage": .string(stage), "reason": .string(reason)]) }
}

@MainActor final class Native011Retention {
    enum Disposition: String { case none, primary, fallback, unknown }
    static let primaryName = "primary.json", fallbackName = "primary-fallback.log"

    private(set) var disposition = Disposition.none
    private(set) var primary: Native011Primary?
    private(set) var outcomes: [Native011Outcome] = []
    private(set) var errors: [Native011Outcome] = []
    private let directory: URL
    private let candidate: String
    private let ops: Native011FileOps
    private let fallback: Native011FallbackFile

    init(directory: URL, candidate: String, ops: Native011FileOps) {
        self.directory = directory
        self.candidate = candidate
        self.ops = ops
        fallback = Native011FallbackFile(url: directory.appendingPathComponent(Self.fallbackName), ops: ops)
    }

    // Failure aborts child creation.
    func prepare() throws {
        do { try fallback.prepare() }
        catch let failure as Native011FileFailure {
            throw Native011LaunchFailure(.publication, stage: failure.stage, reason: "fallback-preparation")
        }
    }

    func noteError(_ failure: Native011LaunchFailure) {
        if errors.count < Native011Bounds.retentionErrors { errors.append(Native011Outcome(failure)) }
    }

    @discardableResult func note(_ failure: Native011LaunchFailure) -> Bool {
        guard outcomes.count < Native011Bounds.outcomes else {
            noteError(Native011LaunchFailure(.bound, stage: "outcomes", reason: "limit"))
            return false
        }
        outcomes.append(Native011Outcome(failure))
        return true
    }

    // Only the first call has effect. The record is retained and verified here, before the caller's next effect.
    @discardableResult func retain(_ candidatePrimary: Native011Primary) -> Disposition {
        guard primary == nil else { return disposition }
        primary = candidatePrimary
        let object: Native011JSON = .object([
            "v": .int(1), "source_sha256": .string(candidate), "producer": .string("native"), "boundary": .string(candidatePrimary.boundary),
            "reason": .string(candidatePrimary.reason), "stage": .string(candidatePrimary.stage),
            "observed_elapsed_ms": .int(max(0, min(candidatePrimary.observedMs, 86_400_000))),
        ])
        let bytes = Data((object.encoded() + "\n").utf8)
        guard bytes.count <= Native011Bounds.primaryBytes else {
            noteError(Native011LaunchFailure(.bound, stage: "primary", reason: "record-size"))
            disposition = .unknown
            return disposition
        }
        do {
            try Native011SafeFile.publish(bytes, as: Self.primaryName, in: directory, replace: false,
                                          bound: Native011Bounds.primaryBytes, ops: ops)
            disposition = .primary
            return disposition
        } catch let failure as Native011FileFailure {
            noteError(Native011LaunchFailure(.publication, stage: "primary-" + failure.stage, reason: "primary-publication"))
        } catch { noteError(Native011LaunchFailure(.publication, stage: "primary", reason: "primary-publication")) }
        do {
            try fallback.write(bytes)
            disposition = .fallback
        } catch let failure as Native011FileFailure {
            noteError(Native011LaunchFailure(.publication, stage: failure.stage, reason: "fallback-publication"))
            disposition = .unknown
        } catch {
            noteError(Native011LaunchFailure(.publication, stage: "fallback", reason: "fallback-publication"))
            disposition = .unknown
        }
        return disposition
    }

    func close() -> Bool { fallback.close() }
}

// MARK: effect leaves for the launcher, application, exit observation and XCTest proxy

enum Native011ExitObservation { case pending, exited(rawWaitStatus: Int), exitedWithoutStatus }
enum Native011ObserverFailure: Error { case denied, alreadyExited, unavailable }
enum Native011ProxyState: String { case unavailable, runningBackground, runningForeground, other }

@MainActor protocol Native011RunningApp: AnyObject {
    var pid: Int32 { get }
    var bundleURL: URL? { get }
    var executableURL: URL? { get }
    var bundleIdentifier: String? { get }
    var isFinishedLaunching: Bool { get }
    var isTerminated: Bool { get }
    func isSameObject(as other: any Native011RunningApp) -> Bool
    func forceTerminate() -> Bool
}

@MainActor protocol Native011ExitObserver: AnyObject {
    func poll() -> Native011ExitObservation
}

@MainActor protocol Native011Launcher: AnyObject {
    var pid: Int32 { get }
    var isRunning: Bool { get }
    var exit: (reason: String, status: Int)? { get }
    func terminate()
}

@MainActor protocol Native011Arrivals: AnyObject {
    var baseline: [any Native011RunningApp] { get }
    func arrived() -> [any Native011RunningApp]
    func stop()
}

@MainActor protocol Native011Platform: AnyObject {
    func now() -> Int
    func pause()
    func startArrivalObservation() -> any Native011Arrivals
    func startLauncher(argv: [String]) throws -> any Native011Launcher
    func identity(pid: Int32) -> Native011Identity?
    func application(pid: Int32) -> (any Native011RunningApp)?
    func observeExit(pid: Int32) throws -> any Native011ExitObserver
    func proxyState() -> Native011ProxyState
    func statusItemOwned() -> Bool
}

struct Native011AdmittedApplication {
    let app: any Native011RunningApp
    let identity: Native011Identity
    let executable: URL
    let bundleURL: URL
}

struct Native011LaunchContext {
    let receipt: Native011ReceiptContext
    let wrapper: URL
    let executable: URL
    let runner: Native011Identity
    let expectedBundleID: String
    let out: URL
}
