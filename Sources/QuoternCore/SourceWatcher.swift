import CoreServices
import Dispatch
import Foundation

/// A monotonic clock with one-shot timers. Tests inject a manual clock; the app uses Dispatch.
@MainActor
public protocol WatcherClock: AnyObject {
    /// Monotonic seconds.
    var now: TimeInterval { get }
    /// Runs `body` once, `delay` seconds from now within `leeway`, unless cancelled.
    func schedule(after delay: TimeInterval, leeway: TimeInterval, _ body: @escaping @MainActor @Sendable () -> Void) -> WatcherTimer
}

@MainActor
public protocol WatcherTimer: AnyObject {
    func cancel()
}

/// A running file-event stream; `stop()` ends it for good.
@MainActor
public protocol WatcherStream: AnyObject {
    func stop()
}

public struct WatcherEvent: Equatable, Sendable {
    public let path: String
    public let flags: FSEventStreamEventFlags

    public init(path: String, flags: FSEventStreamEventFlags) {
        self.path = path
        self.flags = flags
    }
}

/// Starts an event stream over `roots` with `latency` that delivers batches on the main actor.
public typealias WatcherStreamFactory = @MainActor (
    _ roots: [String], _ latency: TimeInterval, _ handler: @escaping @MainActor ([WatcherEvent]) -> Void
) -> WatcherStream?

/// Turns launch, source enable, Refresh, watcher (re)start, file events and a periodic tick into
/// reconcile passes. Every trigger is coalesced: at most one pass in flight and one follow-up
/// pending, at least 5 s between pass starts. With no enabled source there is no stream, no
/// timer and no pass. Rust owns ingest, backoff and freshness; this only decides when to ask.
@MainActor
public final class SourceWatcher {
    public static let minimumSpacing: TimeInterval = 5
    public static let period: TimeInterval = 300
    public static let periodLeeway: TimeInterval = 30
    public static let latency: TimeInterval = 2

    /// Flags that mean events were lost or the root moved: restart and reconcile everything.
    static let restartFlags = FSEventStreamEventFlags(
        kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped
            | kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagRootChanged)

    private let clock: WatcherClock
    private let makeStream: WatcherStreamFactory
    private let dataDirectory: String
    private let pass: @MainActor () async -> Void

    private var enabled = false
    private var roots: [String] = []
    private var stream: WatcherStream?
    private var tick: WatcherTimer?
    private var start: WatcherTimer?
    private var lastStart: TimeInterval?
    private var followUp = false

    public private(set) var passInFlight = false
    /// Passes started so far.
    public private(set) var passCount = 0
    /// Streams started so far, the first one included.
    public private(set) var streamStarts = 0
    public var timerActive: Bool { tick != nil }
    public var streamActive: Bool { stream != nil }

    public init(
        clock: WatcherClock,
        dataDirectory: String,
        makeStream: @escaping WatcherStreamFactory,
        pass: @escaping @MainActor () async -> Void
    ) {
        self.clock = clock
        self.dataDirectory = canonicalPath(dataDirectory)
        self.makeStream = makeStream
        self.pass = pass
    }

    /// Applies the enabled-source set, at launch and whenever a source is enabled or denied.
    /// With an enabled source it (re)starts the stream and the periodic timer and requests one
    /// pass; without one it stops both and never passes.
    public func update(enabled: Bool, roots: [String]) {
        self.enabled = enabled
        self.roots = enabled ? roots : []
        guard enabled else {
            stopStream()
            tick?.cancel()
            tick = nil
            start?.cancel()
            start = nil
            followUp = false
            return
        }
        restartStream()
        scheduleTick()
        request()
    }

    /// The Refresh action.
    public func refresh() {
        request()
    }

    /// One delivered batch. Writes inside the data directory never trigger; lost events or a
    /// changed root restart the stream; anything else asks for one pass.
    func receive(_ events: [WatcherEvent]) {
        let relevant = events.filter { !isInsideDataDirectory($0.path) }
        guard !relevant.isEmpty else { return }
        if relevant.contains(where: { $0.flags & Self.restartFlags != 0 }) {
            restartStream()
        }
        request()
    }

    private func isInsideDataDirectory(_ path: String) -> Bool {
        let trimmed = path.hasSuffix("/") ? String(path.dropLast()) : path
        return trimmed == dataDirectory || trimmed.hasPrefix(dataDirectory + "/")
    }

    private func restartStream() {
        stopStream()
        guard !roots.isEmpty else { return }
        stream = makeStream(roots, Self.latency) { [weak self] events in self?.receive(events) }
        if stream != nil { streamStarts += 1 }
    }

    private func stopStream() {
        stream?.stop()
        stream = nil
    }

    /// One-shot ticks re-armed after each firing: ticks missed while asleep merge into one.
    private func scheduleTick() {
        guard enabled, tick == nil else { return }
        tick = clock.schedule(after: Self.period, leeway: Self.periodLeeway) { [weak self] in
            guard let self else { return }
            tick = nil
            request()
            scheduleTick()
        }
    }

    private func request() {
        guard enabled else { return }
        if passInFlight {
            followUp = true
            return
        }
        // Triggers arriving before the scheduled start merge into it.
        guard start == nil else { return }
        let earliest = (lastStart ?? -.infinity) + Self.minimumSpacing
        start = clock.schedule(after: max(0, earliest - clock.now), leeway: 0) { [weak self] in
            self?.begin()
        }
    }

    private func begin() {
        start = nil
        guard enabled else { return }
        passInFlight = true
        lastStart = clock.now
        passCount += 1
        let pass = self.pass
        Task { [weak self] in
            await pass()
            self?.finish()
        }
    }

    private func finish() {
        passInFlight = false
        if followUp {
            followUp = false
            request()
        }
    }
}

/// The folders the user chose, kept in user defaults for the file-event stream. Rust keeps the
/// sources themselves; this list only says where to watch. It holds full folder paths.
public struct WatchedRoots {
    static let key = "watchedRoots"
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public var all: [String] {
        defaults.stringArray(forKey: Self.key) ?? []
    }

    public func add(_ root: String) {
        var roots = all
        guard !roots.contains(root) else { return }
        roots.append(root)
        defaults.set(roots, forKey: Self.key)
    }
}

/// The path with every symlink resolved, as file events report it (`/var` is `/private/var`);
/// a path that does not exist yet stays as given.
func canonicalPath(_ path: String) -> String {
    guard let resolved = realpath(path, nil) else { return path }
    defer { free(resolved) }
    return String(cString: resolved)
}

// MARK: - Production clock and stream

@MainActor
public final class DispatchWatcherClock: WatcherClock {
    public init() {}

    public var now: TimeInterval {
        TimeInterval(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
    }

    public func schedule(after delay: TimeInterval, leeway: TimeInterval, _ body: @escaping @MainActor @Sendable () -> Void) -> WatcherTimer {
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + delay, leeway: .milliseconds(Int(leeway * 1_000)))
        timer.setEventHandler { MainActor.assumeIsolated { body() } }
        timer.resume()
        return DispatchTimerHandle(timer)
    }
}

@MainActor
private final class DispatchTimerHandle: WatcherTimer {
    private let timer: DispatchSourceTimer

    init(_ timer: DispatchSourceTimer) { self.timer = timer }

    func cancel() { timer.cancel() }
}

/// One FSEventStream over the enabled roots, delivering on the main queue.
@MainActor
public final class FSEventsWatcherStream: WatcherStream {
    private final class Box {
        let handler: @MainActor ([WatcherEvent]) -> Void
        init(_ handler: @escaping @MainActor ([WatcherEvent]) -> Void) { self.handler = handler }
    }

    private let box: Box
    private var stream: FSEventStreamRef?

    public static func make(roots: [String], latency: TimeInterval, handler: @escaping @MainActor ([WatcherEvent]) -> Void) -> WatcherStream? {
        let made = FSEventsWatcherStream(handler)
        return made.start(roots: roots, latency: latency) ? made : nil
    }

    private init(_ handler: @escaping @MainActor ([WatcherEvent]) -> Void) {
        box = Box(handler)
    }

    private func start(roots: [String], latency: TimeInterval) -> Bool {
        var context = FSEventStreamContext(
            version: 0, info: Unmanaged.passUnretained(box).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, paths, flags, _ in
            guard let info else { return }
            let box = Unmanaged<Box>.fromOpaque(info).takeUnretainedValue()
            let names = unsafeBitCast(paths, to: NSArray.self) as? [String] ?? []
            let events = (0..<min(count, names.count)).map { WatcherEvent(path: names[$0], flags: flags[$0]) }
            MainActor.assumeIsolated { box.handler(events) }
        }
        let options = FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagWatchRoot)
        guard let created = FSEventStreamCreate(
            nil, callback, &context, roots.map(canonicalPath) as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow), latency, options)
        else { return false }
        FSEventStreamSetDispatchQueue(created, .main)
        guard FSEventStreamStart(created) else {
            FSEventStreamInvalidate(created)
            FSEventStreamRelease(created)
            return false
        }
        stream = created
        return true
    }

    public func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    isolated deinit {
        stop()
    }
}
