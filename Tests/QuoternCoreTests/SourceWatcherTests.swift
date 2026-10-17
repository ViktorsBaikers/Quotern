import CoreServices
import Darwin
import Foundation
import XCTest
@testable import QuoternCore

/// A manual monotonic clock: timers fire only when the test advances it.
@MainActor
final class ManualClock: WatcherClock {
    private final class Timer: WatcherTimer {
        let due: TimeInterval
        let body: @MainActor @Sendable () -> Void
        var cancelled = false
        init(due: TimeInterval, body: @escaping @MainActor @Sendable () -> Void) {
            self.due = due
            self.body = body
        }
        func cancel() { cancelled = true }
    }

    private(set) var now: TimeInterval = 0
    private var timers: [Timer] = []
    /// (delay, leeway) of every timer scheduled, for the cadence assertions.
    private(set) var scheduled: [(delay: TimeInterval, leeway: TimeInterval)] = []

    func schedule(after delay: TimeInterval, leeway: TimeInterval, _ body: @escaping @MainActor @Sendable () -> Void) -> WatcherTimer {
        let timer = Timer(due: now + delay, body: body)
        timers.append(timer)
        scheduled.append((delay, leeway))
        return timer
    }

    var liveTimers: Int { timers.filter { !$0.cancelled }.count }

    /// Fires every due timer in order up to `time`; `settle` runs after each firing so a started
    /// pass can finish before later timers fire.
    func advance(to time: TimeInterval, settle: () async -> Void) async {
        while let next = timers.filter({ !$0.cancelled && $0.due <= time }).min(by: { $0.due < $1.due }) {
            timers.removeAll { $0 === next }
            now = next.due
            next.body()
            await settle()
        }
        now = time
    }
}

@MainActor
final class ManualStream: WatcherStream {
    let roots: [String]
    let handler: @MainActor ([WatcherEvent]) -> Void
    private(set) var stopped = false
    init(roots: [String], handler: @escaping @MainActor ([WatcherEvent]) -> Void) {
        self.roots = roots
        self.handler = handler
    }
    func stop() { stopped = true }
}

@MainActor
final class SourceWatcherTests: XCTestCase {
    private var clock: ManualClock!
    private var streams: [ManualStream] = []
    private var passes = 0
    /// While set, each pass waits until the test resumes it.
    private var gate: CheckedContinuation<Void, Never>?
    private var holdPasses = false

    override func setUp() async throws {
        clock = ManualClock()
        streams = []
        passes = 0
        holdPasses = false
    }

    private func watcher(dataDirectory: String = "/data", pass: (@MainActor () async -> Void)? = nil) -> SourceWatcher {
        SourceWatcher(
            clock: clock, dataDirectory: dataDirectory,
            makeStream: { [unowned self] roots, latency, handler in
                XCTAssertEqual(latency, 2)
                let stream = ManualStream(roots: roots, handler: handler)
                streams.append(stream)
                return stream
            },
            pass: pass ?? { [unowned self] in
                passes += 1
                if holdPasses {
                    await withCheckedContinuation { gate = $0 }
                }
            }
        )
    }

    /// Lets a started pass run to completion (bounded); a held pass stays in flight.
    private func settle(_ watcher: SourceWatcher) async {
        for _ in 0..<2_000 where watcher.passInFlight && gate == nil && !holdPasses {
            try? await Task.sleep(for: .milliseconds(5))
        }
        for _ in 0..<10 { await Task.yield() }
    }

    private func advance(_ watcher: SourceWatcher, to time: TimeInterval) async {
        await clock.advance(to: time) { await self.settle(watcher) }
    }

    func testLaunchIssuesExactlyOnePassWithoutFSEvent() async {
        let watcher = watcher()
        watcher.update(enabled: true, roots: ["/source"])
        await advance(watcher, to: 1)
        XCTAssertEqual(passes, 1, "the launch pass runs with no file event")
        XCTAssertEqual(watcher.passCount, 1)
        XCTAssertEqual(streams.count, 1)
        XCTAssertEqual(streams[0].roots, ["/source"])
        await advance(watcher, to: 299)
        XCTAssertEqual(passes, 1, "nothing else before the first periodic tick")
    }

    func testEnableRefreshAndWatcherRestartEachIssueOneCoalescedPass() async {
        let watcher = watcher()
        watcher.update(enabled: true, roots: ["/a"])
        await advance(watcher, to: 10)
        XCTAssertEqual(passes, 1)

        // Enable a second source: the stream restarts and the enable and restart merge.
        watcher.update(enabled: true, roots: ["/a", "/b"])
        watcher.refresh()
        await advance(watcher, to: 20)
        XCTAssertEqual(passes, 2, "enable + restart + Refresh at once: one pass")
        XCTAssertEqual(streams.count, 2)
        XCTAssertTrue(streams[0].stopped, "the old stream stopped")

        watcher.refresh()
        await advance(watcher, to: 30)
        XCTAssertEqual(passes, 3, "Refresh: one pass")

        // Dropped events and a changed root restart the stream: one pass for the whole batch.
        let flags = FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs)
        streams[1].handler([
            WatcherEvent(path: "/a", flags: flags),
            WatcherEvent(path: "/b", flags: FSEventStreamEventFlags(kFSEventStreamEventFlagRootChanged)),
            WatcherEvent(path: "/b/x", flags: 0),
        ])
        await advance(watcher, to: 40)
        XCTAssertEqual(passes, 4, "restart: one pass")
        XCTAssertEqual(streams.count, 3, "one bounded restart")
        XCTAssertEqual(watcher.streamStarts, 3)

        // Pass 4 started at 30. Simultaneous triggers at 32 merge into one pass, which waits
        // for the 5 s spacing.
        await advance(watcher, to: 32)
        watcher.refresh()
        streams[2].handler([WatcherEvent(path: "/a/y", flags: 0)])
        watcher.refresh()
        await advance(watcher, to: 34.9)
        XCTAssertEqual(passes, 4, "spacing: no pass before 5 s after the last start")
        await advance(watcher, to: 35)
        XCTAssertEqual(passes, 5, "three triggers, one pass")
        await advance(watcher, to: 100)
        XCTAssertEqual(passes, 5)
    }

    func testEventDuringInFlightPassQueuesOneFollowUp() async {
        holdPasses = true
        let watcher = watcher()
        watcher.update(enabled: true, roots: ["/a"])
        await clock.advance(to: 0) {}
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(passes, 1)
        XCTAssertTrue(watcher.passInFlight)
        for index in 0..<5 {
            streams[0].handler([WatcherEvent(path: "/a/\(index)", flags: 0)])
            watcher.refresh()
        }
        // Finish the pass at t = 1: the follow-up waits for the 5 s spacing.
        gate?.resume()
        gate = nil
        holdPasses = false
        await settle(watcher)
        await advance(watcher, to: 4.9)
        XCTAssertEqual(passes, 1)
        await advance(watcher, to: 5)
        XCTAssertEqual(passes, 2, "ten triggers during a pass: exactly one follow-up")
        await advance(watcher, to: 200)
        XCTAssertEqual(passes, 2, "no further pass")
    }

    func testNoEnabledSourceIssuesZeroPasses() async {
        let watcher = watcher()
        watcher.update(enabled: false, roots: ["/a"])
        watcher.refresh()
        await advance(watcher, to: 3_600)
        XCTAssertEqual(passes, 0)
        XCTAssertEqual(streams.count, 0, "no stream")
        XCTAssertFalse(watcher.timerActive, "no timer")
        XCTAssertEqual(clock.liveTimers, 0)

        // Enabling then disabling stops everything again.
        watcher.update(enabled: true, roots: ["/a"])
        await advance(watcher, to: 3_601)
        XCTAssertEqual(passes, 1)
        watcher.update(enabled: false, roots: [])
        XCTAssertTrue(streams[0].stopped)
        XCTAssertFalse(watcher.timerActive)
        await advance(watcher, to: 7_200)
        XCTAssertEqual(passes, 1)
    }

    func testDataDirectoryWritesNeverTrigger() async {
        let watcher = watcher(dataDirectory: "/base/data")
        watcher.update(enabled: true, roots: ["/base/source"])
        await advance(watcher, to: 10)
        XCTAssertEqual(passes, 1)
        streams[0].handler([
            WatcherEvent(path: "/base/data", flags: 0),
            WatcherEvent(path: "/base/data/history.sqlite-wal", flags: FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs)),
            WatcherEvent(path: "/base/data/", flags: 0),
        ])
        await advance(watcher, to: 100)
        XCTAssertEqual(passes, 1, "data-directory writes never trigger")
        XCTAssertEqual(streams.count, 1, "nor restart the stream")
        // Control: a sibling whose name only starts like the data directory does trigger.
        streams[0].handler([WatcherEvent(path: "/base/data-other/x", flags: 0)])
        await advance(watcher, to: 110)
        XCTAssertEqual(passes, 2)
    }

    /// An unchanged enabled OpenCode JSON-layout source idle for 11 minutes under the injected
    /// clocks: the launch pass and exactly two 300 s periodic passes through the real engine,
    /// last good at 10 minutes and still current at 11.
    func testIdleElevenMinutesIssuesTwoPeriodicPassesOnly() async throws {
        let base = try Support.canonicalTemporaryDirectory()
        defer { Support.remove(base) }
        let root = base.appendingPathComponent("opencode").path
        let home = base.appendingPathComponent("home").path
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let journey = Support.root.appendingPathComponent("Fixtures/journey-home/.local/share/opencode").path
        try FileManager.default.copyItem(atPath: journey, toPath: root)
        let start: Int64 = 1_790_769_600_000
        let client = EngineClient()
        try await client.open(EngineConfig(dataDir: base.path + "/data", home: home))
        _ = try await client.setSourceSelection(SourceSelection(harness: "opencode", root: root, selected: true))
        let clock = self.clock!
        let wallNow = { start + Int64(clock.now * 1_000) }
        let model = TodayModel(client: client, zone: "Europe/Riga", nowMs: { wallNow() })
        let watcher = watcher(pass: { [unowned self] in
            passes += 1
            await model.reconcile()
        })
        watcher.update(enabled: true, roots: [root])
        await advance(watcher, to: 660)
        XCTAssertEqual(passes, 3, "launch + two periodic passes")
        XCTAssertEqual(clock.scheduled.filter { $0.delay == 300 }.map(\.leeway), [30, 30, 30], "300 s ticks with 30 s leeway")
        await model.refresh()
        let total = try XCTUnwrap(model.snapshot?.sourceReported.first?.total)
        XCTAssertEqual(total.lastGoodMs, start + 600_000, "last good at 10 minutes")
        XCTAssertEqual(total.status, .current)
        XCTAssertEqual(total.value, 42)
        XCTAssertEqual(model.snapshot?.bySource.first?.lastAttemptMs, start + 600_000)
        watcher.update(enabled: false, roots: [])
        await client.close()
    }

    /// A change made while the app was closed is counted by the next launch pass alone: the
    /// stream delivers no event and the real engine reads the new record.
    func testClosedAppChangeIsCountedByLaunchPass() async throws {
        let base = try Support.canonicalTemporaryDirectory()
        defer { Support.remove(base) }
        let root = base.appendingPathComponent("opencode").path
        let home = base.appendingPathComponent("home").path
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let journey = Support.root.appendingPathComponent("Fixtures/journey-home/.local/share/opencode").path
        try FileManager.default.copyItem(atPath: journey, toPath: root)
        let start: Int64 = 1_790_769_600_000
        let config = EngineConfig(dataDir: base.path + "/data", home: home)

        func session(_ launchMs: Int64) async throws -> Observation? {
            let client = EngineClient()
            try await client.open(config)
            _ = try await client.setSourceSelection(SourceSelection(harness: "opencode", root: root, selected: true))
            let model = TodayModel(client: client, zone: "Europe/Riga", nowMs: { launchMs })
            let watcher = watcher(pass: { await model.reconcile() })
            watcher.update(enabled: true, roots: [root])
            await advance(watcher, to: clock.now + 1)
            XCTAssertEqual(watcher.passCount, 1, "the launch pass")
            watcher.update(enabled: false, roots: [])
            await client.close()
            return model.snapshot?.sourceReported.first?.total
        }

        let first = try await session(start)
        XCTAssertEqual(first?.value, 42)
        // While closed: one more message with one step-finish part (input 1, output 2).
        let message = root + "/storage/message/ses_journey/msg_later.json"
        try Data(#"{"id":"msg_later","sessionID":"ses_journey","role":"assistant","time":{"created":1790758860000}}"#.utf8)
            .write(to: URL(fileURLWithPath: message))
        try FileManager.default.createDirectory(atPath: root + "/storage/part/msg_later", withIntermediateDirectories: true)
        try Data(#"{"id":"prt_later","sessionID":"ses_journey","messageID":"msg_later","type":"step-finish","tokens":{"input":1,"output":2,"reasoning":0,"cache":{"read":0,"write":0}}}"#.utf8)
            .write(to: URL(fileURLWithPath: root + "/storage/part/msg_later/prt_later.json"))
        let second = try await session(start + 3_600_000)
        XCTAssertEqual(second?.value, 45, "42 + 1 + 2, counted on launch")
        XCTAssertEqual(second?.status, .current)
        XCTAssertEqual(second?.lastGoodMs, start + 3_600_000)
    }

    func testIdleElevenMinutesUnchangedJsonlReadsNoContent() async throws {
        XCTAssertNotEqual(geteuid(), 0, "0000 must actually refuse content reads")
        let world = try CodexWorld()
        let client = EngineClient()
        let start: Int64 = 1_790_769_600_000
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection)
        let clock = self.clock!
        let model = TodayModel(client: client, zone: "Europe/Riga", nowMs: { start + Int64(clock.now * 1_000) })
        let watcher = watcher(pass: { [unowned self] in
            passes += 1
            await model.reconcile()
        })
        watcher.update(enabled: true, roots: [world.source])
        await advance(watcher, to: 0)
        XCTAssertEqual(passes, 1)
        XCTAssertEqual(model.snapshot?.sourceReported.first?.total.value, 10)
        let auth = world.source + "/auth.json"
        let paths = [world.rollout.path, auth]
        var before: [stat] = []
        for path in paths {
            var metadata = stat()
            XCTAssertEqual(lstat(path, &metadata), 0)
            before.append(metadata)
            XCTAssertEqual(chmod(path, 0o000), 0)
        }
        for tick in [300.0, 600.0] {
            await advance(watcher, to: tick)
            let entry = try XCTUnwrap(model.snapshot?.bySource.first)
            XCTAssertEqual(entry.outcome, "consistent", "unreadable unchanged content is never reopened")
            XCTAssertNil(entry.lastErrorCode)
            XCTAssertEqual(entry.lastSuccessMs, start + Int64(tick * 1_000))
            XCTAssertEqual(model.snapshot?.sourceReported.first?.total.value, 10)
        }
        await advance(watcher, to: 660)
        XCTAssertEqual(passes, 3, "launch plus exactly two 300 s periodic passes")
        XCTAssertEqual(clock.scheduled.filter { $0.delay == 300 }.map(\.leeway), [30, 30, 30])
        let total = try XCTUnwrap(model.snapshot?.sourceReported.first?.total)
        XCTAssertEqual(total.lastGoodMs, start + 600_000)
        XCTAssertEqual(total.status, .current)
        for (path, original) in zip(paths, before) {
            var metadata = stat()
            XCTAssertEqual(lstat(path, &metadata), 0)
            XCTAssertEqual(metadata.st_ino, original.st_ino)
            XCTAssertEqual(metadata.st_size, original.st_size)
            XCTAssertEqual(metadata.st_mtimespec.tv_sec, original.st_mtimespec.tv_sec)
            XCTAssertEqual(metadata.st_mtimespec.tv_nsec, original.st_mtimespec.tv_nsec)
            XCTAssertEqual(metadata.st_mode & 0o777, 0)
        }
        watcher.update(enabled: false, roots: [])
        await client.close()
    }

    func testClosedAppCurrentPathAppendCountedAtLaunchWithoutFSEvent() async throws {
        try await codexClosedAppChange(correctPrefix: false)
    }

    func testClosedAppPrefixCorrectionAndAppendReconciledAtLaunch() async throws {
        try await codexClosedAppChange(correctPrefix: true)
    }

    private func codexClosedAppChange(correctPrefix: Bool) async throws {
        let world = try CodexWorld()
        let start: Int64 = 1_790_769_600_000
        func launch(_ now: Int64) async throws -> SourceReported {
            let client = EngineClient()
            try await client.open(world.config)
            if now == start { _ = try await client.setSourceSelection(world.selection) }
            let model = TodayModel(client: client, zone: "Europe/Riga", nowMs: { now })
            let watcher = watcher(pass: { await model.reconcile() })
            watcher.update(enabled: true, roots: [world.source])
            await advance(watcher, to: clock.now + 1)
            XCTAssertEqual(watcher.passCount, 1, "one launch pass with no delivered FSEvent")
            XCTAssertNil(model.snapshot?.bySource.first?.lastErrorCode)
            watcher.update(enabled: false, roots: [])
            await client.close()
            return try XCTUnwrap(model.snapshot?.sourceReported.first)
        }
        let first = try await launch(start)
        XCTAssertEqual(first.total.value, 10)
        let text = try String(contentsOf: world.rollout, encoding: .utf8)
        var record = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(try XCTUnwrap(text.split(separator: "\n").last).utf8)) as? [String: Any])
        var payload = try XCTUnwrap(record["payload"] as? [String: Any])
        payload["response_id"] = "resp_later"
        payload["usage"] = ["input_tokens": 3, "total_tokens": 3]
        record["payload"] = payload
        var append = try JSONSerialization.data(withJSONObject: record)
        append.append(0x0A)
        let attributes = try FileManager.default.attributesOfItem(atPath: world.rollout.path)
        let file = try FileHandle(forUpdating: world.rollout)
        if correctPrefix {
            let corrected = text.replacingOccurrences(of: "\"input_tokens\":10", with: "\"input_tokens\":20")
                .replacingOccurrences(of: "\"total_tokens\":10", with: "\"total_tokens\":20")
            XCTAssertNotEqual(corrected, text)
            try file.write(contentsOf: Data(corrected.utf8))
        }
        try file.seekToEnd()
        try file.write(contentsOf: append)
        try file.close()
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: world.rollout.path)[.systemFileNumber] as? NSNumber,
                       attributes[.systemFileNumber] as? NSNumber, "same inode across correction and append")
        let second = try await launch(start + 3_600_000)
        XCTAssertEqual(second.input.value, correctPrefix ? 23 : 13)
        XCTAssertEqual(second.total.value, correctPrefix ? 23 : 13)
        XCTAssertEqual(second.records, 2)
        XCTAssertEqual(second.total.provenance, .reported)
        XCTAssertEqual(second.originUncertainty, "unverified_origin")
        XCTAssertNil(second.output.value)
        XCTAssertNil(second.output.provenance)
        XCTAssertEqual(second.total.status, .current)
        XCTAssertEqual(second.total.lastGoodMs, start + 3_600_000)
        let replay = try await launch(start + 7_200_000)
        XCTAssertEqual(Support.acquired(replay), Support.acquired(second), "next launch adds zero")
    }

    /// SAME decoded `error-engine-failed.json` in TodayModel's result entry: last good stays,
    /// Retry reopens once (the failed request is never re-sent on the old handle) and the next
    /// snapshot equals the last-good totals.
    func testEngineFailedRetryClosesAndReopens() async throws {
        let world = try World(rows: Support.dailyRows())
        let now = try Support.nowMs("utc_counters")
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        let model = TodayModel(client: client, zone: "UTC", nowMs: { now })
        await model.reconcile()
        let lastGood = try XCTUnwrap(model.snapshot)
        let engineFailed: BridgeError
        let golden = Array(try Support.data("Contracts/bridge-v1/error-engine-failed.json"))
        do throws(BridgeError) {
            _ = try Envelope.decode(golden, as: TodaySnapshot.self)
            return XCTFail("the golden is an error")
        } catch {
            engineFailed = error
        }
        XCTAssertEqual(engineFailed, BridgeError(code: "engine_failed", message: "engine failed", retryable: false))
        model.receiveLatest(.failure(engineFailed))
        XCTAssertEqual(model.snapshot, lastGood, "last good retained")
        XCTAssertEqual(model.error, engineFailed)
        XCTAssertTrue(model.awaitingRetry)
        XCTAssertEqual(statusWords(model), Array(repeating: "Error", count: 6), "last good shown as error, never current")

        // No automatic call reaches the failed handle.
        let idle = FFICounters.shared.current
        await model.reconcile()
        await model.refresh()
        XCTAssertEqual(FFICounters.shared.current.calls, idle.calls, "no automatic call")

        let before = FFICounters.shared.current
        await model.retry()
        let after = FFICounters.shared.current
        XCTAssertEqual(after.openCalls - before.openCalls, 1, "Retry: one reopen")
        XCTAssertEqual(after.handlesClosed - before.handlesClosed, 1, "the old handle closed")
        XCTAssertEqual(after.handlesOpened - before.handlesOpened, 1, "a new handle opened")
        XCTAssertEqual(after.calls - before.calls, 1, "only the new snapshot call, on the new handle")
        XCTAssertNil(model.error)
        XCTAssertEqual(model.snapshot?.sourceReported, lastGood.sourceReported, "next snapshot equals last-good totals")
        XCTAssertEqual(statusWords(model), Array(repeating: "Current", count: 6), "recovered: Rust's status again")
        await client.close()
    }

    /// A client `malformed_response` in the same entry: last good kept, the error shown, no data
    /// substituted, no automatic call; the user's Retry reopens once.
    func testMalformedResponseKeepsLastGoodUntilRetry() async throws {
        let world = try World(rows: Support.dailyRows())
        let now = try Support.nowMs("utc_counters")
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        let model = TodayModel(client: client, zone: "UTC", nowMs: { now })
        await model.reconcile()
        let lastGood = try XCTUnwrap(model.snapshot)
        model.receiveLatest(.failure(.malformedResponse))
        XCTAssertEqual(model.snapshot, lastGood)
        XCTAssertEqual(model.error, .malformedResponse)
        XCTAssertEqual(statusWords(model), Array(repeating: "Error", count: 6), "last good shown as error, never current")
        let idle = FFICounters.shared.current
        await model.reconcile()
        XCTAssertEqual(FFICounters.shared.current.calls, idle.calls, "no automatic call")
        XCTAssertEqual(FFICounters.shared.current.openCalls, idle.openCalls)
        await model.retry()
        let after = FFICounters.shared.current
        XCTAssertEqual(after.openCalls - idle.openCalls, 1, "Retry: one reopen")
        XCTAssertEqual(model.snapshot?.sourceReported, lastGood.sourceReported)
        XCTAssertEqual(statusWords(model), Array(repeating: "Current", count: 6), "recovered: Rust's status again")
        await client.close()
    }

    /// A launch open refused because another owner holds the data directory: nothing calls the
    /// closed engine, Retry reopens with the attempted config, a failed reopen keeps its own error
    /// (never a NULL-engine `invalid_request`) and reports failure, and a successful one reports
    /// success and reads the snapshot on the new handle.
    func testLaunchOpenFailureIsRetriedWithItsConfig() async throws {
        let world = try World(rows: Support.dailyRows())
        let now = try Support.nowMs("utc_counters")
        let owner = EngineClient()
        try await owner.open(world.config)
        _ = try await owner.setSourceSelection(world.selection())
        _ = try await owner.ingest(nowMs: now)

        let client = EngineClient()
        let model = TodayModel(client: client, zone: "UTC", nowMs: { now })
        let opened = await model.open(world.config)
        XCTAssertFalse(opened)
        XCTAssertEqual(model.error?.code, "store_busy")
        XCTAssertTrue(model.awaitingRetry, "only Retry may open the engine")

        let idle = FFICounters.shared.current
        await model.reconcile()
        await model.refresh()
        XCTAssertEqual(FFICounters.shared.current.calls, idle.calls, "no call reaches the closed engine")

        // The owner still holds the directory: the reopen fails with its own error.
        let failedRetry = await model.retry()
        XCTAssertFalse(failedRetry)
        XCTAssertEqual(model.error?.code, "store_busy", "the reopen error stays")
        XCTAssertTrue(model.awaitingRetry)
        XCTAssertEqual(FFICounters.shared.current.calls, idle.calls, "nothing sent to a NULL engine")
        XCTAssertEqual(FFICounters.shared.current.openCalls - idle.openCalls, 1, "one reopen attempt")

        await owner.close()
        let before = FFICounters.shared.current
        let retried = await model.retry()
        let after = FFICounters.shared.current
        XCTAssertTrue(retried)
        XCTAssertEqual(after.openCalls - before.openCalls, 1, "one reopen with the attempted config")
        XCTAssertEqual(after.calls - before.calls, 1, "then one snapshot call")
        XCTAssertNil(model.error)
        XCTAssertFalse(model.awaitingRetry)
        XCTAssertEqual(model.snapshot?.sourceReported.first?.total.value, 141, "the owner's history, read on the new handle")
        await client.close()
    }

    /// An ingest that fails with an ordinary error still reads today's snapshot, so Rust re-judges
    /// freshness at the present instant: the rows leave Current, keep their last good values and
    /// show their absolute last good time; the error stays shown.
    func testIngestFailureStillReadsSnapshot() async throws {
        let world = try World(rows: Support.dailyRows())
        let start = try Support.nowMs("utc_counters")
        let clock = self.clock!
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        let model = TodayModel(client: client, zone: "UTC", nowMs: { start + Int64(clock.now * 1_000) })
        await model.reconcile()
        let lastGood = try XCTUnwrap(model.snapshot?.sourceReported.first)
        XCTAssertEqual(lastGood.total.status, .current)

        // The pass's task is cancelled before it runs: ingest (the only method that reads the
        // token) answers `cancelled`; today_snapshot still answers.
        await clock.advance(to: 11 * 60) {}
        let before = FFICounters.shared.current
        let pass = Task { await model.reconcile() }
        pass.cancel()
        await pass.value
        let after = FFICounters.shared.current
        XCTAssertEqual(model.error?.code, "cancelled", "the failed pass is shown")
        XCTAssertEqual(after.calls - before.calls, 2, "ingest, then today_snapshot")
        let total = try XCTUnwrap(model.snapshot?.sourceReported.first?.total)
        XCTAssertEqual(total.value, lastGood.total.value, "last good value kept")
        XCTAssertEqual(total.lastGoodMs, start, "last good instant kept")
        XCTAssertNotEqual(total.status, .current, "Rust re-judged at the present instant")
        let rendered = Render.render(model, dark: false)
        rendered.window.orderOut(nil)
        let row = try XCTUnwrap(rendered.rows.first { $0.label.hasPrefix("Total, ") }?.value)
        // utc_counters: last good 2026-04-02T10:00Z, now 10:11Z.
        XCTAssertEqual(row, "141 tokens, Derived, Partial, Error, Updated at 10:00\u{202F}AM", "age never freezes")
        await client.close()
    }

    /// Rust backs a refused source off for at most 300,000 ms (`RETRY_MAX_MS`, limits.rs) and
    /// does no source I/O before the deadline. The watcher never asks sooner than its periodic
    /// tick: a pass that finds the source backing off queues nothing, and every later pass starts
    /// at or after the deadline the previous one could have set.
    func testPeriodicTickWaitsOutRustBackoff() async {
        let longestBackoff: TimeInterval = 300
        var starts: [TimeInterval] = []
        let watcher = watcher(pass: { [unowned self] in
            starts.append(clock.now)
        })
        watcher.update(enabled: true, roots: ["/a"])
        await advance(watcher, to: 1_000)
        XCTAssertEqual(starts, [0, 300, 600, 900], "the launch pass, then only the 300 s ticks")
        for (previous, next) in zip(starts, starts.dropFirst()) {
            XCTAssertGreaterThanOrEqual(next, previous + longestBackoff, "a pass never lands inside the longest backoff")
        }
    }

    /// The status word of each rendered observation row, in row order, as accessibility reads it.
    private func statusWords(_ model: TodayModel) -> [String] {
        let rendered = Render.render(model, dark: false)
        rendered.window.orderOut(nil)
        return Render.rowLabels.compactMap { label in
            rendered.rows.first { $0.label.hasPrefix("\(label), ") }?.value.components(separatedBy: ", ").dropLast().last
        }
    }
}

