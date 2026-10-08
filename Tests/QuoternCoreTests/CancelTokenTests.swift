import Foundation
import XCTest
@testable import QuoternCore

final class CancelTokenTests: XCTestCase {
    func testTokenNewEqualsFreeUnderConcurrentTriggers() {
        let before = FFICounters.shared.current
        for _ in 0..<50 {
            let token = FFICancelToken()
            DispatchQueue.concurrentPerform(iterations: 16) { _ in token.trigger() }
            withExtendedLifetime(token) {}
        }
        let after = FFICounters.shared.current
        XCTAssertEqual(after.tokensNew - before.tokensNew, 50)
        XCTAssertEqual(after.tokensFree - before.tokensFree, 50, "cancel new == free")
    }

    func testTriggerFromAnotherThreadWhileCallRuns() async throws {
        let world = try World(rows: Support.dailyRows())
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        let now = try Support.nowMs("utc_counters")
        let before = FFICounters.shared.current

        let task = Task { () -> Result<[SourceEntry], BridgeError> in
            while !Task.isCancelled { await Task.yield() }
            do {
                return .success(try await client.ingest(nowMs: now))
            } catch let error as BridgeError {
                return .failure(error)
            } catch {
                return .failure(.malformedResponse)
            }
        }
        DispatchQueue.global().async { task.cancel() }
        guard case .failure(let error) = await task.value else {
            return XCTFail("a call started under a triggered token is cancelled")
        }
        XCTAssertEqual(error, BridgeError(code: "cancelled", message: "cancelled", retryable: true))
        let after = FFICounters.shared.current
        XCTAssertEqual(after.tokensNew - before.tokensNew, after.tokensFree - before.tokensFree)

        // The next ingest converges to the independent oracle and replay adds nothing.
        _ = try await client.ingest(nowMs: now)
        let snapshot = try await client.todaySnapshot(tz: "UTC", nowMs: now)
        let id = try XCTUnwrap(snapshot.sourceReported.first?.sourceId)
        XCTAssertEqual(snapshot.sourceReported, [try Support.reported("utc_counters", sourceId: id)])
        _ = try await client.ingest(nowMs: now + 1)
        let replay = try await client.todaySnapshot(tz: "UTC", nowMs: now)
        XCTAssertEqual(replay.sourceReported.map(Support.acquired), snapshot.sourceReported.map(Support.acquired))
        // Judged at `now`, before the replay's success at `now + 1`: never current.
        XCTAssertEqual(lifecycle(replay.sourceReported.first), Array(repeating: "stale \(now + 1)", count: 6))
        await client.close()
    }

    /// A cancel triggered while a long pass runs publishes only whole groups, returns
    /// `cancelled`, and the next passes converge. Credit needs the receipt: `cancelled` with
    /// 0 < records < rows and input == records (every row is its own single-row group).
    func testCancelRacingALongPassCommitsWholeGroupsAndConverges() async throws {
        let base: Int64 = 1_775_124_000_000
        let rows = Support.bulkRows(5_100, base: base)
        let total = UInt64(rows.count)
        let cancelled = BridgeError(code: "cancelled", message: "cancelled", retryable: true)
        let before = FFICounters.shared.current
        var receipts = 0
        var outcomes: [String] = []
        for attempt in 0..<20 where receipts == 0 {
            let world = try World(rows: rows)
            let client = EngineClient()
            try await client.open(world.config)
            _ = try await client.setSourceSelection(world.selection())
            let calls = FFICounters.shared.current.calls
            let task = Task { () -> BridgeError? in
                do throws(BridgeError) {
                    _ = try await client.ingest(nowMs: base)
                    return nil
                } catch {
                    return error
                }
            }
            // Trigger only once the counters show the ingest call entered the bridge.
            while FFICounters.shared.current.calls == calls { await Task.yield() }
            try await Task.sleep(nanoseconds: UInt64(attempt) * 250_000)
            task.cancel()
            let outcome = await task.value
            let partial = try await client.todaySnapshot(tz: "UTC", nowMs: base)
            let records = try XCTUnwrap(partial.sourceReported.first).records
            outcomes.append("\(outcome?.code ?? "ok") \(records)")
            if outcome == cancelled, records > 0, records < total {
                receipts += 1
                XCTAssertEqual(partial.sourceReported.first?.input.value, records, "only whole groups published")
                // Converge: later passes publish every row exactly once; replay adds zero.
                var converged = partial
                for pass in 1...5 where converged.sourceReported.first?.records != total {
                    _ = try await client.ingest(nowMs: base + Int64(pass))
                    converged = try await client.todaySnapshot(tz: "UTC", nowMs: base)
                }
                XCTAssertEqual(converged.sourceReported.first?.records, total)
                XCTAssertEqual(converged.sourceReported.first?.input.value, total)
                _ = try await client.ingest(nowMs: base + 100)
                let replay = try await client.todaySnapshot(tz: "UTC", nowMs: base)
                XCTAssertEqual(replay.sourceReported.map(Support.acquired), converged.sourceReported.map(Support.acquired), "replay adds zero")
                // Re-proving 5,100 rows exceeds the 5,000-row pass budget, so the replay pass
                // leaves the source catching up; its success at `base + 100` is the last good.
                XCTAssertEqual(lifecycle(replay.sourceReported.first), Array(repeating: "catchingUp \(base + 100)", count: 6))
            }
            await client.close()
        }
        XCTAssertEqual(receipts, 1, "no attempt of 20 fresh worlds gave a mid-pass cancelled receipt: \(outcomes)")
        let after = FFICounters.shared.current
        XCTAssertEqual(after.tokensNew - before.tokensNew, after.tokensFree - before.tokensFree, "cancel new == free")
    }

    /// Rust's lifecycle of every observation: status and last-good instant.
    private func lifecycle(_ reported: SourceReported?) -> [String] {
        guard let reported else { return [] }
        return [reported.input, reported.output, reported.reasoning, reported.cacheRead, reported.cacheWrite, reported.total]
            .map { "\($0.status) \($0.lastGoodMs.map(String.init) ?? "null")" }
    }
}
