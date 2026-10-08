import CQuotern
import Foundation
import XCTest
@testable import QuoternCore

final class BridgeContractV1Tests: XCTestCase {
    private func golden(_ name: String) throws -> Data {
        try Support.data("Contracts/bridge-v1/\(name)")
    }

    private func decodeGolden<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        try Envelope.decode(Array(golden(name)), as: type)
    }

    // MARK: Header

    /// The Swift import of the SAME `quotern.h`: each of the eight exports bound to its expected
    /// C function type, so a width, arity or `char *` constness change in the header fails to
    /// compile here. Swift imports every pointer to the incomplete `QuoternEngine` and
    /// `QuoternCancel` as `OpaquePointer`, so their constness is asserted only by the C-side
    /// prototype assertions of `crates/quotern-ffi/tests/support/abi_signature.c`.
    func testImportedHeaderSignatures() {
        let abiVersion: @convention(c) () -> UInt32 = quotern_abi_version
        let open: @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<OpaquePointer?>?)
            -> UnsafeMutablePointer<CChar>? = quotern_engine_open
        let close: @convention(c) (OpaquePointer?) -> Void = quotern_engine_close
        let call: @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, UnsafePointer<CChar>?, OpaquePointer?)
            -> UnsafeMutablePointer<CChar>? = quotern_call
        let cancelNew: @convention(c) () -> OpaquePointer? = quotern_cancel_new
        let cancelTrigger: @convention(c) (OpaquePointer?) -> Void = quotern_cancel_trigger
        let cancelFree: @convention(c) (OpaquePointer?) -> Void = quotern_cancel_free
        let stringFree: @convention(c) (UnsafeMutablePointer<CChar>?) -> Void = quotern_string_free
        XCTAssertEqual(abiVersion(), 1)
        // Every NULL argument the header documents as a no-op, through the typed bindings.
        close(nil)
        cancelTrigger(nil)
        cancelFree(nil)
        stringFree(nil)
        let token = cancelNew()
        XCTAssertNotNil(token)
        cancelFree(token)
        _ = (open, call)
    }

    // MARK: Requests

    func testFirstUseRequestsEncodeSharedGoldens() throws {
        let file = try XCTUnwrap(JSONSerialization.jsonObject(with: golden("requests-first-use.json")) as? [String: Any])
        func parsed(_ text: String) throws -> NSDictionary {
            try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? NSDictionary)
        }
        let encoded: [String: String] = [
            "open": EngineClient.encode(EngineConfig(dataDir: "/quotern-golden/data", home: "/quotern-golden/home")),
            "set_source_selection": EngineClient.encode(
                SourceSelection(harness: "opencode", root: "/quotern-golden/opencode", selected: true)),
            "list_sources": "{}",
            "ingest": EngineClient.encode(IngestRequest(nowMs: 1_775_124_000_000)),
            "today_snapshot": EngineClient.encode(TodayRequest(tz: "UTC", nowMs: 1_775_124_000_000)),
        ]
        XCTAssertEqual(Set(file.keys), Set(encoded.keys), "every first-use method is in the golden")
        for (method, text) in encoded {
            XCTAssertEqual(try parsed(text), file[method] as? NSDictionary, method)
        }
    }

    // MARK: Responses

    func testSharedSnapshotGoldensDecode() throws {
        let empty = try decodeGolden("snapshot-empty.json", as: TodaySnapshot.self)
        XCTAssertTrue(empty.bySource.isEmpty)
        XCTAssertTrue(empty.sourceReported.isEmpty)
        XCTAssertEqual(empty.window.tz, "UTC")

        let catching = try decodeGolden("snapshot-catching-up.json", as: TodaySnapshot.self)
        XCTAssertEqual(catching.bySource.first?.outcome, "catching_up")
        XCTAssertEqual(catching.sourceReported.first?.records, 4_968)

        let pending = try decodeGolden("snapshot-pending-partial.json", as: TodaySnapshot.self)
        XCTAssertEqual(pending.sourceReported.first?.pendingPartial, true)

        let open = try decodeGolden("open-ok.json", as: OpenData.self)
        XCTAssertEqual(open.abiVersion, 1)
        let list = try decodeGolden("sources-list.json", as: SourceList.self)
        XCTAssertEqual(list.sources.count, 1)

        let reported = try decodeGolden("snapshot-opencode-reported.json", as: TodaySnapshot.self)
        let first = try XCTUnwrap(reported.sourceReported.first)
        XCTAssertEqual(reported.sourceReported, [try Support.reported("utc_counters", sourceId: first.sourceId)])

        let errors: [String: BridgeError] = [
            "error-invalid-request.json": BridgeError(code: "invalid_request", message: "invalid request: request", retryable: false),
            "error-limit-exceeded.json": BridgeError(code: "limit_exceeded", message: "limit exceeded: request_bytes", retryable: false),
            "error-cancelled.json": BridgeError(code: "cancelled", message: "cancelled", retryable: true),
            "error-internal-panic.json": BridgeError(code: "internal_panic", message: "internal panic", retryable: false),
            "error-engine-failed.json": BridgeError(code: "engine_failed", message: "engine failed", retryable: false),
        ]
        for (name, expected) in errors {
            let bytes = Array(try golden(name))
            do {
                _ = try Envelope.decode(bytes, as: SourceList.self)
                XCTFail("\(name) must throw")
            } catch {
                XCTAssertEqual(error, expected, name)
            }
        }

        // Every Observation-bearing golden carries the full shape: value, unit, provenance and
        // completeness as acquired, Rust's lifecycle status and last good instant.
        XCTAssertEqual(catching.sourceReported.first?.input.status, .catchingUp)
        XCTAssertEqual(pending.sourceReported.first?.total.status, .error, "a failure after the success")
        XCTAssertEqual(pending.sourceReported.first?.total.completeness, .partial)
        XCTAssertEqual(reported.sourceReported.first?.total.provenance, .derived)
        XCTAssertEqual(reported.sourceReported.first?.input.completeness, .complete)

        // The lifecycle states golden: each entry's response decodes (ObservationStateTests
        // renders and checks them).
        let states = try XCTUnwrap(Support.json("Contracts/bridge-v1/snapshot-states.json") as? [String: Any])
        let entries = try XCTUnwrap(states["states"] as? [[String: Any]])
        XCTAssertEqual(entries.count, 16)
        for entry in entries {
            let response = try JSONSerialization.data(withJSONObject: XCTUnwrap(entry["response"]))
            XCTAssertEqual(try Envelope.decode(Array(response), as: TodaySnapshot.self).sourceReported.count, 1)
        }

        // Inventory: every response golden in the contract directory is decoded above.
        let decoded = Set([
            "snapshot-empty.json", "snapshot-catching-up.json", "snapshot-pending-partial.json",
            "snapshot-opencode-reported.json", "open-ok.json", "sources-list.json", "snapshot-states.json",
        ]).union(errors.keys)
        let directory = Support.root.appendingPathComponent("Contracts/bridge-v1").path
        let responses = try FileManager.default.contentsOfDirectory(atPath: directory)
            .filter { $0.hasSuffix(".json") && !$0.hasPrefix("requests-") }
        XCTAssertEqual(Set(responses), decoded)
    }

    func testLiveSnapshotEqualsSharedGolden() async throws {
        let world = try World(rows: Support.dailyRows())
        let now = try Support.nowMs("utc_counters")
        let client = EngineClient()
        try await client.open(world.config)
        _ = try await client.setSourceSelection(world.selection())
        _ = try await client.ingest(nowMs: now)
        let live = try await client.todaySnapshot(tz: "UTC", nowMs: now)
        await client.close()
        let shared = try decodeGolden("snapshot-opencode-reported.json", as: TodaySnapshot.self)
        XCTAssertEqual(live.window, shared.window)
        let liveReported = try XCTUnwrap(live.sourceReported.first)
        let sharedReported = try XCTUnwrap(shared.sourceReported.first)
        XCTAssertEqual(liveReported, try Support.reported("utc_counters", sourceId: liveReported.sourceId))
        XCTAssertEqual(try Support.reported("utc_counters", sourceId: sharedReported.sourceId), sharedReported)
    }

    func testDecodedEngineFailedRequiresReopen() throws {
        let reopen: [(String, BridgeError)] = [
            ("error-engine-failed.json", BridgeError(code: "engine_failed", message: "engine failed", retryable: false)),
            ("error-internal-panic.json", BridgeError(code: "internal_panic", message: "internal panic", retryable: false)),
        ]
        for (name, expected) in reopen {
            let bytes = Array(try golden(name))
            do {
                _ = try Envelope.decode(bytes, as: SourceList.self)
                XCTFail("\(name) must throw")
            } catch {
                XCTAssertEqual(error, expected, name)
                XCTAssertTrue(error.requiresReopen, name)
            }
        }
        let cancelled = Array(try golden("error-cancelled.json"))
        do {
            _ = try Envelope.decode(cancelled, as: SourceList.self)
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "cancelled", message: "cancelled", retryable: true))
            XCTAssertFalse(error.requiresReopen)
        }
    }

    // MARK: Numeric widths

    private func mutatedSnapshot(_ change: (inout [String: Any]) -> Void) throws -> [UInt8] {
        var envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: golden("snapshot-catching-up.json")) as? [String: Any])
        var data = try XCTUnwrap(envelope["data"] as? [String: Any])
        change(&data)
        envelope["data"] = data
        return Array(try JSONSerialization.data(withJSONObject: envelope))
    }

    private func mutateFirst(_ data: inout [String: Any], _ list: String, _ edit: (inout [String: Any]) -> Void) {
        var rows = data[list] as? [[String: Any]] ?? []
        edit(&rows[0])
        data[list] = rows
    }

    func testNumericWidthBoundaries() throws {
        let maxSource: Int64 = 253_402_300_799_999
        let wide = try mutatedSnapshot { data in
            mutateFirst(&data, "source_reported") { row in
                row["records"] = NSNumber(value: UInt64.max)
                var input = row["input"] as? [String: Any] ?? [:]
                input["value"] = NSNumber(value: UInt64.max)
                row["input"] = input
            }
            mutateFirst(&data, "by_source") { row in
                row["rejected_count"] = NSNumber(value: UInt32.max)
                row["last_attempt_ms"] = NSNumber(value: maxSource)
                row["last_success_ms"] = NSNumber(value: maxSource)
            }
            data["window"] = ["start_ms": 0, "end_ms": NSNumber(value: maxSource), "tz": "UTC"] as [String: Any]
        }
        let snapshot = try Envelope.decode(wide, as: TodaySnapshot.self)
        XCTAssertEqual(snapshot.sourceReported.first?.records, UInt64.max)
        XCTAssertEqual(snapshot.sourceReported.first?.input.value, UInt64.max)
        XCTAssertEqual(snapshot.bySource.first?.rejectedCount, UInt32.max)
        XCTAssertEqual(snapshot.bySource.first?.lastAttemptMs, maxSource)
        XCTAssertEqual(snapshot.window.endMs, maxSource)

        let rejected: [(String, (inout [String: Any]) -> Void)] = [
            ("UInt64 -1", { data in self.mutateFirst(&data, "source_reported") { $0["records"] = NSNumber(value: -1) } }),
            ("UInt64 1.5", { data in self.mutateFirst(&data, "source_reported") { $0["records"] = NSNumber(value: 1.5) } }),
            ("UInt64 string", { data in self.mutateFirst(&data, "source_reported") { $0["records"] = "1" } }),
            ("UInt32 4294967296", { data in self.mutateFirst(&data, "by_source") { $0["rejected_count"] = NSNumber(value: Int64(4_294_967_296)) } }),
            ("UInt32 -1", { data in self.mutateFirst(&data, "by_source") { $0["rejected_count"] = NSNumber(value: -1) } }),
            ("Int64 2^63", { data in self.mutateFirst(&data, "by_source") { $0["last_success_ms"] = NSNumber(value: UInt64(1) << 63) } }),
        ]
        for (label, change) in rejected {
            let bytes = try mutatedSnapshot(change)
            do {
                _ = try Envelope.decode(bytes, as: TodaySnapshot.self)
                XCTFail("\(label) must be malformed_response")
            } catch {
                XCTAssertEqual(error, BridgeError.malformedResponse, label)
            }
        }
    }

    // MARK: Client errors

    /// Swift invents no error: without a handle a call reaches Rust's own NULL-engine refusal,
    /// and `reopen()` without an earlier open reaches Rust's NULL-config refusal.
    func testWithoutAHandleTheErrorsAreRusts() async throws {
        let client = EngineClient()
        let before = FFICounters.shared.current
        do {
            _ = try await client.listSources()
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "invalid_request", message: "invalid request: engine", retryable: false))
        }
        do {
            try await client.reopen()
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "invalid_request", message: "invalid request: config_json", retryable: false))
        }
        let after = FFICounters.shared.current
        XCTAssertEqual(after.calls - before.calls, 1, "one quotern_call")
        XCTAssertEqual(after.openCalls - before.openCalls, 1, "one quotern_engine_open")
        XCTAssertEqual(after.entries - before.entries, 2)
        XCTAssertEqual(after.frees - before.frees, 2, "each Rust string freed once")
        XCTAssertEqual(after.handlesOpened - before.handlesOpened, 0)
    }

    func testClientErrorsAbiMismatchAndMalformedResponse() async throws {
        // abi_mismatch through the version gate: open is never called.
        let before = FFICounters.shared.current
        let mismatched = EngineClient(abiVersion: { 2 })
        do {
            try await mismatched.open(EngineConfig(dataDir: "/quotern-golden/data", home: "/quotern-golden/home"))
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, BridgeError(code: "abi_mismatch", message: "incompatible engine", retryable: false))
        }
        let gated = FFICounters.shared.current
        XCTAssertEqual(gated.openCalls, before.openCalls, "open never called")
        XCTAssertEqual(gated.handlesOpened, before.handlesOpened)

        let world = try World(rows: Support.dailyRows())
        let raw = try RawEngine(config: world.config)

        // The wrong-DTO row is a genuine EngineClient call: one quotern_call, no retry.
        let client = EngineClient()
        try await client.open(world.config.withDataDir(world.base.path + "/wrong-dto"))
        let beforeCall = FFICounters.shared.current
        do {
            _ = try await client.call("list_sources", "{}", as: TodaySnapshot.self)
            XCTFail("a wrong DTO must throw")
        } catch {
            XCTAssertEqual(error, BridgeError.malformedResponse)
        }
        let afterCall = FFICounters.shared.current
        XCTAssertEqual(afterCall.calls - beforeCall.calls, 1, "exactly one quotern_call")
        XCTAssertEqual(afterCall.entries - beforeCall.entries, 1, "wrong DTO: one entry")
        XCTAssertEqual(afterCall.frees - beforeCall.frees, 1, "wrong DTO: one free")
        await client.close()

        let invalidRequest = BridgeError(code: "invalid_request", message: "invalid request: request", retryable: false)
        func realString() throws -> UnsafeMutablePointer<CChar> {
            let pointer = "list_sources".withCString { method in
                "x".withCString { quotern_call(raw.engine, method, $0, nil) }
            }
            return try XCTUnwrap(pointer)
        }
        // Control: an unmodified string decodes to its real invalid_request error.
        let untouched = try realString()
        let length = strlen(untouched)
        XCTAssertGreaterThan(length, 60)
        do {
            _ = try EngineClient.copyFreeDecode(untouched, as: SourceList.self)
            XCTFail("must throw")
        } catch {
            XCTAssertEqual(error, invalidRequest)
        }

        func text(_ value: String) -> [UInt8] { Array(value.utf8) }
        let errorTail = "\"error\":{\"code\":\"cancelled\",\"message\":\"m\",\"retryable\":true}"
        let rows: [(String, [UInt8])] = [
            ("non-UTF-8", [0xFF, 0xFE, 0xFD, 0x80]),
            ("invalid JSON", text("{\"v\":1,\"ok\":")),
            ("v=2", text("{\"v\":2,\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("v missing", text("{\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("v string", text("{\"v\":\"1\",\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("v 1.5", text("{\"v\":1.5,\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("v 1.0", text("{\"v\":1.0,\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("v 1e0", text("{\"v\":1e0,\"ok\":true,\"data\":{\"sources\":[]}}")),
            ("ok missing", text("{\"v\":1,\"data\":{\"sources\":[]}}")),
            ("ok string", text("{\"v\":1,\"ok\":\"true\",\"data\":{\"sources\":[]}}")),
            ("ok 1", text("{\"v\":1,\"ok\":1,\"data\":{\"sources\":[]}}")),
            ("ok true with error", text("{\"v\":1,\"ok\":true,\"data\":{\"sources\":[]},\(errorTail)}")),
            ("ok true without data", text("{\"v\":1,\"ok\":true}")),
            ("ok false without error", text("{\"v\":1,\"ok\":false}")),
            ("ok false with data", text("{\"v\":1,\"ok\":false,\"data\":{},\(errorTail)}")),
            ("error string", text("{\"v\":1,\"ok\":false,\"error\":\"x\"}")),
            ("error array", text("{\"v\":1,\"ok\":false,\"error\":[]}")),
            ("code missing", text("{\"v\":1,\"ok\":false,\"error\":{\"message\":\"m\",\"retryable\":false}}")),
            ("code number", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":5,\"message\":\"m\",\"retryable\":false}}")),
            ("message missing", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"cancelled\",\"retryable\":false}}")),
            ("message number", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"cancelled\",\"message\":7,\"retryable\":false}}")),
            ("retryable missing", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"cancelled\",\"message\":\"m\"}}")),
            ("retryable string", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"cancelled\",\"message\":\"m\",\"retryable\":\"false\"}}")),
            ("retryable 0", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"cancelled\",\"message\":\"m\",\"retryable\":0}}")),
            ("code outside the table", text("{\"v\":1,\"ok\":false,\"error\":{\"code\":\"no_such\",\"message\":\"m\",\"retryable\":false}}")),
        ]
        for (label, row) in rows {
            let pointer = try realString()
            let available = strlen(pointer)
            guard available >= row.count else {
                XCTFail("\(label): \(row.count) B does not fit the real \(available) B string")
                _ = try? EngineClient.copyFreeDecode(pointer, as: SourceList.self)  // the one free site
                continue
            }
            // Overwrite only bytes [0, L) in place, padding with JSON spaces; never NUL.
            var content = row
            content.append(contentsOf: [UInt8](repeating: UInt8(ascii: " "), count: Int(available) - row.count))
            XCTAssertFalse(content.contains(0))
            content.withUnsafeBytes { UnsafeMutableRawPointer(pointer).copyMemory(from: $0.baseAddress!, byteCount: Int(available)) }
            XCTAssertEqual(strlen(pointer), available, "length is untouched")
            let counters = FFICounters.shared.current
            do {
                _ = try EngineClient.copyFreeDecode(pointer, as: SourceList.self)
                XCTFail("\(label) decoded to a DTO")
            } catch {
                XCTAssertEqual(error, BridgeError.malformedResponse, label)
            }
            let after = FFICounters.shared.current
            XCTAssertEqual(after.entries - counters.entries, 1, "\(label): one entry")
            XCTAssertEqual(after.frees - counters.frees, 1, "\(label): one free")
        }

        // Control: a mutated valid envelope decodes to an empty list.
        let valid = try realString()
        let validLength = Int(strlen(valid))
        let body = text("{\"v\":1,\"ok\":true,\"data\":{\"sources\":[]}}")
        guard validLength >= body.count else {
            _ = try? EngineClient.copyFreeDecode(valid, as: SourceList.self)
            return XCTFail("the control does not fit the real \(validLength) B string")
        }
        let padded = body + [UInt8](repeating: UInt8(ascii: " "), count: validLength - body.count)
        padded.withUnsafeBytes { UnsafeMutableRawPointer(valid).copyMemory(from: $0.baseAddress!, byteCount: validLength) }
        XCTAssertEqual(try EngineClient.copyFreeDecode(valid, as: SourceList.self).sources.count, 0)
    }
}

private extension EngineConfig {
    func withDataDir(_ path: String) -> EngineConfig {
        EngineConfig(dataDir: path, home: home)
    }
}
