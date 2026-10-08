import Foundation
import XCTest
@testable import QuoternCore

/// Every entry of the SAME `snapshot-states.json` that contract_v1 matches to the provider:
/// decoded strictly, rendered in light and dark, and checked through accessibility for the unit,
/// provenance, completeness, status word and freshness of every observation.
@MainActor
final class ObservationStateTests: XCTestCase {
    private struct Entry {
        let name: String
        let nowMs: Int64
        let snapshot: TodaySnapshot
    }

    private func entries() throws -> [Entry] {
        let file = try XCTUnwrap(Support.json("Contracts/bridge-v1/snapshot-states.json") as? [String: Any])
        let states = try XCTUnwrap(file["states"] as? [[String: Any]])
        return try states.map { state in
            let request = try XCTUnwrap(state["request"] as? [String: Any])
            let response = try JSONSerialization.data(withJSONObject: XCTUnwrap(state["response"]))
            return Entry(
                name: try XCTUnwrap(state["name"] as? String),
                nowMs: try XCTUnwrap(request["now_ms"] as? Int64),
                snapshot: try Envelope.decode(Array(response), as: TodaySnapshot.self))
        }
    }

    /// One hand-written row per entry name.
    private struct Expected {
        /// The status of every present value in the entry.
        let status: Observation.Status
        /// The exact accessibility value of the Total row.
        let total: String
        /// The same while the model holds a client or engine error over this snapshot.
        let totalUnderError: String
    }

    /// The entries' last good instant is 2026-04-02T10:00:00Z (1_775_124_000_000) or 10 s later;
    /// the popover formats in the request zone, UTC. en_US puts U+202F before AM.
    private static let atTen = "Updated at 10:00\u{202F}AM"
    private static let partial141 = "141 tokens, Derived, Partial"

    /// Hand table, per entry name. A non-current status shows the absolute last good time; a
    /// current one shows its age at the present instant (here the request instant).
    private let expected: [String: Expected] = [
        "current_at_600000_ms": .init(status: .current, total: "\(partial141), Current, Updated 10 minutes ago", totalUnderError: "\(partial141), Error, \(atTen)"),
        "stale_at_600001_ms": .init(status: .stale, total: "\(partial141), Stale, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "unavailable_empty_window": .init(status: .unavailable, total: "Unavailable, Updated at Apr 2, 2026 at 10:00\u{202F}AM", totalUnderError: "Unavailable, Updated at Apr 2, 2026 at 10:00\u{202F}AM"),
        "denied_retains_values": .init(status: .denied, total: "\(partial141), Denied, \(atTen)", totalUnderError: "\(partial141), Denied, \(atTen)"),
        "error_attached_newer_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "error_attached_equal_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "error_attached_earlier_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "current_after_attached_recovery": .init(status: .current, total: "\(partial141), Current, Updated just now", totalUnderError: "\(partial141), Error, \(atTen)"),
        "error_unattached_null_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "error_unattached_equal_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "error_unattached_earlier_attempt": .init(status: .error, total: "\(partial141), Error, \(atTen)", totalUnderError: "\(partial141), Error, \(atTen)"),
        "current_after_reattach": .init(status: .current, total: "\(partial141), Current, Updated just now", totalUnderError: "\(partial141), Error, \(atTen)"),
        "catching_up_with_live_backlog": .init(status: .catchingUp, total: "4,968 tokens, Reported, Catching up, \(atTen)", totalUnderError: "4,968 tokens, Reported, Error, \(atTen)"),
        "fresh_partial_completeness_is_current": .init(status: .current, total: "\(partial141), Current, Updated just now", totalUnderError: "\(partial141), Error, \(atTen)"),
        "null_value_beside_error": .init(status: .error, total: "Unavailable, \(atTen)", totalUnderError: "Unavailable, \(atTen)"),
        "null_value_beside_denied": .init(status: .denied, total: "Unavailable, \(atTen)", totalUnderError: "Unavailable, \(atTen)"),
    ]

    /// The status words, by hand.
    private let word: [Observation.Status: String] = [
        .current: "Current", .stale: "Stale", .unavailable: "Unavailable",
        .error: "Error", .denied: "Denied", .catchingUp: "Catching up",
    ]

    /// Screenshot names for one representative entry of each state.
    private let screenshot: [String: String] = [
        "current_at_600000_ms": "current",
        "stale_at_600001_ms": "stale",
        "unavailable_empty_window": "unavailable",
        "denied_retains_values": "denied",
        "error_attached_equal_attempt": "error",
        "catching_up_with_live_backlog": "catching-up",
    ]

    /// The hand row of an entry; an entry without one fails loudly by name.
    private func row(_ name: String) -> Expected? {
        guard let row = expected[name] else {
            XCTFail("snapshot-states.json entry \"\(name)\" has no hand-written row in ObservationStateTests.expected; add its expected status and Total accessibility values")
            return nil
        }
        return row
    }

    func testEveryEntryHasAHandRow() throws {
        let names = try entries().map(\.name)
        for name in names { _ = row(name) }
        for name in Set(expected.keys).subtracting(names).sorted() {
            XCTFail("ObservationStateTests.expected has a row for \"\(name)\", which snapshot-states.json no longer contains")
        }
    }

    func testEveryStateDecodesWithItsLifecycle() throws {
        let entries = try entries()
        for entry in entries {
            guard let want = row(entry.name) else { continue }
            let reported = try XCTUnwrap(entry.snapshot.sourceReported.first, entry.name)
            let observations = [reported.input, reported.output, reported.reasoning, reported.cacheRead, reported.cacheWrite, reported.total]
            for observation in observations {
                XCTAssertEqual(observation.status, observation.value == nil ? .unavailable : want.status, entry.name)
                XCTAssertEqual(observation.unit, .tokens)
                XCTAssertEqual(observation.lastGoodMs, entry.snapshot.bySource.first?.lastSuccessMs, entry.name)
            }
        }
        // Equal and earlier failure states and their recovery controls.
        let byName = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
        let t: Int64 = 1_775_124_000_000
        for (name, attempt) in [("error_attached_equal_attempt", t), ("error_attached_earlier_attempt", t - 1),
                                ("error_unattached_equal_attempt", t), ("error_unattached_earlier_attempt", t - 1)] {
            let source = try XCTUnwrap(byName[name]?.snapshot.bySource.first)
            XCTAssertEqual(source.lastAttemptMs, attempt, name)
            XCTAssertEqual(source.lastSuccessMs, t, name)
            XCTAssertNotNil(source.lastErrorCode, name)
        }
        XCTAssertNil(byName["error_unattached_null_attempt"]?.snapshot.bySource.first?.lastAttemptMs)
    }

    func testEveryStateRendersUnitProvenanceStatusAndFreshness() throws {
        for entry in try entries() {
            guard let want = row(entry.name) else { continue }
            for dark in [false, true] {
                let model = Render.model(.success(entry.snapshot), nowMs: entry.nowMs)
                let rendered = Render.render(model, dark: dark)
                let rows = rendered.rows
                XCTAssertEqual(rows.count, 6, "\(entry.name): six observation rows")
                let reported = try XCTUnwrap(entry.snapshot.sourceReported.first)
                XCTAssertEqual(rows.first { $0.label == "Total, OpenCode reported tokens" }?.value, want.total, "\(entry.name) Total")
                let observations = [reported.total, reported.input, reported.output, reported.reasoning, reported.cacheRead, reported.cacheWrite]
                for (label, observation) in zip(Render.rowLabels, observations) {
                    let row = try XCTUnwrap(rows.first { $0.label.hasPrefix("\(label), ") }, "\(entry.name) \(label)")
                    let spoken = row.label + " " + row.value
                    XCTAssertTrue(spoken.contains("tokens"), "\(entry.name) \(label): unit")
                    XCTAssertTrue(row.value.contains("Updated ") || row.value.contains("Never updated"), "\(entry.name) \(label): freshness")
                    if let value = observation.value {
                        XCTAssertTrue(row.value.hasPrefix("\(value.formatted(.number.locale(Locale(identifier: "en_US")))) tokens, "), "\(entry.name) \(label): \(row.value)")
                        let provenance = observation.provenance == .derived ? "Derived" : "Reported"
                        XCTAssertTrue(row.value.contains(", \(provenance), "), "\(entry.name) \(label): provenance")
                        XCTAssertEqual(row.value.contains(", Partial, "), observation.completeness == .partial, "\(entry.name) \(label): completeness")
                        XCTAssertTrue(row.value.contains(", \(word[want.status]!), "), "\(entry.name) \(label): status")
                    } else {
                        XCTAssertTrue(row.value.hasPrefix("Unavailable, "), "\(entry.name) \(label): null is Unavailable")
                        XCTAssertFalse(row.value.contains("0 tokens"), "\(entry.name) \(label): never 0 for null")
                        XCTAssertTrue(row.label.contains("reported tokens"), "\(entry.name) \(label): provenance family")
                    }
                }
                // Stale keeps the last good time visible.
                if want.status == .stale {
                    XCTAssertTrue(rendered.texts.contains { $0.value == Self.atTen && $0.label.isEmpty }, "stale keeps its time visible")
                }
                if let name = screenshot[entry.name] {
                    try Render.save(rendered, as: "slice-008-\(name)-\(dark ? "dark" : "light")")
                } else {
                    rendered.window.orderOut(nil)
                }
            }
        }
    }

    /// Every state as last good data while the model holds an error (DEC-076 and amendments):
    /// each row keeps its value, unit, provenance and completeness; a present non-denied value
    /// reads Error with its absolute last good time, never Current. Denied stays Denied and a
    /// null value stays Unavailable.
    func testAnyHeldErrorShowsEveryLastGoodStateAsError() throws {
        let errors: [BridgeError] = [
            try Support.decodedError("error-engine-failed.json"),
            try Support.decodedError("error-internal-panic.json"),
            try Support.decodedError("error-cancelled.json"),
            BridgeError(code: "store_busy", message: "store busy", retryable: true),
            BridgeError(code: "source_unavailable", message: "source unavailable", retryable: false),
            .malformedResponse,
        ]
        for entry in try entries() {
            guard let want = row(entry.name) else { continue }
            let reported = try XCTUnwrap(entry.snapshot.sourceReported.first)
            for error in errors {
                let failed = Render.render(Render.model(.failure(error), nowMs: entry.nowMs, lastGood: entry.snapshot), dark: false)
                failed.window.orderOut(nil)
                let rows = failed.rows
                XCTAssertEqual(rows.count, 6, "\(entry.name) \(error.code)")
                XCTAssertEqual(rows.first { $0.label == "Total, OpenCode reported tokens" }?.value, want.totalUnderError, "\(entry.name) \(error.code)")
                let observations = [reported.total, reported.input, reported.output, reported.reasoning, reported.cacheRead, reported.cacheWrite]
                for (label, observation) in zip(Render.rowLabels, observations) {
                    let value = try XCTUnwrap(rows.first { $0.label.hasPrefix("\(label), ") }?.value, "\(entry.name) \(label)")
                    XCTAssertFalse(value.contains("Current"), "\(entry.name) \(error.code) \(label): never Current")
                    let shown = observation.value == nil ? "Unavailable" : (want.status == .denied ? "Denied" : "Error")
                    XCTAssertTrue(value.hasPrefix("Unavailable, ") || value.contains(", \(shown), "), "\(entry.name) \(error.code) \(label): \(value)")
                }
            }
        }
    }

    /// A golden missing completeness, or with provenance on a null value, is rejected by the
    /// Swift consumer as Rust's comparison rejects it.
    func testMalformedObservationsAreRejected() throws {
        let file = try XCTUnwrap(Support.json("Contracts/bridge-v1/snapshot-states.json") as? [String: Any])
        let states = try XCTUnwrap(file["states"] as? [[String: Any]])
        func mutate(_ index: Int, _ field: String, _ change: (inout [String: Any]) -> Void) throws -> [UInt8] {
            var response = try XCTUnwrap(states[index]["response"] as? [String: Any])
            var data = try XCTUnwrap(response["data"] as? [String: Any])
            var reported = try XCTUnwrap(data["source_reported"] as? [[String: Any]])
            var observation = try XCTUnwrap(reported[0][field] as? [String: Any])
            change(&observation)
            reported[0][field] = observation
            data["source_reported"] = reported
            response["data"] = data
            return Array(try JSONSerialization.data(withJSONObject: response))
        }
        let empty = try XCTUnwrap(states.firstIndex { $0["name"] as? String == "unavailable_empty_window" })
        let rows: [(String, [UInt8])] = [
            ("missing completeness", try mutate(0, "input") { $0.removeValue(forKey: "completeness") }),
            ("missing last_good_ms", try mutate(0, "input") { $0.removeValue(forKey: "last_good_ms") }),
            ("four-key shape", try mutate(0, "total") { $0.removeValue(forKey: "completeness"); $0.removeValue(forKey: "last_good_ms") }),
            ("provenance on a null value", try mutate(empty, "total") { $0["provenance"] = "reported" }),
            ("completeness on a null value", try mutate(empty, "total") { $0["completeness"] = "complete" }),
            ("present value without completeness", try mutate(0, "input") { $0["completeness"] = NSNull() }),
            ("null value that is current", try mutate(empty, "input") { $0["status"] = "current" }),
            ("unknown status", try mutate(0, "input") { $0["status"] = "fresh" }),
            ("unknown unit", try mutate(0, "input") { $0["unit"] = "bytes" }),
        ]
        for (label, bytes) in rows {
            do {
                _ = try Envelope.decode(bytes, as: TodaySnapshot.self)
                XCTFail("\(label) must be malformed_response")
            } catch {
                XCTAssertEqual(error, .malformedResponse, label)
            }
        }
        // Control: the unmodified entry decodes.
        XCTAssertNoThrow(try Envelope.decode(Array(try mutate(0, "input") { _ in }), as: TodaySnapshot.self))
    }
}
