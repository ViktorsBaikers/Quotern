import AppKit
import SwiftUI
import XCTest
@testable import QuoternCore

/// Renders the real popover in a laid-out window, reads its accessibility tree and saves the
/// screenshots inspected for proof.
@MainActor
enum Render {
    nonisolated static let rowLabels = ["Total", "Input", "Output", "Reasoning", "Cache read", "Cache write"]
    static let screenshots = Support.root.appendingPathComponent("build/proof/screenshots")

    struct Rendered {
        let window: NSWindow
        let view: NSView
        let texts: [AccessibleText]
        var rows: [AccessibleText] { texts.filter { text in rowLabels.contains { text.label.hasPrefix("\($0), ") } } }
        func text(_ label: String) -> AccessibleText? { texts.first { $0.label == label } }
    }

    /// Calls of each popover action, for keyboard-shortcut assertions.
    @MainActor
    final class Calls {
        var refresh = 0, addFolder = 0, retry = 0, quit = 0
        var actions: PopoverActions {
            PopoverActions(
                refresh: { self.refresh += 1 }, addFolder: { self.addFolder += 1 },
                retry: { self.retry += 1 }, quit: { self.quit += 1 })
        }
    }

    static func model(_ result: Result<TodaySnapshot, BridgeError>?, nowMs: Int64, lastGood: TodaySnapshot? = nil, pending: Bool = false) -> TodayModel {
        let model = TodayModel(client: EngineClient(), zone: "UTC", nowMs: { nowMs })
        if let lastGood { model.receiveLatest(.success(lastGood)) }
        if let result { model.receiveLatest(result) }
        if pending { _ = model.begin() }
        return model
    }

    static func render(_ model: TodayModel, dark: Bool) -> Rendered {
        render(model, appearance: dark ? .darkAqua : .aqua)
    }

    /// `popoverMaterial` draws the popover's own material behind the content instead of the
    /// window background.
    static func render(
        _ model: TodayModel, appearance: NSAppearance.Name, calls: Calls = Calls(),
        maxListHeight: CGFloat? = nil, popoverMaterial: Bool = false
    ) -> Rendered {
        _ = NSApplication.shared
        var popover = PopoverView(model: model, actions: calls.actions)
        if let maxListHeight { popover.maxListHeight = maxListHeight }
        // A capture draws only the view: without a material, the window background is drawn into
        // it so text reads against the appearance it was rendered in.
        let hosting = NSHostingView(rootView: popover.background(popoverMaterial ? Color.clear : Color(nsColor: .windowBackgroundColor)))
        let size = hosting.fittingSize
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: PopoverView.width, height: size.height), styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: appearance)
        hosting.appearance = window.appearance
        let view: NSView
        if popoverMaterial {
            let material = NSVisualEffectView(frame: NSRect(origin: .zero, size: NSSize(width: PopoverView.width, height: size.height)))
            material.material = .popover
            material.blendingMode = .withinWindow
            material.state = .active
            hosting.frame = material.bounds
            hosting.autoresizingMask = [.width, .height]
            material.addSubview(hosting)
            window.backgroundColor = .clear
            view = material
        } else {
            window.backgroundColor = .windowBackgroundColor
            view = hosting
        }
        window.contentView = view
        window.orderFrontRegardless()
        view.layoutSubtreeIfNeeded()
        window.display()
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        let texts = AccessibilityTree.texts(of: hosting)
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        return Rendered(window: window, view: view, texts: texts.isEmpty ? AccessibilityTree.texts(of: hosting) : texts)
    }

    static func save(_ rendered: Rendered, as name: String) throws {
        try FileManager.default.createDirectory(at: screenshots, withIntermediateDirectories: true)
        let view = rendered.view
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        try png.write(to: screenshots.appendingPathComponent("\(name).png"))
        rendered.window.orderOut(nil)
    }

    /// Sends a key equivalent to the rendered window, as the keyboard does.
    static func press(_ key: String, _ modifiers: NSEvent.ModifierFlags, in rendered: Rendered) -> Bool {
        let event = NSEvent.keyEvent(
            with: .keyDown, location: .zero, modifierFlags: modifiers, timestamp: 0,
            windowNumber: rendered.window.windowNumber, context: nil, characters: key,
            charactersIgnoringModifiers: key, isARepeat: false, keyCode: key == "\r" ? 36 : 0)
        let handled = event.map { rendered.window.performKeyEquivalent(with: $0) } ?? false
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        return handled
    }

    static func snapshot(_ golden: String) throws -> TodaySnapshot {
        try Envelope.decode(Array(Support.data("Contracts/bridge-v1/\(golden)")), as: TodaySnapshot.self)
    }
}

@MainActor
final class TodayViewRenderTests: XCTestCase {
    private let t: Int64 = 1_775_124_000_000
    /// 2026-04-02T10:00:00Z in UTC, as en_US formats it (U+202F before AM).
    private let atTen = "Updated at 10:00\u{202F}AM"

    /// The SAME reported golden rendered in light and dark: separate rows with value and unit,
    /// provenance, completeness, status and freshness, within 360 pt. (Increased contrast is not
    /// rendered here: a hosting view takes it from the system setting, not from a high-contrast
    /// `NSAppearance`, whose captures are byte-identical to these.)
    func testReportedGoldenRendersInLightAndDark() throws {
        let snapshot = try Render.snapshot("snapshot-opencode-reported.json")
        for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
            let rendered = Render.render(Render.model(.success(snapshot), nowMs: t), appearance: appearance)
            XCTAssertLessThanOrEqual(rendered.view.fittingSize.width, PopoverView.width)
            let rows = Dictionary(uniqueKeysWithValues: rendered.rows.map { ($0.label, $0.value) })
            // Independent oracle: the hand daily oracle's numbers (27/41/6/8/10, total 141
            // derived); reasoning, cache and total were not carried by every record.
            XCTAssertEqual(rows, [
                "Total, OpenCode reported tokens": "141 tokens, Derived, Partial, Current, Updated just now",
                "Input, OpenCode reported tokens": "27 tokens, Reported, Current, Updated just now",
                "Output, OpenCode reported tokens": "41 tokens, Reported, Current, Updated just now",
                "Reasoning, OpenCode reported tokens": "6 tokens, Reported, Partial, Current, Updated just now",
                "Cache read, OpenCode reported tokens": "8 tokens, Reported, Partial, Current, Updated just now",
                "Cache write, OpenCode reported tokens": "10 tokens, Reported, Partial, Current, Updated just now",
            ], suffix)
            XCTAssertTrue(rendered.texts.contains { $0.value == "Origin unverified" })
            XCTAssertNotNil(rendered.text("OpenCode reported tokens, source"), "the section names its folder: \(rendered.texts)")
            try Render.save(rendered, as: "slice-008-reported-\(suffix)")
        }
        // The pending-partial golden: the latest pass failed after publication.
        let partial = try Render.snapshot("snapshot-pending-partial.json")
        for dark in [false, true] {
            let rendered = Render.render(Render.model(.success(partial), nowMs: t), dark: dark)
            XCTAssertTrue(rendered.rows.allSatisfy { $0.value.hasSuffix(", Partial, Error, \(atTen)") }, "\(rendered.rows)")
            XCTAssertTrue(rendered.texts.contains { $0.value == "Last read failed. Refresh to try again." }, "\(rendered.texts)")
            try Render.save(rendered, as: dark ? "slice-008-reported-partial-dark" : "slice-008-reported-partial")
        }
    }

    /// The popover's own material behind the same content, light and dark.
    func testReportedGoldenOverPopoverMaterial() throws {
        let snapshot = try Render.snapshot("snapshot-opencode-reported.json")
        for dark in [false, true] {
            let rendered = Render.render(Render.model(.success(snapshot), nowMs: t), appearance: dark ? .darkAqua : .aqua, popoverMaterial: true)
            XCTAssertEqual(rendered.rows.count, 6)
            try Render.save(rendered, as: "slice-008-reported-popover-material-\(dark ? "dark" : "light")")
        }
    }

    func testLoadingEmptyAndPendingStates() throws {
        for dark in [false, true] {
            let suffix = dark ? "dark" : "light"
            let loading = Render.render(Render.model(nil, nowMs: t), dark: dark)
            XCTAssertTrue(loading.texts.contains { $0.label.contains("Loading") || $0.value.contains("Loading") }, "\(loading.texts)")
            XCTAssertTrue(loading.rows.isEmpty, "no number while loading")
            XCTAssertEqual(loading.text("Refresh")?.enabled, false, "nothing to refresh while loading")
            XCTAssertEqual(loading.text("Add folder…")?.enabled, false, "no folder change while loading")
            XCTAssertEqual(loading.text("Quit Quotern")?.enabled, true)
            try Render.save(loading, as: "slice-008-loading-\(suffix)")

            let calls = Render.Calls()
            let empty = Render.render(Render.model(.success(try Render.snapshot("snapshot-empty.json")), nowMs: t), appearance: dark ? .darkAqua : .aqua, calls: calls)
            XCTAssertTrue(empty.texts.contains { $0.value == "No sources selected" }, "\(empty.texts)")
            XCTAssertEqual(empty.texts.filter { $0.label == "Add folder…" }.count, 1, "one primary action: \(empty.texts)")
            XCTAssertNil(empty.text("Refresh"), "nothing to refresh before a folder is chosen")
            XCTAssertTrue(empty.rows.isEmpty, "an empty inventory shows no number, never 0")
            XCTAssertTrue(Render.press("\r", [], in: empty), "Return is handled")
            XCTAssertEqual(calls.addFolder, 1, "Return chooses a folder in the empty first run")
            try Render.save(empty, as: "slice-008-empty-first-run-\(suffix)")

            // A call pending over the last good data: the data stays.
            let lastGood = try Render.snapshot("snapshot-opencode-reported.json")
            let pending = Render.render(Render.model(nil, nowMs: t, lastGood: lastGood, pending: true), dark: dark)
            XCTAssertTrue(pending.texts.contains { $0.value.contains("Refreshing") || $0.label.contains("Refreshing") }, "\(pending.texts)")
            XCTAssertEqual(pending.rows.count, 6, "last good data shown while pending")
            XCTAssertEqual(pending.text("Refresh")?.enabled, false, "no second refresh while one is pending")
            try Render.save(pending, as: "slice-008-pending-\(suffix)")
        }
    }

    /// ⌘R refreshes and ⌘Q quits.
    func testKeyboardShortcuts() throws {
        let calls = Render.Calls()
        let rendered = Render.render(Render.model(.success(try Render.snapshot("snapshot-opencode-reported.json")), nowMs: t), appearance: .aqua, calls: calls)
        defer { rendered.window.orderOut(nil) }
        XCTAssertTrue(Render.press("r", .command, in: rendered))
        XCTAssertEqual(calls.refresh, 1, "⌘R refreshes")
        XCTAssertTrue(Render.press("q", .command, in: rendered))
        XCTAssertEqual(calls.quit, 1, "⌘Q quits")
        XCTAssertEqual(calls.retry + calls.addFolder, 0)
    }

    /// Rows of the reported golden's last good data while the model holds a failure: value,
    /// unit, provenance and completeness unchanged; the status word is Error with the absolute
    /// last good time.
    private var lastGoodUnderFailure: [String: String] {
        [
            "Total, OpenCode reported tokens": "141 tokens, Derived, Partial, Error, \(atTen)",
            "Input, OpenCode reported tokens": "27 tokens, Reported, Error, \(atTen)",
            "Output, OpenCode reported tokens": "41 tokens, Reported, Error, \(atTen)",
            "Reasoning, OpenCode reported tokens": "6 tokens, Reported, Partial, Error, \(atTen)",
            "Cache read, OpenCode reported tokens": "8 tokens, Reported, Partial, Error, \(atTen)",
            "Cache write, OpenCode reported tokens": "10 tokens, Reported, Partial, Error, \(atTen)",
        ]
    }

    /// The SAME decoded engine_failed and internal_panic in the result entry: plain copy naming
    /// the recovery, Retry as the default action, and the last good rows with the status word
    /// Error, never Current. Accessibility reads them in visual order.
    func testEngineFailureShowsErrorOverLastGood() throws {
        let lastGood = try Render.snapshot("snapshot-opencode-reported.json")
        let cases: [(String, String, String)] = [
            ("error-engine-failed.json", "Couldn't update: the engine stopped.", "engine-failed"),
            ("error-internal-panic.json", "Couldn't update: the engine stopped unexpectedly.", "internal-panic"),
        ]
        for (golden, headline, name) in cases {
            let failed = try Support.decodedError(golden)
            for dark in [false, true] {
                let calls = Render.Calls()
                let rendered = Render.render(Render.model(.failure(failed), nowMs: t, lastGood: lastGood), appearance: dark ? .darkAqua : .aqua, calls: calls)
                XCTAssertEqual(rendered.texts.filter { $0.label.isEmpty }.map(\.value).filter { $0.hasPrefix("Couldn't") || $0.hasPrefix("Retry ") || $0.hasPrefix("Showing") }, [
                    headline, "Retry restarts the engine.", "Showing the last good data.",
                ], golden)
                XCTAssertFalse(rendered.texts.contains { $0.value.contains(failed.message) }, "no raw engine text: \(rendered.texts)")
                XCTAssertNotNil(rendered.text("Retry"))
                XCTAssertEqual(Dictionary(uniqueKeysWithValues: rendered.rows.map { ($0.label, $0.value) }), lastGoodUnderFailure, golden)
                XCTAssertFalse(rendered.texts.contains { $0.value.contains("Current") || $0.label.contains("Current") }, "\(rendered.texts)")
                XCTAssertEqual(rendered.text("Refresh")?.enabled, false, "only Retry recovers")
                XCTAssertTrue(Render.press("\r", [], in: rendered))
                XCTAssertEqual(calls.retry, 1, "Return is Retry")

                // Keyboard and VoiceOver order: header, error, section, rows, then the actions.
                let order = rendered.texts.map { $0.label.isEmpty ? $0.value : $0.label }
                let landmarks = ["Today", headline, "Retry", "OpenCode reported tokens, source"]
                    + Render.rowLabels.map { "\($0), OpenCode reported tokens" } + ["Refresh", "Add folder…", "Quit Quotern"]
                XCTAssertEqual(order.filter(landmarks.contains), landmarks, "accessibility order: \(order)")
                if golden == "error-engine-failed.json" {
                    try Render.save(rendered, as: "slice-008-engine-failed-\(dark ? "dark" : "light")")
                } else {
                    try Render.save(rendered, as: "slice-008-\(name)-\(dark ? "dark" : "light")")
                }
            }
        }
    }

    /// A client malformed_response over the same last good data shows its own copy, Retry and
    /// the same Error rows; the next good snapshot restores Rust's Current.
    func testMalformedResponseShowsErrorOverLastGoodUntilRecovery() throws {
        let lastGood = try Render.snapshot("snapshot-opencode-reported.json")
        let model = Render.model(.failure(.malformedResponse), nowMs: t, lastGood: lastGood)
        let failed = Render.render(model, dark: false)
        XCTAssertTrue(failed.texts.contains { $0.value == "Couldn't update: the engine's response couldn't be read." }, "\(failed.texts)")
        XCTAssertTrue(failed.texts.contains { $0.value == "Retry restarts the engine." })
        XCTAssertNotNil(failed.text("Retry"), "malformed_response offers Retry")
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: failed.rows.map { ($0.label, $0.value) }), lastGoodUnderFailure)
        failed.window.orderOut(nil)

        model.receiveLatest(.success(lastGood))
        let recovered = Render.render(model, dark: false)
        XCTAssertEqual(recovered.rows.count, 6)
        XCTAssertTrue(recovered.rows.allSatisfy { $0.value.contains(", Current, Updated just now") }, "\(recovered.rows)")
        XCTAssertFalse(recovered.texts.contains { $0.value.hasPrefix("Couldn't") })
        recovered.window.orderOut(nil)
    }

    /// The launch open fails because another owner holds the data directory: no snapshot, so
    /// no "last good" line; Retry is offered and nothing else can call the closed engine.
    func testLaunchOpenFailureOffersRetryWithoutLastGood() async throws {
        let world = try World(rows: Support.dailyRows())
        let config = world.config
        let owner = EngineClient()
        try await owner.open(config)
        // The owner claims the data directory with its first store use.
        _ = try await owner.setSourceSelection(world.selection())
        for dark in [false, true] {
            let model = TodayModel(client: EngineClient(), zone: "UTC", nowMs: { self.t })
            let opened = await model.open(config)
            XCTAssertFalse(opened)
            XCTAssertEqual(model.error?.code, "store_busy")
            let rendered = Render.render(model, dark: dark)
            let lines = rendered.texts.filter { $0.label.isEmpty }.map(\.value)
            XCTAssertTrue(lines.contains("Couldn't update: usage history is busy."), "\(lines)")
            XCTAssertTrue(lines.contains("Quit any other copy of Quotern, then Retry."), "\(lines)")
            XCTAssertFalse(lines.contains("Showing the last good data."), "there is no last good data")
            XCTAssertNotNil(rendered.text("Retry"))
            XCTAssertEqual(rendered.text("Refresh")?.enabled, false)
            XCTAssertEqual(rendered.text("Add folder…")?.enabled, false)
            try Render.save(rendered, as: "slice-008-open-failed-\(dark ? "dark" : "light")")
        }
        await owner.close()
    }

    /// A failed folder selection says so, with its own next step.
    func testAddFolderFailureIsWordedAsSuch() throws {
        let lastGood = try Render.snapshot("snapshot-opencode-reported.json")
        let model = Render.model(nil, nowMs: t, lastGood: lastGood)
        model.receiveFailure(BridgeError(code: "source_overlap_conflict", message: "source overlap conflict", retryable: false), action: .addFolder)
        let rendered = Render.render(model, dark: false)
        rendered.window.orderOut(nil)
        let lines = rendered.texts.filter { $0.label.isEmpty }.map(\.value)
        XCTAssertTrue(lines.contains("Couldn't add folder: this folder overlaps one already chosen."), "\(lines)")
        XCTAssertTrue(lines.contains("Choose a folder that is neither inside nor around one already chosen."), "\(lines)")
        XCTAssertNil(rendered.text("Retry"), "a refused folder is not retried")
    }

    /// Every error code has its own plain copy and next step; no raw engine text is shown.
    func testEveryErrorCodeHasPlainCopy() {
        let codes = rustErrorCodes.sorted() + [BridgeError.abiMismatch.code, BridgeError.malformedResponse.code]
        var summaries: Set<String> = []
        for code in codes {
            let summary = ErrorText.summary(code)
            XCTAssertNotEqual(summary, ErrorText.summary("not_a_code"), "\(code) has its own copy")
            XCTAssertFalse(summary.contains("_"), "\(code): no code names in copy")
            XCTAssertTrue(ErrorText.nextStep(code, action: .update).hasSuffix("."), code)
            summaries.insert(summary)
        }
        XCTAssertEqual(summaries.count, codes.count - 1, "only invalid_request and unknown_method share copy")
        XCTAssertEqual(ErrorText.summary("store_newer_version"), "usage history was written by a newer Quotern")
        XCTAssertEqual(ErrorText.nextStep("store_newer_version", action: .update), "Update Quotern to read it.")
        XCTAssertEqual(ErrorText.nextStep("store_corrupt", action: .update), "Quit Quotern and move ~/Library/Application Support/Quotern aside to start a new history. Nothing is deleted automatically.")
        XCTAssertEqual(ErrorText.nextStep("abi_mismatch", action: .update), "Reinstall Quotern.")
    }

    /// Three sources with long folder names: each section names its folder, rows say which
    /// folder they belong to, and the list scrolls within its bound instead of overflowing.
    func testManySourcesWithLongNamesStayBounded() throws {
        let one = try XCTUnwrap(Support.json("Contracts/bridge-v1/snapshot-opencode-reported.json") as? [String: Any])
        var data = try XCTUnwrap(one["data"] as? [String: Any])
        let entry = try XCTUnwrap((data["by_source"] as? [[String: Any]])?.first)
        let reported = try XCTUnwrap((data["source_reported"] as? [[String: Any]])?.first)
        let names = [
            "opencode-work-laptop-primary-account-with-a-very-long-folder-name",
            "opencode-personal",
            "opencode-client-project-archive-2026-with-another-long-name",
        ]
        var entries: [[String: Any]] = [], reports: [[String: Any]] = []
        for (index, name) in names.enumerated() {
            let id = String(repeating: "\(index + 1)", count: 32)
            var e = entry, r = reported
            e["source_id"] = id
            e["root_display"] = name
            r["source_id"] = id
            entries.append(e)
            reports.append(r)
        }
        data["by_source"] = entries
        data["source_reported"] = reports
        let bytes = Array(try JSONSerialization.data(withJSONObject: ["v": 1, "ok": true, "data": data]))
        let snapshot = try Envelope.decode(bytes, as: TodaySnapshot.self)
        for dark in [false, true] {
            let rendered = Render.render(Render.model(.success(snapshot), nowMs: t), appearance: dark ? .darkAqua : .aqua, maxListHeight: 360)
            XCTAssertLessThanOrEqual(rendered.view.fittingSize.width, PopoverView.width)
            XCTAssertLessThan(rendered.view.fittingSize.height, 560, "the list is bounded, not three full sections tall")
            for name in names {
                XCTAssertNotNil(rendered.text("OpenCode reported tokens, \(name)"), "section names \(name): \(rendered.texts.map(\.label))")
            }
            XCTAssertNotNil(rendered.text("Total, OpenCode reported tokens in opencode-personal"), "rows say their folder: \(rendered.rows.map(\.label))")
            XCTAssertEqual(Set(rendered.rows.map(\.label)).count, rendered.rows.count, "no two rows share a label")
            XCTAssertNotNil(rendered.text("Quit Quotern"), "actions stay reachable below the list")
            try Render.save(rendered, as: "slice-008-many-sources-\(dark ? "dark" : "light")")
        }
    }
}
