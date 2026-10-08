import AppKit
import Darwin
import MachO
import QuoternCore

/// `--selftest-journey`: drives the real status item, popover, watcher and engine over an
/// isolated fixture home and data directory, then writes `journey.json` with the expected,
/// actual and displayed values and exits 0 only if every check passed. It refuses the
/// production data directory.
@MainActor
final class SelfTestJourney: NSObject, NSApplicationDelegate {
    private let options: SelfTestArguments.Journey
    private var checks: [[String: Any]] = []
    private var statusItem: StatusItemController?
    private var watcher: SourceWatcher?
    private var fallbackAnchor: NSWindow?

    init(options: SelfTestArguments.Journey) {
        self.options = options
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            let passed = await run()
            exit(passed ? 0 : 1)
        }
    }

    private func check(_ name: String, _ ok: Bool, _ detail: Any = NSNull()) {
        checks.append(["name": name, "pass": ok, "detail": detail])
        if !ok { FileHandle.standardError.write(Data("selftest check failed: \(name)\n".utf8)) }
    }

    private func run() async -> Bool {
        var record: [String: Any] = ["phase": options.phase, "now_ms": options.nowMs]
        defer { write(record) }
        guard let expected = (try? JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: options.home + "/expected.json")))) as? [String: Any],
              let zone = expected["tz"] as? String,
              let source = expected["source"] as? [String: Any],
              let relativeRoot = source["root"] as? String
        else {
            check("expected.json readable", false)
            record["checks"] = checks
            return false
        }
        record["expected"] = expected
        let root = options.home + "/" + relativeRoot
        let client = EngineClient()
        let now = options.nowMs
        let model = TodayModel(client: client, zone: zone, nowMs: { now })
        do {
            try await client.open(EngineConfig(dataDir: options.dataDirectory, home: options.home))
            if options.phase == "first" {
                _ = try await client.setSourceSelection(SourceSelection(harness: "opencode", root: root, selected: true))
            }
        } catch {
            check("engine open and selection", false, error.code)
            record["checks"] = checks
            return false
        }

        // Launch: the real watcher issues the one launch pass; no file event is needed.
        let watcher = SourceWatcher(
            clock: DispatchWatcherClock(), dataDirectory: options.dataDirectory,
            makeStream: FSEventsWatcherStream.make, pass: { await model.reconcile() })
        self.watcher = watcher
        watcher.update(enabled: true, roots: [root])
        await waitUntil { watcher.passCount >= 1 && !watcher.passInFlight && !model.pending }
        check("one launch pass without a file event", watcher.passCount == 1, watcher.passCount)
        check("one file-event stream", watcher.streamActive && watcher.streamStarts == 1, watcher.streamStarts)

        // The real status item, opened by a real click on its button.
        let controller = StatusItemController(model: model, actions: PopoverActions(refresh: {}, addFolder: {}, retry: {}, quit: {}))
        statusItem = controller
        await waitUntil { (controller.statusItem.button?.window?.frame.height ?? 0) > 0 }
        NSApp.activate(ignoringOtherApps: true)
        controller.statusItem.button?.performClick(nil)
        await waitUntil { controller.popover.isShown }
        try? await Task.sleep(for: .milliseconds(800))
        let placed = controller.statusItem.button?.window?.frame ?? .zero
        record["status_item_frame"] = NSStringFromRect(placed)
        check("status-item click opens the popover", controller.popover.isShown, NSStringFromRect(placed))
        if !controller.popover.isShown {
            // The system menu bar did not place the item (zero-height frame), so the click had
            // nothing to anchor to. The click clause stays failed; the same popover is anchored
            // to a plain window only so its content can still be read and recorded.
            let anchor = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 40), styleMask: [.titled], backing: .buffered, defer: false)
            anchor.title = "Quotern self-test anchor"
            anchor.center()
            anchor.orderFrontRegardless()
            fallbackAnchor = anchor
            if let view = anchor.contentView {
                controller.popover.show(relativeTo: view.bounds, of: view, preferredEdge: .minY)
            }
            await waitUntil { controller.popover.isShown }
            try? await Task.sleep(for: .milliseconds(800))
            record["popover_anchor"] = "fallback window (status item unplaced)"
        } else {
            record["popover_anchor"] = "status item"
        }
        // Before a measured family exists the status item shows its symbol alone: no title and
        // no digit anywhere an assistive client reads it.
        let button = controller.statusItem.button
        let title = button?.title ?? "<no button>"
        let axValue = button?.accessibilityValue().map { "\($0)" } ?? ""
        let oracle = expected["status_item"] as? [String: String]
        check("status item title", title == oracle?["title"] && button?.image != nil, title)
        check("status item is named", button?.accessibilityLabel() == oracle?["accessibility_label"], button?.accessibilityLabel() ?? NSNull())
        check("status item title and accessibility value carry no digit",
              !(title + axValue).contains(where: \.isNumber), ["title": title, "accessibility_value": axValue])

        let content = controller.popover.contentViewController?.view
        let width = content?.window?.frame.width ?? 0
        check("popover is 360 pt wide", content?.frame.width == PopoverView.width, content?.frame.width ?? 0)
        record["popover_window_width"] = width
        let classes = content.map(viewClasses) ?? []
        check("AppKit hosting view, no web view", classes.contains { $0.contains("NSHostingView") } && !classes.contains { $0.lowercased().contains("webview") },
              classes.count)

        // Displayed: every accessibility label and value of the real popover, unlabelled texts
        // included, in reading order.
        let texts = content.map(AccessibilityTree.texts) ?? []
        record["displayed_texts"] = texts.map { ["label": $0.label, "value": $0.value] }
        var displayed: [String: String] = [:]
        for text in texts where !text.label.isEmpty {
            displayed[text.label] = text.value
        }
        record["displayed"] = displayed
        let unlabelled = texts.filter { $0.label.isEmpty }.map(\.value)
        // The adapter cannot verify the origin of OpenCode records, and the launch pass at --now
        // succeeded, so the section header says both.
        check("displayed Origin unverified", unlabelled.contains("Origin unverified"), unlabelled)
        check("displayed header freshness Updated just now", unlabelled.contains("Updated just now"), unlabelled)
        if let expectedDisplayed = expected["displayed"] as? [String: String] {
            for (label, value) in expectedDisplayed.sorted(by: { $0.key < $1.key }) {
                check("displayed \(label)", displayed[label] == value, displayed[label] ?? NSNull())
            }
        } else {
            check("expected.displayed present", false)
        }

        // Actual: the decoded snapshot the popover shows.
        if let snapshot = model.snapshot, let actual = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot)) {
            record["actual"] = actual
            let reported = snapshot.sourceReported.first
            check("one reported source", snapshot.sourceReported.count == 1, snapshot.sourceReported.count)
            check("window start", snapshot.window.startMs == (expected["window"] as? [String: Any])?["start_ms"] as? Int64, snapshot.window.startMs)
            check("window end", snapshot.window.endMs == (expected["window"] as? [String: Any])?["end_ms"] as? Int64, snapshot.window.endMs)
            if let reported, let oracle = expected["source_reported"] as? [String: [String: Any]] {
                let observations: [String: Observation] = [
                    "input": reported.input, "output": reported.output, "reasoning": reported.reasoning,
                    "cache_read": reported.cacheRead, "cache_write": reported.cacheWrite, "total": reported.total,
                ]
                for (field, want) in oracle.sorted(by: { $0.key < $1.key }) {
                    let got = observations[field]
                    let same = got.map {
                        ($0.value.map { NSNumber(value: $0) } ?? NSNull()) as NSObject == (want["value"] as? NSObject ?? NSNull())
                            && $0.provenance?.rawValue == want["provenance"] as? String
                            && $0.completeness?.rawValue == want["completeness"] as? String
                            && $0.status.rawValue == want["status"] as? String
                            && $0.unit.rawValue == want["unit"] as? String
                            && $0.lastGoodMs == want["last_good_ms"] as? Int64
                    } ?? false
                    check("actual \(field)", same)
                }
            }
        } else {
            check("snapshot present", false, model.error?.code ?? NSNull())
        }

        // Native runtime boundary of this process.
        let forbidden = forbiddenImages()
        check("no web or Python runtime loaded", forbidden.isEmpty, forbidden)
        record["loaded_images"] = Int(_dyld_image_count())
        let listeners = tcpListeners()
        check("no TCP listener", listeners == 0, listeners)

        if let content { savePNG(of: content, to: options.out + "/popover.png") }
        controller.popover.performClose(nil)
        watcher.update(enabled: false, roots: [])
        await client.close()
        record["checks"] = checks
        record["pass_count"] = watcher.passCount
        let passed = checks.allSatisfy { $0["pass"] as? Bool == true }
        record["result"] = passed ? "pass" : "fail"
        return passed
    }

    private func waitUntil(_ condition: @MainActor () -> Bool) async {
        let deadline = Date().addingTimeInterval(20)
        while !condition(), Date() < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    private func savePNG(of view: NSView, to path: String) {
        try? FileManager.default.createDirectory(atPath: options.out, withIntermediateDirectories: true)
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds),
              let context = NSGraphicsContext(bitmapImageRep: bitmap)
        else { return }
        // The popover's material is drawn by its frame, not by this view: lay the window
        // background under the capture, in the view's appearance, so its text stays readable.
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            NSColor.windowBackgroundColor.setFill()
            view.bounds.fill()
        }
        NSGraphicsContext.restoreGraphicsState()
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try? bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }

    private func write(_ record: [String: Any]) {
        try? FileManager.default.createDirectory(atPath: options.out, withIntermediateDirectories: true)
        guard let data = try? JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys]) else { return }
        try? data.write(to: URL(fileURLWithPath: options.out + "/journey.json"))
    }
}
