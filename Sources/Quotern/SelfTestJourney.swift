import AppKit
import Darwin
import MachO
import QuoternCore

/// `--selftest-journey`: observes native test inputs over the real status item and engine in an
/// isolated fixture home and data directory, then writes `journey.json` with the expected,
/// actual and displayed values and exits 0 only if every check passed. It refuses the
/// production data directory.
@MainActor
final class SelfTestJourney: NSObject, NSApplicationDelegate, NSOpenSavePanelDelegate {
    private let options: SelfTestArguments.Journey
    private var checks: [[String: Any]] = []
    private var statusItem: StatusItemController?
    private var watcher: SourceWatcher?
    private var pickerChoice: (name: String, root: String, deadline: ContinuousClock.Instant)?
    private var pickerObserved = false
    private var pickerPanel: NSOpenPanel?
    private var pickerSubmissionFinished = false
    private var pickerFault: String?
    private var pickerClockAdvance: Duration = .zero
    private var pickerNow: ContinuousClock.Instant { ContinuousClock().now.advanced(by: pickerClockAdvance) }
    private var pickerEvents: [String] = []
    private var pickerTimedOut = false
    private var pickerValidationRejections = 0
    private var pickerVisibleAtRejection = false


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
              let relativeRoot = source["root"] as? String,
              let codex = expected["codex"] as? [String: Any],
              let codexRelativeRoot = codex["root"] as? String
        else {
            check("expected.json readable", false)
            record["checks"] = checks
            return false
        }
        if let fault = expected["picker_fault"] {
            guard let fault = fault as? String, ["withheld-readiness", "refused-ok", "late-ok"].contains(fault), options.phase == "first" else {
                check("picker fault is valid for first use", false)
                record["checks"] = checks
                return false
            }
            pickerFault = fault
        }
        record["expected"] = expected
        let root = options.home + "/" + relativeRoot
        let codexRoot = options.home + "/" + codexRelativeRoot
        let authPath = codexRoot + "/auth.json"
        var authBefore = stat()
        let authPresent = lstat(authPath, &authBefore) == 0
        check("Codex auth fixture is unreadable", authPresent && authBefore.st_mode & 0o777 == 0 && geteuid() != 0)
        let client = EngineClient()
        let now = options.nowMs
        let model = TodayModel(client: client, zone: zone, nowMs: { now })
        do {
            try await client.open(EngineConfig(dataDir: options.dataDirectory, home: options.home))
        } catch {
            check("engine open and selection", false, error.code)
            record["checks"] = checks
            return false
        }

        let suite = "app.quotern.selftest." + options.dataDirectory.utf8.map { String(format: "%02x", $0) }.joined()
        guard let defaults = UserDefaults(suiteName: suite) else {
            check("isolated defaults available", false)
            record["checks"] = checks
            return false
        }
        record["defaults_suite"] = suite
        let roots = WatchedRoots(defaults: defaults)
        let watcher = SourceWatcher(
            clock: DispatchWatcherClock(), dataDirectory: options.dataDirectory,
            makeStream: FSEventsWatcherStream.make, pass: { await model.reconcile() })
        self.watcher = watcher
        defer { watcher.update(enabled: false, roots: []) }
        if options.phase != "first" { await model.refresh() }

        // XCUITest supplies the native click; this process only observes it.
        let controller = StatusItemController(model: model, actions: PopoverActions(refresh: {}, addFolder: {
            let panel = NSOpenPanel()
            if self.pickerFault == "refused-ok" { panel.delegate = self }
            self.pickerPanel = panel
            addUsageFolder(client: client, model: model, panel: panel,
                           deadline: self.pickerChoice?.deadline, now: { self.afterAcceptedOK() }) { root in
                await completeUsageFolder(root, client: client, model: model, roots: roots, watcher: watcher)
                self.pickerSubmissionFinished = true
            }
        }, retry: {}, quit: {}))
        statusItem = controller
        await waitUntil { (controller.statusItem.button?.window?.frame.height ?? 0) > 0 }
        NSApp.activate(ignoringOtherApps: true)
        await waitUntil(timeout: .seconds(60)) { controller.popover.isShown }
        try? await Task.sleep(for: .milliseconds(800))
        let placed = controller.statusItem.button?.window?.frame ?? .zero
        record["status_item_frame"] = NSStringFromRect(placed)
        record["application_activation_policy"] = NSApp.activationPolicy().rawValue
        record["application_active"] = NSApp.isActive
        record["status_item_visible"] = controller.statusItem.isVisible
        record["status_item_button_bounds"] = controller.statusItem.button.map { NSStringFromRect($0.bounds) } ?? "<no button>"
        record["status_item_window_visible"] = controller.statusItem.button?.window?.isVisible as Any? ?? NSNull()
        check("status-item click opens the popover", controller.popover.isShown, NSStringFromRect(placed))
        record["checks"] = checks
        record["result"] = "running"
        record["complete"] = false
        write(record)
        record["popover_anchor"] = "status item"
        guard controller.popover.isShown else { return false }
        if options.phase == "first" {
            for (name, harness, path) in [("Codex", "codex", codexRoot), ("OpenCode", "opencode", root)] {
                await chooseFolder(name: name, harness: harness, root: path, controller: controller, client: client, model: model, roots: roots)
                if pickerFault != nil {
                    await client.close()
                    controller.popover.performClose(nil)
                    record["checks"] = checks
                    let passed = checks.allSatisfy { $0["pass"] as? Bool == true }
                    record["result"] = passed ? "pass" : "fail"
                    record["complete"] = true
                    return passed
                }
            }
        }

        if options.phase != "first" {
            await applyUsageSources(client: client, model: model, roots: roots, watcher: watcher)
        }
        let expectedStarts = options.phase == "first" ? 2 : 1
        await waitUntil { watcher.passCount >= expectedStarts && !watcher.passInFlight && !model.pending }
        if options.phase == "first" {
            check("one pass per selected folder", watcher.passCount == 2, watcher.passCount)
            check("one stream restarted for the added root", watcher.streamActive && watcher.streamStarts == 2, watcher.streamStarts)
        } else {
            check("one launch pass without a file event", watcher.passCount == 1, watcher.passCount)
            check("one file-event stream", watcher.streamActive && watcher.streamStarts == 1, watcher.streamStarts)
        }
        record["persisted_roots"] = WatchedRoots(defaults: defaults).all
        check("selected roots persisted canonically", Set(roots.all) == Set([root, codexRoot].map {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path
        }), roots.all)
        check("enabled sources have a watcher timer", watcher.timerActive)

        await waitUntil(timeout: .seconds(60)) { controller.popover.isShown }

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
        if let content, let expectedDisplayed = expected["displayed"] as? [String: String] {
            await waitUntil {
                let texts = AccessibilityTree.texts(of: content)
                return expectedDisplayed.allSatisfy { label, value in texts.contains { $0.label == label && $0.value == value } }
            }
        }
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
        // Neither adapter verifies the origin of reported records, and the launch pass at --now
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
            check("two reported sources", snapshot.sourceReported.count == 2, snapshot.sourceReported.count)
            let opencodeId = snapshot.bySource.first { $0.harness == "opencode" }?.sourceId
            let codexEntry = snapshot.bySource.first { $0.harness == "codex" }
            check("Codex source has no error", codexEntry != nil && codexEntry?.lastErrorCode == nil)
            check("window start", snapshot.window.startMs == (expected["window"] as? [String: Any])?["start_ms"] as? Int64, snapshot.window.startMs)
            check("window end", snapshot.window.endMs == (expected["window"] as? [String: Any])?["end_ms"] as? Int64, snapshot.window.endMs)
            for (harness, sourceId, sourceOracle) in [
                ("opencode", opencodeId, expected["source_reported"]),
                ("codex", codexEntry?.sourceId, codex["source_reported"]),
            ] {
                guard let reported = snapshot.sourceReported.first(where: { $0.sourceId == sourceId }),
                      let oracle = sourceOracle as? [String: [String: Any]] else {
                    check("\(harness) oracle and reported source present", false)
                    continue
                }
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
                    check("actual \(harness) \(field)", same)
                }
            }
        } else {
            check("snapshot present", false, model.error?.code ?? NSNull())
        }

        var authAfter = stat()
        check("Codex auth metadata unchanged", authPresent && lstat(authPath, &authAfter) == 0
              && authBefore.st_ino == authAfter.st_ino && authBefore.st_size == authAfter.st_size
              && authBefore.st_mtimespec.tv_sec == authAfter.st_mtimespec.tv_sec
              && authBefore.st_mtimespec.tv_nsec == authAfter.st_mtimespec.tv_nsec)

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
        record["complete"] = true
        return passed
    }

    /// Observes the rendered action and panel while XCUITest supplies all native input.
    private func chooseFolder(name: String, harness: String, root: String, controller: StatusItemController, client: EngineClient, model: TodayModel, roots: WatchedRoots) async {
        await waitUntil(timeout: .seconds(60)) { controller.popover.isShown }
        guard controller.popover.isShown, let content = controller.popover.contentViewController?.view else {
            check("Add Folder \(name) native picker", false, "popover unavailable")
            check("Add Folder \(name) registered harness", false)
            return
        }
        pickerEvents = []
        var readiness: [String: Any] = [:]
        let readinessWindow: Duration = .seconds(90)
        let pickerWindow: Duration = .seconds(60)
        let readinessDeadline = pickerNow.advanced(by: readinessWindow)
        if harness == "codex" {
            await waitUntil { AccessibilityTree.texts(of: content).contains { $0.label == "Add folder…" && !$0.enabled } }
            let disabledPresent = AccessibilityTree.texts(of: content).contains { $0.label == "Add folder…" && !$0.enabled }
            readiness["disabled_present"] = disabledPresent
            guard disabledPresent else {
                readiness["diagnostic"] = "disabled accessibility action unavailable"
                check("Add Folder \(name) native picker", false, readiness)
                check("Add Folder \(name) registered harness", false)
                return
            }
            pickerEvents.append("disabled action observed")
            // Advance beyond a full picker timeout while the real action is still disabled.
            pickerClockAdvance += (pickerFault == "withheld-readiness" ? readinessWindow : pickerWindow) + .seconds(1)
            pickerEvents.append("clock advanced before readiness")
            readiness["no_premature_panel"] = pickerPanel == nil && NSApp.modalWindow == nil
            do {
                readiness["registered_before_readiness"] = try await client.listSources().count
            } catch {
                check("Add Folder \(name) source listing", false, error.code)
            }
            if pickerFault != "withheld-readiness" {
                pickerEvents.append("readiness released")
                await model.refresh()
            }
        }
        await waitUntil(deadline: readinessDeadline) { AccessibilityTree.texts(of: content).contains { $0.label == "Add folder…" && $0.enabled } }
        let enabledPresent = AccessibilityTree.texts(of: content).contains { $0.label == "Add folder…" && $0.enabled }
        readiness["enabled_present"] = enabledPresent
        guard enabledPresent else {
            if pickerNow >= readinessDeadline { pickerEvents.append("readiness deadline expired") }
            readiness["diagnostic"] = "enabled accessibility action unavailable"
            readiness["panel_created"] = pickerPanel != nil
            readiness["submission_finished"] = pickerSubmissionFinished
            do {
                readiness["registered_count"] = try await client.listSources().count
            } catch {
                check("Add Folder \(name) source listing", false, error.code)
            }
            readiness["events"] = pickerEvents
            check("Add Folder \(name) native picker", false, readiness)
            check("Add Folder \(name) registered harness", false)
            return
        }
        pickerEvents.append("enabled action observed")
        pickerChoice = (name, root, pickerNow.advanced(by: pickerWindow))
        pickerEvents.append("picker deadline armed")
        pickerObserved = false
        pickerSubmissionFinished = false
        pickerTimedOut = false
        pickerValidationRejections = 0
        pickerVisibleAtRejection = false
        let timer = Timer(timeInterval: 0.1, target: self, selector: #selector(observeFolderPanel(_:)), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .modalPanel)
        RunLoop.main.add(timer, forMode: .common)
        defer {
            timer.invalidate()
            pickerChoice = nil
            pickerPanel = nil
        }
        await waitUntil(timeout: pickerWindow) { (pickerObserved && pickerPanel?.isVisible == false) || self.pickerNow >= (pickerChoice?.deadline ?? self.pickerNow) }
        if pickerPanel?.isVisible == true {
            pickerPanel?.cancel(nil)
            NSApp.abortModal()
            await waitUntil { pickerPanel?.isVisible == false }
        }
        timer.invalidate()
        if pickerChoice.map({ pickerNow >= $0.deadline }) == true {
            if !pickerTimedOut { pickerEvents.append("picker deadline expired") }
            pickerTimedOut = true
        }
        let panelClosed = pickerPanel != nil && pickerPanel?.isVisible == false && pickerPanel?.attachedSheet == nil
        if panelClosed { pickerEvents.append("panel closed") }
        let pickedRoot = pickerPanel?.url?.standardizedFileURL.path
        let confirmed = pickerObserved && panelClosed && !pickerTimedOut && pickerValidationRejections == 0
            && pickedRoot == URL(fileURLWithPath: root).standardizedFileURL.path
        readiness["events"] = pickerEvents
        readiness["diagnostic"] = pickerTimedOut ? "picker deadline expired" : (confirmed ? "confirmed" : "picker not confirmed")
        readiness["validation_rejections"] = pickerValidationRejections
        readiness["panel_visible_at_rejection"] = pickerVisibleAtRejection
        readiness["panel_closed"] = panelClosed
        if !confirmed {
            readiness["submission_finished"] = pickerSubmissionFinished
            do {
                readiness["registered_count"] = try await client.listSources().count
            } catch {
                check("Add Folder \(name) source listing", false, error.code)
            }
        }
        check("Add Folder \(name) native picker", confirmed, readiness)
        guard confirmed else {
            check("Add Folder \(name) registered harness", false)
            return
        }
        await waitUntil { pickerSubmissionFinished }
        do {
            let registered = try await client.listSources().contains {
                $0.harness == harness && $0.rootDisplay == URL(fileURLWithPath: root).lastPathComponent && $0.consent == "enabled"
            }
            let canonicalRoot = URL(fileURLWithPath: root).resolvingSymlinksInPath().standardizedFileURL.path
            let expectedRoots = (harness == "codex" ? [root] : [options.home + "/.codex", root]).map {
                URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path
            }
            let persisted = roots.all == expectedRoots
            let expectedPasses = harness == "codex" ? 1 : 2
            await waitUntil { self.watcher?.passCount ?? 0 >= expectedPasses && self.watcher?.passInFlight == false && !model.pending }
            let acquired = model.snapshot?.bySource.contains { $0.harness == harness && $0.lastErrorCode == nil } == true
            check("Add Folder \(name) registered harness", pickerSubmissionFinished && registered && persisted
                  && acquired && watcher?.streamActive == true && watcher?.timerActive == true,
                  ["expected_root": canonicalRoot, "persisted_roots": roots.all, "acquired": acquired,
                   "stream_starts": watcher?.streamStarts ?? 0, "pass_count": watcher?.passCount ?? 0])
        } catch {
            check("Add Folder \(name) registered harness", false, error.code)
        }
    }

    private func afterAcceptedOK() -> ContinuousClock.Instant {
        if !pickerEvents.contains("OK attempted") { pickerEvents.append("OK attempted") }
        if pickerFault == "late-ok", let deadline = pickerChoice?.deadline {
            pickerClockAdvance += pickerNow.duration(to: deadline) + .seconds(1)
            pickerEvents.append("clock advanced after accepted OK")
        }
        return pickerNow
    }

    @objc private func observeFolderPanel(_ timer: Timer) {
        guard let choice = pickerChoice else { return }
        guard pickerNow < choice.deadline else {
            if !pickerTimedOut { pickerEvents.append("picker deadline expired") }
            pickerTimedOut = true
            if let panel = pickerPanel {
                if let sheet = panel.attachedSheet {
                    panel.endSheet(sheet, returnCode: .cancel)
                    sheet.orderOut(nil)
                }
                panel.cancel(nil)
                if NSApp.modalWindow === panel { NSApp.abortModal() }
                if !panel.isVisible && panel.attachedSheet == nil { timer.invalidate() }
            }
            return
        }
        guard let panel = pickerPanel, panel.isVisible else { return }
        if !pickerEvents.contains("panel visible") { pickerEvents.append("panel visible") }
        if let kind = panel.accessoryView as? NSPopUpButton {
            pickerObserved = kind.itemTitles == ["OpenCode", "Codex"] && kind.titleOfSelectedItem == choice.name
        }
    }

    func panel(_ sender: Any, validate url: URL) throws {
        guard pickerFault == "refused-ok", let panel = sender as? NSOpenPanel, panel === pickerPanel else { return }
        pickerValidationRejections += 1
        pickerVisibleAtRejection = panel.isVisible
        pickerEvents.append("OK attempted")
        pickerEvents.append("URL validation rejected")
        if let deadline = pickerChoice?.deadline {
            pickerClockAdvance += pickerNow.duration(to: deadline) + .seconds(1)
        }
        pickerEvents.append("clock advanced after rejection")
        throw NSError(domain: "QuoternSelfTest", code: 1, userInfo: [NSLocalizedDescriptionKey: "Folder refused by the native picker test."])
    }

    private func waitUntil(deadline: ContinuousClock.Instant? = nil, timeout: Duration = .seconds(20), _ condition: @MainActor () -> Bool) async {
        let watchdog = ContinuousClock().now.advanced(by: timeout)
        while !condition(), ContinuousClock().now < watchdog, deadline.map({ pickerNow < $0 }) ?? true {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    private func savePNG(of view: NSView, to path: String) {
        do { try FileManager.default.createDirectory(atPath: options.out, withIntermediateDirectories: true) }
        catch { failOutput(error) }
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds),
              let context = NSGraphicsContext(bitmapImageRep: bitmap)
        else { failOutput(NSError(domain: "QuoternSelfTest.capture", code: 1)) }
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
        do {
            guard let png = bitmap.representation(using: .png, properties: [:]), !png.isEmpty else {
                failOutput(NSError(domain: "QuoternSelfTest.capture", code: 2))
            }
            try png.write(to: URL(fileURLWithPath: path), options: .atomic)
        } catch { failOutput(error) }
    }

    private func failOutput(_ error: Error) -> Never {
        FileHandle.standardError.write(Data("selftest output failed: \(error)\n".utf8))
        exit(1)
    }

    private func write(_ record: [String: Any]) {
        do { try FileManager.default.createDirectory(atPath: options.out, withIntermediateDirectories: true) }
        catch { failOutput(error) }
        do {
            let data = try JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: URL(fileURLWithPath: options.out + "/journey.json"), options: .atomic)
        } catch { failOutput(error) }
    }
}
