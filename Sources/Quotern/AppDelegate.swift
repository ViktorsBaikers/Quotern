import AppKit
import QuoternCore

/// Harness kinds with an implemented adapter: the only kinds a chosen folder can be read as.
let implementedHarnesses: [(id: String, name: String)] = [("opencode", "OpenCode")]

func wallClockMs() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1_000).rounded(.down))
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let client = EngineClient()
    private lazy var model = TodayModel(client: client, zone: TimeZone.current.identifier, nowMs: { wallClockMs() })
    private let roots = WatchedRoots()
    private var watcher: SourceWatcher?
    private var statusItem: StatusItemController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let dataDirectory = productionDataDirectory
        let model = model
        watcher = SourceWatcher(
            clock: DispatchWatcherClock(),
            dataDirectory: dataDirectory,
            makeStream: FSEventsWatcherStream.make,
            pass: { await model.reconcile() }
        )
        statusItem = StatusItemController(model: model, actions: PopoverActions(
            refresh: { [weak self] in self?.refresh() },
            addFolder: { [weak self] in self?.addFolder() },
            retry: { [weak self] in self?.retry() },
            quit: { NSApp.terminate(nil) }
        ))
        Task {
            if await model.open(EngineConfig(dataDir: dataDirectory, home: NSHomeDirectory())) {
                await applySources()
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        watcher?.update(enabled: false, roots: [])
    }

    /// Launch and enable: the watcher passes only while a source is enabled; without one the
    /// popover shows the empty first run.
    private func applySources() async {
        let enabled: Bool
        do {
            enabled = try await client.listSources().contains { $0.consent == "enabled" }
        } catch {
            model.receiveFailure(error)
            return
        }
        watcher?.update(enabled: enabled, roots: roots.all)
        if !enabled { await model.refresh() }
    }

    private func refresh() {
        if let watcher, watcher.timerActive {
            watcher.refresh()
        } else {
            Task { await model.refresh() }
        }
    }

    /// Sources are applied again only once the engine is open; a failed reopen leaves its error.
    private func retry() {
        Task {
            if await model.retry() {
                await applySources()
            }
        }
    }

    /// Explicit folder selection, offering only harness kinds with an implemented adapter.
    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a folder for Quotern to read. Only usage numbers are read."
        panel.prompt = "Read Folder"
        let kind = NSPopUpButton()
        kind.addItems(withTitles: implementedHarnesses.map(\.name))
        kind.setAccessibilityLabel("Harness")
        kind.sizeToFit()
        panel.accessoryView = kind
        panel.isAccessoryViewDisclosed = true
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let harness = implementedHarnesses[max(0, kind.indexOfSelectedItem)].id
        let root = url.path
        Task {
            do throws(BridgeError) {
                _ = try await client.setSourceSelection(SourceSelection(harness: harness, root: root, selected: true))
            } catch {
                model.receiveFailure(error, action: .addFolder)
                return
            }
            roots.add(root)
            await applySources()
        }
    }
}
