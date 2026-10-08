import AppKit
import Darwin
import MachO
import QuoternCore
import SwiftUI

/// `--selftest-startup`: launches the app over an isolated data directory (never the production
/// one), opens the engine, builds the popover's hosting view in a window and writes
/// `<out>/startup.json`:
/// `{"appkit_hosting_view": bool, "tcp_listeners": int, "forbidden_images": [name], "startup_ms": int}`.
/// It exits 0 once the file is written; it writes nothing and exits 1 when a fact cannot be
/// measured.
@MainActor
final class SelfTestStartup: NSObject, NSApplicationDelegate {
    private let options: SelfTestArguments.Startup
    private var window: NSWindow?

    init(options: SelfTestArguments.Startup) {
        self.options = options
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { exit(await run()) }
    }

    private func fail(_ reason: String) -> Int32 {
        FileHandle.standardError.write(Data("selftest-startup failed: \(reason)\n".utf8))
        return 1
    }

    private func run() async -> Int32 {
        guard let started = processStartMs() else { return fail("process start time unavailable") }
        let home = options.out + "/home"
        do {
            try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        } catch {
            return fail("cannot create \(options.out)")
        }
        let client = EngineClient()
        let model = TodayModel(client: client, zone: TimeZone.current.identifier, nowMs: { wallClockMs() })
        guard await model.open(EngineConfig(dataDir: options.dataDirectory, home: home)) else {
            return fail("engine open: \(model.error?.code ?? "unknown")")
        }
        await model.refresh()

        let view = NSHostingView(rootView: PopoverView(model: model, actions: PopoverActions(refresh: {}, addFolder: {}, retry: {}, quit: {})))
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: PopoverView.width, height: view.fittingSize.height),
            styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = view
        window.orderFrontRegardless()
        view.layoutSubtreeIfNeeded()
        window.display()
        self.window = window
        let startupMs = wallClockMs() - started

        let listeners = tcpListeners()
        guard listeners >= 0 else { return fail("socket table unavailable") }
        let record: [String: Any] = [
            "appkit_hosting_view": viewClasses(view).contains { $0.contains("NSHostingView") },
            "tcp_listeners": listeners,
            "forbidden_images": forbiddenImages(),
            "startup_ms": startupMs,
        ]
        window.orderOut(nil)
        await client.close()
        guard let data = try? JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys]),
              (try? data.write(to: URL(fileURLWithPath: options.out + "/startup.json"))) != nil
        else { return fail("cannot write startup.json") }
        return 0
    }

    /// The wall-clock instant this process started, from the kernel's process table.
    private func processStartMs() -> Int64? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return Int64(info.pbi_start_tvsec) * 1_000 + Int64(info.pbi_start_tvusec) / 1_000
    }
}

// MARK: - Runtime facts of this process, shared with the journey

/// The class names of a view and all its descendants.
@MainActor
func viewClasses(_ view: NSView) -> [String] {
    [String(describing: type(of: view))] + view.subviews.flatMap(viewClasses)
}

/// Loaded dyld images that are a web, JavaScript, Electron, Node, Bun or Python runtime. A runtime
/// is identified by its image name (lib prefix and extension removed), not by any substring:
/// libunwind is not Bun.
func forbiddenImages() -> [String] {
    let images = (0..<_dyld_image_count()).compactMap { _dyld_get_image_name($0).map { String(cString: $0) } }
    return images.compactMap { path in
        let file = (path as NSString).lastPathComponent
        var name = (file as NSString).deletingPathExtension.lowercased()
        if name.hasPrefix("lib") { name.removeFirst(3) }
        let forbidden = ["webkit", "javascriptcore", "electron", "chromium", "node", "bun", "python"].contains { name.hasPrefix($0) }
        return forbidden ? file : nil
    }
}

/// TCP sockets of this process in LISTEN state, through libproc; -1 if the table is unreadable.
func tcpListeners() -> Int {
    let pid = getpid()
    let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard size > 0 else { return -1 }
    let count = Int(size) / MemoryLayout<proc_fdinfo>.stride
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
    let filled = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
    guard filled > 0 else { return -1 }
    var listening = 0
    for fd in fds.prefix(Int(filled) / MemoryLayout<proc_fdinfo>.stride) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
        var info = socket_fdinfo()
        let got = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.stride))
        if got == Int32(MemoryLayout<socket_fdinfo>.stride), info.psi.soi_kind == SOCKINFO_TCP,
           info.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN {
            listening += 1
        }
    }
    return listening
}
