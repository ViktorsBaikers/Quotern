import AppKit
import QuoternCore
import SwiftUI

/// The menu-bar item and its popover. Until a measured family exists the item shows its symbol
/// alone: reported values never enter the menu bar.
@MainActor
final class StatusItemController: NSObject {
    let statusItem: NSStatusItem
    let popover = NSPopover()

    init(model: TodayModel, actions: PopoverActions) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "chart.bar", accessibilityDescription: "Quotern")
            button.setAccessibilityLabel("Quotern")
            button.target = self
            button.action = #selector(toggle(_:))
        }
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: PopoverView(model: model, actions: actions))
        popover.contentSize = NSSize(width: PopoverView.width, height: 10)
    }

    @objc func toggle(_ sender: Any?) {
        if popover.isShown {
            popover.performClose(sender)
        } else if let button = statusItem.button {
            // An accessory app is not active on its own; activate it so the popover takes keys.
            NSApp.activate()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }
}
