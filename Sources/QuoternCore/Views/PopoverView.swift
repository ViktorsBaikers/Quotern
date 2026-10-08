import AppKit
import SwiftUI

/// The popover's actions, supplied by the app.
public struct PopoverActions {
    public var refresh: @MainActor () -> Void
    public var addFolder: @MainActor () -> Void
    public var retry: @MainActor () -> Void
    public var quit: @MainActor () -> Void

    public init(
        refresh: @escaping @MainActor () -> Void,
        addFolder: @escaping @MainActor () -> Void,
        retry: @escaping @MainActor () -> Void,
        quit: @escaping @MainActor () -> Void
    ) {
        self.refresh = refresh
        self.addFolder = addFolder
        self.retry = retry
        self.quit = quit
    }
}

/// Today's popover: the last good snapshot with each observation's unit, provenance, status and
/// freshness; loading, empty first run, error with its next step, and a pending refresh over
/// cached data.
public struct PopoverView: View {
    public static let width: CGFloat = 360

    @ObservedObject var model: TodayModel
    let actions: PopoverActions
    /// The tallest the source list grows before it scrolls, so the actions stay on screen.
    var maxListHeight: CGFloat = max(240, (NSScreen.main?.visibleFrame.height ?? 800) - 240)

    public init(model: TodayModel, actions: PopoverActions) {
        self.model = model
        self.actions = actions
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let error = model.error {
                ErrorBanner(
                    error: error, action: model.failedAction, awaitingRetry: model.awaitingRetry,
                    showsLastGood: model.snapshot != nil, retry: actions.retry)
            }
            content
            Divider()
            HStack {
                // The empty first run offers its one action in its body instead.
                if !isEmptyFirstRun {
                    Button("Refresh", action: actions.refresh)
                        .keyboardShortcut("r")
                        .disabled(isLoading || model.pending || model.awaitingRetry)
                    Button("Add folder…", action: actions.addFolder)
                        .disabled(isLoading || model.awaitingRetry)
                }
                Spacer()
                Button("Quit Quotern", action: actions.quit)
                    .keyboardShortcut("q")
            }
        }
        .padding(16)
        .frame(width: Self.width, alignment: .leading)
        .onChange(of: model.error) { _, error in
            if let error { announce(ErrorText.headline(error, action: model.failedAction)) }
        }
        .onChange(of: model.pending) { wasPending, pending in
            if wasPending, !pending, model.error == nil { announce("Today's usage updated.") }
        }
    }

    private func announce(_ text: String) {
        AccessibilityNotification.Announcement(text).post()
    }

    private var isLoading: Bool {
        model.snapshot == nil && model.error == nil
    }

    private var isEmptyFirstRun: Bool {
        model.snapshot?.bySource.isEmpty == true
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Today")
                .font(.headline)
            Spacer()
            if model.pending {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Refreshing…")
                }
                .font(.caption)
                .accessibilityElement(children: .combine)
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        if let snapshot = model.snapshot {
            if snapshot.bySource.isEmpty {
                EmptyFirstRun(addFolder: actions.addFolder, isDefault: model.error == nil, disabled: model.awaitingRetry)
            } else {
                ScrollView {
                    // Ages are read against the present instant, re-read each minute while shown.
                    TimelineView(.everyMinute) { _ in
                        let now = model.nowMs()
                        VStack(alignment: .leading, spacing: 16) {
                            ForEach(snapshot.sourceReported, id: \.sourceId) { reported in
                                SourceSection(
                                    entry: snapshot.bySource.first { $0.sourceId == reported.sourceId },
                                    reported: reported,
                                    namesFolderInRows: snapshot.sourceReported.count > 1,
                                    nowMs: now,
                                    zone: model.timeZone,
                                    status: model.status(of:)
                                )
                            }
                        }
                    }
                }
                .scrollBounceBehavior(.basedOnSize)
                .frame(maxHeight: maxListHeight)
                .fixedSize(horizontal: false, vertical: true)
            }
        } else if model.error == nil {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Loading today's usage…")
            }
            .accessibilityElement(children: .combine)
        }
    }
}

private struct SourceSection: View {
    let entry: SourceEntry?
    let reported: SourceReported
    /// Several sections share a family name, so each row also names its folder.
    let namesFolderInRows: Bool
    let nowMs: Int64
    let zone: TimeZone
    let status: (Observation) -> Observation.Status

    private var title: String {
        "\(Self.harnessName(entry?.harness)) reported tokens"
    }

    private var folder: String {
        entry?.rootDisplay ?? reported.sourceId
    }

    static func harnessName(_ harness: String?) -> String {
        switch harness {
        case "opencode": "OpenCode"
        case let other?: other
        case nil: "Source"
        }
    }

    /// Why the section is not current, from Rust's source state.
    private var note: String? {
        if entry?.consent == "denied" { return "Reading this folder is turned off." }
        if entry?.lastErrorCode != nil { return "Last read failed. Refresh to try again." }
        if reported.total.status == .catchingUp { return "Reading earlier activity; totals may rise." }
        return nil
    }

    var body: some View {
        let family = namesFolderInRows ? "\(title) in \(folder)" : title
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .accessibilityLabel("\(title), \(folder)")
                    .accessibilityAddTraits(.isHeader)
                Text(folder)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(folder)
                    // Read in full through the header label.
                    .accessibilityHidden(true)
                HStack(spacing: 6) {
                    if reported.originUncertainty == "unverified_origin" {
                        Text("Origin unverified")
                        Text("·").accessibilityHidden(true)
                    }
                    Text(ObservationText.freshness(lastGoodMs: reported.total.lastGoodMs, status: status(reported.total), nowMs: nowMs, zone: zone))
                }
                .font(.caption)
                if let note {
                    Text(note)
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            row("Total", reported.total, family)
            Divider()
            row("Input", reported.input, family)
            row("Output", reported.output, family)
            row("Reasoning", reported.reasoning, family)
            row("Cache read", reported.cacheRead, family)
            row("Cache write", reported.cacheWrite, family)
        }
    }

    private func row(_ label: String, _ observation: Observation, _ family: String) -> ObservationRow {
        ObservationRow(label: label, family: family, observation: observation, status: status(observation), nowMs: nowMs, zone: zone)
    }
}

private struct EmptyFirstRun: View {
    let addFolder: @MainActor () -> Void
    /// Return chooses a folder, unless an error's Retry is the default.
    let isDefault: Bool
    let disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No sources selected")
                .font(.subheadline.weight(.semibold))
            Text("Choose a folder for Quotern to read. Nothing is read until you choose one.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Add folder…", action: addFolder)
                .keyboardShortcut(isDefault ? .defaultAction : nil)
                .disabled(disabled)
        }
    }
}

/// Plain words for each error code: what happened and what to do next. The engine's own message
/// is never shown.
enum ErrorText {
    static func summary(_ code: String) -> String {
        switch code {
        case "engine_failed": "the engine stopped"
        case "internal_panic": "the engine stopped unexpectedly"
        case "malformed_response": "the engine's response couldn't be read"
        case "store_busy": "usage history is busy"
        case "cancelled": "the update was cancelled"
        case "source_unavailable": "a chosen folder can't be read"
        case "limit_exceeded": "a request was larger than Quotern allows"
        case "invalid_request", "unknown_method": "the engine refused Quotern's request"
        case "store_corrupt": "usage history is damaged"
        case "store_newer_version": "usage history was written by a newer Quotern"
        case "store_migration_failed": "usage history couldn't be upgraded"
        case "source_overlap_conflict": "this folder overlaps one already chosen"
        case "abi_mismatch": "the engine doesn't match this app"
        default: "something unexpected went wrong"
        }
    }

    static func nextStep(_ code: String, action: TodayModel.Action) -> String {
        switch code {
        case "engine_failed", "internal_panic", "malformed_response": "Retry restarts the engine."
        case "store_busy": "Quit any other copy of Quotern, then Retry."
        case "cancelled": "Retry to try again."
        case "source_unavailable": "Check that the folder still exists, then Refresh."
        case "invalid_request", "unknown_method", "limit_exceeded":
            action == .addFolder ? "Choose another folder." : "Quit and reopen Quotern."
        case "store_corrupt": "Quit Quotern and move ~/Library/Application Support/Quotern aside to start a new history. Nothing is deleted automatically."
        case "store_newer_version": "Update Quotern to read it."
        case "store_migration_failed": "Quit and reopen Quotern to try the upgrade again."
        case "source_overlap_conflict": "Choose a folder that is neither inside nor around one already chosen."
        case "abi_mismatch": "Reinstall Quotern."
        default: "Quit and reopen Quotern."
        }
    }

    static func headline(_ error: BridgeError, action: TodayModel.Action) -> String {
        "\(action == .addFolder ? "Couldn't add folder" : "Couldn't update"): \(summary(error.code))."
    }
}

private struct ErrorBanner: View {
    let error: BridgeError
    let action: TodayModel.Action
    let awaitingRetry: Bool
    let showsLastGood: Bool
    let retry: @MainActor () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(Color(nsColor: .systemRed))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(ErrorText.headline(error, action: action))
                Text(ErrorText.nextStep(error.code, action: action))
                    .font(.caption)
                if showsLastGood {
                    Text("Showing the last good data.")
                        .font(.caption)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if awaitingRetry || error.retryable {
                Button("Retry", action: retry)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .accessibilityElement(children: .contain)
    }
}

/// One element of a rendered view's accessibility tree, as an assistive client reads it.
public struct AccessibleText: Equatable, Sendable {
    public let label: String
    public let value: String
    /// Whether the element can be activated; false for a disabled control.
    public let enabled: Bool
}

/// Reads the accessibility tree of a view in a laid-out window, for tests and the self-tests
/// only. SwiftUI builds its tree lazily for assistive clients, so this asks for it the way one
/// does (`AXEnhancedUserInterface` on the application) before reading.
@MainActor
public enum AccessibilityTree {
    public static func texts(of view: NSView) -> [AccessibleText] {
        NSApp.accessibilitySetValue(true, forAttribute: NSAccessibility.Attribute(rawValue: "AXEnhancedUserInterface"))
        view.layoutSubtreeIfNeeded()
        var texts: [AccessibleText] = []
        collect(view, into: &texts)
        return texts
    }

    private static func string(_ object: NSObject, _ name: String) -> String? {
        let selector = NSSelectorFromString(name)
        guard object.responds(to: selector) else { return nil }
        return object.perform(selector)?.takeUnretainedValue() as? String
    }

    private static func collect(_ element: Any, into texts: inout [AccessibleText]) {
        guard let object = element as? NSObject else { return }
        let label = string(object, "accessibilityLabel") ?? ""
        // SwiftUI exposes `.accessibilityValue(_:)` text as the value description.
        let value = string(object, "accessibilityValueDescription") ?? string(object, "accessibilityValue") ?? ""
        let enabled = object.responds(to: NSSelectorFromString("isAccessibilityEnabled"))
            ? object.value(forKey: "accessibilityEnabled") as? Bool ?? true : true
        if !label.isEmpty || !value.isEmpty { texts.append(AccessibleText(label: label, value: value, enabled: enabled)) }
        let selector = NSSelectorFromString("accessibilityChildren")
        guard object.responds(to: selector), let children = object.perform(selector)?.takeUnretainedValue() as? [Any] else { return }
        for child in children { collect(child, into: &texts) }
    }
}
