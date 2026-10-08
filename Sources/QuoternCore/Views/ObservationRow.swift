import AppKit
import SwiftUI

/// The words an observation is presented with, visible and to accessibility alike. They only
/// format what Rust returned; nothing here decides a status or a number.
public enum ObservationText {
    /// The product copy is English, so numbers and times are formatted in English too.
    static let locale = Locale(identifier: "en_US")

    public static func value(_ observation: Observation) -> String {
        guard let value = observation.value else { return "Unavailable" }
        return "\(value.formatted(.number.locale(locale))) \(observation.unit.rawValue)"
    }

    public static func provenance(_ observation: Observation) -> String? {
        switch observation.provenance {
        case .reported: "Reported"
        case .derived: "Derived"
        case nil: nil
        }
    }

    /// "Partial" when not every contributing record carried the value.
    static func completeness(_ observation: Observation) -> String? {
        observation.completeness == .partial ? "Partial" : nil
    }

    public static func status(_ status: Observation.Status) -> String {
        switch status {
        case .current: "Current"
        case .stale: "Stale"
        case .unavailable: "Unavailable"
        case .error: "Error"
        case .denied: "Denied"
        case .catchingUp: "Catching up"
        }
    }

    static func symbol(_ status: Observation.Status) -> String {
        switch status {
        case .current: "checkmark.circle"
        case .stale: "clock"
        case .unavailable: "minus.circle"
        case .error: "exclamationmark.triangle"
        case .denied: "hand.raised"
        case .catchingUp: "arrow.triangle.2.circlepath"
        }
    }

    /// "Never updated" without a success. A current value says how long ago, at the present
    /// instant; any other status shows the absolute last good time in `zone`, so the age never
    /// freezes while updates are blocked.
    public static func freshness(lastGoodMs: Int64?, status: Observation.Status, nowMs: Int64, zone: TimeZone) -> String {
        guard let lastGoodMs else { return "Never updated" }
        let age = nowMs - lastGoodMs
        guard status == .current, age >= 0 else {
            let date = Date(timeIntervalSince1970: TimeInterval(lastGoodMs) / 1_000)
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = zone
            let today = calendar.isDate(date, inSameDayAs: Date(timeIntervalSince1970: TimeInterval(nowMs) / 1_000))
            var style = Date.FormatStyle(date: today ? .omitted : .abbreviated, time: .shortened).locale(locale)
            style.timeZone = zone
            return "Updated at \(date.formatted(style))"
        }
        if age < 60_000 { return "Updated just now" }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        formatter.unitsStyle = .full
        return "Updated \(formatter.localizedString(fromTimeInterval: -TimeInterval(age / 1_000)))"
    }

    /// The accessibility value: the value with its unit, provenance, completeness, shown status
    /// and freshness.
    public static func accessibilityValue(_ observation: Observation, status shown: Observation.Status, nowMs: Int64, zone: TimeZone) -> String {
        var parts = [value(observation)]
        if let provenance = provenance(observation) { parts.append(provenance) }
        if let completeness = completeness(observation) { parts.append(completeness) }
        if observation.value != nil { parts.append(status(shown)) }
        parts.append(freshness(lastGoodMs: observation.lastGoodMs, status: shown, nowMs: nowMs, zone: zone))
        return parts.joined(separator: ", ")
    }
}

/// One numeric observation: its name, the value with unit, provenance, completeness and status.
/// Status is always a word beside its symbol, never colour alone. Every word is primary text;
/// the caption size carries the hierarchy, so it keeps its contrast on any background.
struct ObservationRow: View {
    let label: String
    /// The family the value belongs to, for accessibility, e.g. "OpenCode reported tokens".
    let family: String
    let observation: Observation
    /// The status shown, `TodayModel.status(of:)` of the observation.
    let status: Observation.Status
    let nowMs: Int64
    let zone: TimeZone

    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                Text(ObservationText.value(observation))
                    .monospacedDigit()
                Group {
                    if observation.value == nil {
                        // The value already says Unavailable; say what is missing instead.
                        Text("\(observation.unit.rawValue) · no data today")
                    } else {
                        HStack(spacing: 6) {
                            Text([ObservationText.provenance(observation), ObservationText.completeness(observation)].compactMap { $0 }.joined(separator: " · "))
                            // The word carries the status; the tinted symbol only reinforces it.
                            Label {
                                Text(ObservationText.status(status))
                            } icon: {
                                Image(systemName: ObservationText.symbol(status))
                                    .foregroundStyle(tint)
                            }
                        }
                    }
                }
                .font(.caption)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label), \(family)")
        .accessibilityValue(ObservationText.accessibilityValue(observation, status: status, nowMs: nowMs, zone: zone))
    }

    /// System colours, which resolve to their darker variants under increased contrast.
    private var tint: Color {
        switch status {
        case .current: Color(nsColor: .systemGreen)
        case .error: Color(nsColor: .systemRed)
        case .stale, .catchingUp: Color(nsColor: .systemOrange)
        case .unavailable, .denied: contrast == .increased ? .primary : Color(nsColor: .secondaryLabelColor)
        }
    }
}
