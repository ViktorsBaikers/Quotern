import Foundation

/// The production data directory, `~/Library/Application Support/Quotern`. Self-tests refuse it.
public var productionDataDirectory: String {
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    return support.appendingPathComponent("Quotern", isDirectory: true).path
}

public struct SelfTestRefusal: Error, Equatable, Sendable {
    public let reason: String
    init(_ reason: String) { self.reason = reason }
}

/// A self-test command line. Each mode runs over an explicit data directory and refuses the
/// production one, any directory inside it and any directory containing it.
public enum SelfTestArguments: Equatable, Sendable {
    /// `--selftest-journey`: the real status item, popover, watcher and engine over a fixture home.
    case journey(Journey)
    /// `--selftest-startup`: the real popover built at launch, with the process's runtime facts.
    case startup(Startup)

    public struct Journey: Equatable, Sendable {
        public let home: String
        public let dataDirectory: String
        public let nowMs: Int64
        public let phase: String
        public let out: String
    }

    public struct Startup: Equatable, Sendable {
        public let dataDirectory: String
        public let out: String
    }

    public static let journeyUsage = "usage: Quotern --selftest-journey --selftest-home <dir> --data-dir <dir> --now <ISO-8601> --phase first|restart --out <dir>"
    public static let startupUsage = "usage: Quotern --selftest-startup --data-dir <dir> --out <dir>"

    /// The parsed self-test, why it is refused, or nil when the arguments name no self-test.
    public static func parse(_ arguments: [String], production: String = productionDataDirectory) -> Result<Self, SelfTestRefusal>? {
        guard let modeIndex = arguments.firstIndex(where: { $0.hasPrefix("--selftest") }) else { return nil }
        let mode = arguments[modeIndex]
        let allowed: [String]
        switch mode {
        case "--selftest-journey": allowed = ["--selftest-home", "--data-dir", "--now", "--phase", "--out"]
        case "--selftest-startup": allowed = ["--data-dir", "--out"]
        default: return .failure(.init("\(journeyUsage)\n\(startupUsage)"))
        }
        var values: [String: String] = [:]
        var index = modeIndex + 1
        while index < arguments.count {
            let key = arguments[index]
            guard allowed.contains(key), index + 1 < arguments.count else {
                return .failure(.init("unknown or incomplete argument \(key)"))
            }
            values[key] = arguments[index + 1]
            index += 2
        }
        func absolute(_ key: String) -> String? {
            values[key].map { URL(fileURLWithPath: $0).standardizedFileURL.resolvingSymlinksInPath().path }
        }
        guard let dataDirectory = absolute("--data-dir") else { return .failure(.init("--data-dir is required")) }
        if overlaps(dataDirectory, production) {
            return .failure(.init("refusing the production data directory"))
        }
        if mode == "--selftest-startup" {
            guard let out = absolute("--out") else { return .failure(.init(startupUsage)) }
            return .success(.startup(Startup(dataDirectory: dataDirectory, out: out)))
        }
        guard let home = absolute("--selftest-home"), let out = absolute("--out"),
              let nowText = values["--now"], let now = try? Date(nowText, strategy: .iso8601),
              let phase = values["--phase"], ["first", "restart"].contains(phase)
        else { return .failure(.init(journeyUsage)) }
        return .success(.journey(Journey(
            home: home, dataDirectory: dataDirectory,
            nowMs: Int64((now.timeIntervalSince1970 * 1_000).rounded()), phase: phase, out: out)))
    }

    /// Whether one directory is the other or contains it, compared by whole path components after
    /// resolving symlinks, so `/` contains everything and `Quotern-other` is not `Quotern`.
    static func overlaps(_ path: String, _ production: String) -> Bool {
        let a = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().pathComponents
        let b = URL(fileURLWithPath: production).standardizedFileURL.resolvingSymlinksInPath().pathComponents
        return a.starts(with: b) || b.starts(with: a)
    }
}
