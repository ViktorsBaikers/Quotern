import Foundation

/// Error of the bridge: a fixed Rust code, or one of the two client-only codes.
public struct BridgeError: Error, Equatable, Sendable {
    public let code: String
    public let message: String
    public let retryable: Bool

    public init(code: String, message: String, retryable: Bool) {
        self.code = code
        self.message = message
        self.retryable = retryable
    }

    /// The recovery is `reopen()`; the failed request is never re-sent on the old handle.
    public var requiresReopen: Bool {
        !retryable && (code == "engine_failed" || code == "internal_panic")
    }

    public static let abiMismatch = BridgeError(code: "abi_mismatch", message: "incompatible engine", retryable: false)
    public static let malformedResponse = BridgeError(code: "malformed_response", message: "malformed response", retryable: false)
}

/// The fixed code table of the Rust side. A code outside it is a malformed response.
let rustErrorCodes: Set<String> = [
    "invalid_request", "unknown_method", "limit_exceeded", "cancelled", "source_unavailable",
    "store_busy", "store_corrupt", "store_newer_version", "store_migration_failed",
    "internal_panic", "engine_failed", "source_overlap_conflict",
]

public struct EngineConfig: Codable, Equatable, Sendable {
    public var dataDir: String
    public var home: String
    public init(dataDir: String, home: String) {
        self.dataDir = dataDir
        self.home = home
    }
}

public struct SourceSelection: Codable, Equatable, Sendable {
    public var harness: String
    public var root: String
    public var selected: Bool
    public init(harness: String, root: String, selected: Bool) {
        self.harness = harness
        self.root = root
        self.selected = selected
    }
}

public struct Observation: Codable, Equatable, Sendable {
    public let value: UInt64?
    public let unit: String
    public let provenance: String?
    public let status: String
}

public struct SourceReported: Codable, Equatable, Sendable {
    public let sourceId: String
    public let records: UInt64
    public let input: Observation
    public let output: Observation
    public let reasoning: Observation
    public let cacheRead: Observation
    public let cacheWrite: Observation
    public let total: Observation
    public let sourceConvention: String?
    public let acquisitionConsistency: String?
    public let originUncertainty: String
    public let totalMismatch: Bool
    public let mirrorConflict: Bool
    public let pendingPartial: Bool
}

public struct SourceEntry: Codable, Equatable, Sendable {
    public let sourceId: String
    public let harness: String
    public let rootDisplay: String
    public let kind: String
    public let consent: String
    public let outcome: String?
    public let lastAttemptMs: Int64?
    public let lastSuccessMs: Int64?
    public let lastErrorCode: String?
    public let rejectedCount: UInt32
    public let pendingPartial: Bool
}

public struct SourceList: Codable, Equatable, Sendable {
    public let sources: [SourceEntry]
}

public struct Window: Codable, Equatable, Sendable {
    public let startMs: Int64
    public let endMs: Int64
    public let tz: String
}

public struct TodaySnapshot: Codable, Equatable, Sendable {
    public let window: Window
    public let bySource: [SourceEntry]
    public let sourceReported: [SourceReported]
}

struct OpenData: Codable, Equatable, Sendable {
    let abiVersion: UInt32
}

struct EmptyRequest: Encodable {}
struct IngestRequest: Encodable { let nowMs: Int64 }
struct TodayRequest: Encodable { let tz: String; let nowMs: Int64 }

private struct DataEnvelope<T: Decodable>: Decodable {
    let data: T
}

enum Envelope {
    private static func isBool(_ value: Any) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    /// Decodes a Rust envelope into `T`, or the Rust error it carries. Every deviation from the
    /// v1 envelope shape, or from `T`, is `malformed_response`; nothing is defaulted or coerced.
    static func decode<T: Decodable>(_ bytes: [UInt8], as type: T.Type) throws(BridgeError) -> T {
        var data = Data(bytes)
        guard String(bytes: bytes, encoding: .utf8) != nil else { throw .malformedResponse }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw .malformedResponse
        }
        // `v` is the integer 1: a bool, a float such as 1.0 or 1e0, or any other value is not v1.
        guard let versionNumber = object["v"] as? NSNumber, !isBool(versionNumber),
              !CFNumberIsFloatType(versionNumber), versionNumber.stringValue == "1"
        else {
            throw .malformedResponse
        }
        guard let ok = object["ok"], isBool(ok), let isOk = ok as? Bool else { throw .malformedResponse }
        if isOk {
            guard object["data"] != nil, object["error"] == nil else { throw .malformedResponse }
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            do {
                data = Data(bytes)
                return try decoder.decode(DataEnvelope<T>.self, from: data).data
            } catch {
                throw .malformedResponse
            }
        }
        guard object["data"] == nil, let error = object["error"] as? [String: Any] else { throw .malformedResponse }
        guard let code = error["code"] as? String, rustErrorCodes.contains(code),
              let message = error["message"] as? String,
              let retryable = error["retryable"], isBool(retryable), let isRetryable = retryable as? Bool
        else { throw .malformedResponse }
        throw BridgeError(code: code, message: message, retryable: isRetryable)
    }
}
