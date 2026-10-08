import CQuotern
import Dispatch
import Foundation
import os

/// Allocation, free and call counters of the bridge, for tests. They count only in DEBUG
/// builds and never record a path, label or source text.
final class FFICounters: Sendable {
    struct Counts: Equatable {
        var entries = 0
        var frees = 0
        var tokensNew = 0
        var tokensFree = 0
        var handlesOpened = 0
        var handlesClosed = 0
        var openCalls = 0
        var calls = 0
    }

    static let shared = FFICounters()
    private let counts = OSAllocatedUnfairLock(initialState: Counts())

    var current: Counts { counts.withLock { $0 } }

    private func bump(_ change: @Sendable (inout Counts) -> Void) {
        #if DEBUG
        counts.withLock { change(&$0) }
        #endif
    }

    func entry() { bump { $0.entries += 1 } }
    func freed() { bump { $0.frees += 1 } }
    func tokenNew() { bump { $0.tokensNew += 1 } }
    func tokenFree() { bump { $0.tokensFree += 1 } }
    func handleOpened() { bump { $0.handlesOpened += 1 } }
    func handleClosed() { bump { $0.handlesClosed += 1 } }
    func openCall() { bump { $0.openCalls += 1 } }
    func call() { bump { $0.calls += 1 } }
}

/// The open engine handle, held only as `EngineClient`'s actor-isolated state. Releasing it
/// closes the engine exactly once, so a client dropped without `close()` never leaks its handle
/// or its data-directory owner claim.
private final class EngineHandle {
    let pointer: OpaquePointer

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
        FFICounters.shared.handleOpened()
    }

    deinit {
        quotern_engine_close(pointer)
        FFICounters.shared.handleClosed()
    }
}

/// The Swift side of bridge v1. An actor on a private serial queue: the raw engine pointer is
/// actor-isolated state that never leaves it, so no two calls overlap and `close` never runs
/// during a call. Swift never filters, re-windows or sums what Rust returns.
public actor EngineClient {
    private let queue = DispatchSerialQueue(label: "app.quotern.engine")
    public nonisolated var unownedExecutor: UnownedSerialExecutor { queue.asUnownedSerialExecutor() }

    private var handle: EngineHandle?
    private var config: EngineConfig?
    private let abiVersion: @Sendable () -> UInt32

    public init() {
        self.init(abiVersion: { quotern_abi_version() })
    }

    /// Test seam for the version gate only.
    init(abiVersion: @escaping @Sendable () -> UInt32) {
        self.abiVersion = abiVersion
    }

    // MARK: Lifecycle

    /// Opens the engine. The config is kept even when the open fails, so `reopen()` can retry it.
    public func open(_ config: EngineConfig) async throws(BridgeError) {
        self.config = config
        try openEngine(Self.encode(config))
    }

    /// Opens a new handle from `request`. A NULL request (no earlier open, so no config) is
    /// refused by Rust itself; Swift invents no error.
    private func openEngine(_ request: String?) throws(BridgeError) {
        close()
        guard abiVersion() == 1 else {
            QuoternLog.record("open", code: BridgeError.abiMismatch.code)
            throw .abiMismatch
        }
        var out: OpaquePointer?
        FFICounters.shared.openCall()
        let raw = if let request {
            request.withCString { quotern_engine_open($0, &out) }
        } else {
            quotern_engine_open(nil, &out)
        }
        let data: OpenData
        do {
            data = try Self.copyFreeDecode(raw, as: OpenData.self)
        } catch {
            if let out { quotern_engine_close(out) }
            QuoternLog.record("open", code: error.code)
            throw error
        }
        guard let opened = out else {
            QuoternLog.record("open", code: BridgeError.malformedResponse.code)
            throw .malformedResponse
        }
        guard data.abiVersion == 1 else {
            quotern_engine_close(opened)
            QuoternLog.record("open", code: BridgeError.abiMismatch.code)
            throw .abiMismatch
        }
        handle = EngineHandle(opened)
        QuoternLog.record("open", code: "ok")
    }

    /// Closes the handle if there is one. There is no call in flight: the actor serializes.
    public func close() {
        handle = nil
    }

    /// Close then open with the last attempted config; the recovery for `engine_failed`,
    /// `internal_panic` and a failed open.
    public func reopen() async throws(BridgeError) {
        try openEngine(config.map { Self.encode($0) })
    }

    // MARK: Methods

    public func setSourceSelection(_ selection: SourceSelection) async throws(BridgeError) -> [SourceEntry] {
        try await call("set_source_selection", Self.encode(selection), as: SourceList.self).sources
    }

    public func listSources() async throws(BridgeError) -> [SourceEntry] {
        try await call("list_sources", "{}", as: SourceList.self).sources
    }

    public func ingest(nowMs: Int64) async throws(BridgeError) -> [SourceEntry] {
        try await call("ingest", Self.encode(IngestRequest(nowMs: nowMs)), as: SourceList.self).sources
    }

    public func todaySnapshot(tz: String, nowMs: Int64) async throws(BridgeError) -> TodaySnapshot {
        try await call("today_snapshot", Self.encode(TodayRequest(tz: tz, nowMs: nowMs)), as: TodaySnapshot.self)
    }

    // MARK: Primitives

    /// One bridge call. A cancelled task triggers the call's token; the token and the handle
    /// outlive the call. Without a handle Rust receives a NULL engine and refuses it; Swift
    /// invents no error.
    func call<T: Decodable & Sendable>(
        _ method: String, _ request: String, as type: T.Type
    ) async throws(BridgeError) -> T {
        let engine = handle
        let token = FFICancelToken()
        let outcome: Result<T, BridgeError> = await withTaskCancellationHandler {
            withExtendedLifetime((token, engine)) {
                FFICounters.shared.call()
                let raw = method.withCString { methodText in
                    request.withCString { requestText in
                        quotern_call(engine?.pointer, methodText, requestText, token.pointer)
                    }
                }
                do throws(BridgeError) {
                    return .success(try Self.copyFreeDecode(raw, as: type))
                } catch {
                    return .failure(error)
                }
            }
        } onCancel: {
            token.trigger()
        }
        switch outcome {
        case .success(let value):
            QuoternLog.record(method, code: "ok")
            return value
        case .failure(let error):
            QuoternLog.record(method, code: error.code)
            throw error
        }
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()

    /// Encodes one of the request DTOs. They hold only strings, integers and bools, which
    /// `JSONEncoder` always encodes to UTF-8, so a failure is a broken invariant, not an input.
    static func encode<T: Encodable>(_ value: T) -> String {
        do {
            return String(decoding: try encoder.encode(value), as: UTF8.self)
        } catch {
            preconditionFailure("request DTO did not encode: \(error)")
        }
    }

    /// The only place a Rust string is read and the only place it is freed: the bytes are copied,
    /// the string is freed exactly once, and only then are the copied bytes decoded.
    static func copyFreeDecode<T: Decodable>(
        _ raw: UnsafeMutablePointer<CChar>?, as type: T.Type
    ) throws(BridgeError) -> T {
        guard let raw else { throw .malformedResponse }
        FFICounters.shared.entry()
        let length = strlen(raw)
        let bytes = Array(UnsafeBufferPointer(start: UnsafeRawPointer(raw).assumingMemoryBound(to: UInt8.self), count: length))
        quotern_string_free(raw)
        FFICounters.shared.freed()
        return try Envelope.decode(bytes, as: type)
    }
}
