import Combine
import Foundation

/// What the popover presents: the last good snapshot, the latest error and whether a call is
/// pending. The popover never waits on the bridge; it always shows the cached snapshot. Swift
/// never computes a total, a status or a window here: every number and status is Rust's.
@MainActor
public final class TodayModel: ObservableObject {
    /// What a failed call was for, so the error can say so.
    public enum Action: Sendable {
        case update, addFolder
    }

    /// The last good snapshot. A failure never replaces or clears it.
    @Published public private(set) var snapshot: TodaySnapshot?
    @Published public private(set) var error: BridgeError?
    @Published public private(set) var failedAction: Action = .update
    @Published public private(set) var pending = false
    /// There is no live engine handle: the launch open or a reopen failed.
    @Published public private(set) var engineClosed = false

    private let client: EngineClient
    /// The request zone, which the popover also displays times in.
    let zone: String
    let timeZone: TimeZone
    /// The present instant. Rows read their age against it, never against a past request.
    let nowMs: @MainActor () -> Int64
    /// Monotonic request id: a superseded result never replaces a newer one.
    private var latestRequest = 0

    public init(client: EngineClient, zone: String, nowMs: @escaping @MainActor () -> Int64) {
        self.client = client
        self.zone = zone
        // Rust refuses an unknown zone, so no snapshot is ever shown against this fallback.
        self.timeZone = TimeZone(identifier: zone) ?? .current
        self.nowMs = nowMs
    }

    /// An error only the user's Retry recovers: there is no live handle, the handle failed, or
    /// the response could not be trusted. No automatic call is made until then.
    public var awaitingRetry: Bool {
        if engineClosed { return true }
        guard let error else { return false }
        return error.requiresReopen || error == .malformedResponse
    }

    /// The status a value is shown with: Rust's, except while the model holds any error over the
    /// last good snapshot (DEC-076). Then the latest call failed, so a present value is an error,
    /// never current. Denied stays denied (consent precedes failure, as in Rust) and a null value
    /// stays unavailable. Freshness is never recomputed here.
    public func status(of observation: Observation) -> Observation.Status {
        guard error != nil, observation.value != nil, observation.status != .denied else { return observation.status }
        return .error
    }

    /// Opens the engine at launch. On failure the error is shown and only Retry opens it again.
    public func open(_ config: EngineConfig) async -> Bool {
        do throws(BridgeError) {
            try await client.open(config)
            return true
        } catch {
            engineClosed = true
            receiveFailure(error)
            return false
        }
    }

    /// One reconcile pass: ingest every enabled source, then read today's snapshot. After an
    /// ordinary ingest failure the snapshot is still read, so Rust judges freshness at this
    /// instant; the failure stays shown. A reopen-class failure is never followed by a call.
    public func reconcile() async {
        guard !awaitingRetry else { return }
        let request = begin()
        let now = nowMs()
        var ingestFailure: BridgeError?
        do {
            _ = try await client.ingest(nowMs: now)
        } catch {
            guard !(error.requiresReopen || error == .malformedResponse) else {
                receive(.failure(error), request: request)
                return
            }
            ingestFailure = error
        }
        await read(request: request, nowMs: now, holding: ingestFailure)
    }

    /// Reads today's snapshot without a pass.
    public func refresh() async {
        guard !awaitingRetry else { return }
        let request = begin()
        await read(request: request, nowMs: nowMs())
    }

    /// The user's Retry. Without a live handle, or after `engine_failed`, `internal_panic` or
    /// `malformed_response`, it reopens the engine once with the attempted config (the failed
    /// request is never re-sent on the old handle), then reads the snapshot on the new handle.
    /// Returns false when the reopen failed, so nothing else is sent to a closed engine.
    @discardableResult
    public func retry() async -> Bool {
        let request = begin()
        if awaitingRetry {
            do throws(BridgeError) {
                try await client.reopen()
            } catch {
                engineClosed = true
                receive(.failure(error), request: request)
                return false
            }
            engineClosed = false
            error = nil
        }
        await read(request: request, nowMs: nowMs())
        return true
    }

    func begin() -> Int {
        latestRequest += 1
        pending = true
        return latestRequest
    }

    private func read(request: Int, nowMs now: Int64, holding held: BridgeError? = nil) async {
        do {
            let snapshot = try await client.todaySnapshot(tz: zone, nowMs: now)
            receive(.success(snapshot), request: request, holding: held)
        } catch {
            receive(.failure(error), request: request)
        }
    }

    /// The result entry: a success replaces the snapshot and clears the error, or keeps `held`,
    /// the failure of the same pass; a failure keeps the last good snapshot, shows the error
    /// and substitutes nothing.
    func receive(_ result: Result<TodaySnapshot, BridgeError>, request: Int, holding held: BridgeError? = nil, action: Action = .update) {
        guard request == latestRequest else { return }
        pending = false
        switch result {
        case .success(let value):
            snapshot = value
            error = held
            failedAction = .update
        case .failure(let failure):
            error = failure
            failedAction = action
        }
    }

    /// Feeds a result into the entry as the latest request, as a bridge call would.
    func receiveLatest(_ result: Result<TodaySnapshot, BridgeError>, action: Action = .update) {
        receive(result, request: begin(), action: action)
    }

    /// A failure of a call the app made outside this model (list, selection).
    public func receiveFailure(_ error: BridgeError, action: Action = .update) {
        receiveLatest(.failure(error), action: action)
    }
}
