import CQuotern

/// The single `@unchecked Sendable` type of the bridge.
///
/// Invariant: `pointer` is immutable after init and comes from `quotern_cancel_new`. The only
/// operations are `trigger()` (a thread-safe atomic store in Rust) and `deinit`, which frees the
/// token once. `EngineClient` wraps every call in `withExtendedLifetime(token)`, so the free can
/// never precede the call's return.
public final class FFICancelToken: @unchecked Sendable {
    let pointer: OpaquePointer

    public init() {
        guard let created = quotern_cancel_new() else { fatalError("quotern_cancel_new returned NULL") }
        pointer = created
        FFICounters.shared.tokenNew()
    }

    public func trigger() {
        quotern_cancel_trigger(pointer)
    }

    deinit {
        quotern_cancel_free(pointer)
        FFICounters.shared.tokenFree()
    }
}
