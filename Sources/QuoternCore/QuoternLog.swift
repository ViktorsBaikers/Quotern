import os

/// Bridge log: only fixed codes and operation names are ever written, never paths, labels or
/// source text. `captured` holds the same lines for tests, at most the 256 most recent.
public enum QuoternLog {
    static let capacity = 256
    private static let lines = OSAllocatedUnfairLock(initialState: [String]())

    public static func record(_ operation: String, code: String) {
        lines.withLock { lines in
            if lines.count == capacity { lines.removeFirst() }
            lines.append("\(operation) \(code)")
        }
    }

    public static var captured: [String] {
        lines.withLock { $0 }
    }

    public static func reset() {
        lines.withLock { $0.removeAll() }
    }
}
