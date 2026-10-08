// swift-tools-version: 6.0
import PackageDescription

// The Rust static library is linked only from the Cargo target-triple output
// (`.cargo/config.toml` build.target), never from `target/release`.
let archive = "\(Context.packageDirectory)/target/aarch64-apple-darwin/release/libquotern_ffi.a"

// `throws(BridgeError)` everywhere: a `catch` block sees the typed error.
let typedThrows: [SwiftSetting] = [.enableUpcomingFeature("FullTypedThrows")]

let package = Package(
    name: "Quotern",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "QuoternCore", targets: ["QuoternCore"]),
    ],
    targets: [
        .target(name: "CQuotern", path: "Sources/CQuotern"),
        .target(
            name: "QuoternCore",
            dependencies: ["CQuotern"],
            path: "Sources/QuoternCore",
            swiftSettings: typedThrows,
            // The native libraries are the staticlib's own list, from
            // `cargo rustc -p quotern-ffi --release --locked -- --print native-static-libs`
            // (observed `-lSystem -lc -lm`), in that order.
            linkerSettings: [
                .unsafeFlags([archive]),
                .linkedLibrary("System"),
                .linkedLibrary("c"),
                .linkedLibrary("m"),
            ]
        ),
        .testTarget(
            name: "QuoternCoreTests",
            dependencies: ["QuoternCore", "CQuotern"],
            path: "Tests/QuoternCoreTests",
            swiftSettings: typedThrows
        ),
    ],
    swiftLanguageModes: [.v6]
)
