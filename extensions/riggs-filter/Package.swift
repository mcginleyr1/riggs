// swift-tools-version: 5.9
import PackageDescription

// SwiftPM compiles everything here and runs the RiggsFilterCore tests
// (`swift test`). It cannot produce an installable system extension on its
// own: build.sh takes the two executables, assembles "Riggs Filter.app" with
// the extension embedded, and signs both with their entitlements.

let package = Package(
    name: "RiggsFilter",
    platforms: [.macOS(.v13)],
    targets: [
        // Pure logic (TLS SNI parsing, domain matching), unit-tested.
        .target(name: "RiggsFilterCore"),
        // The NEFilterDataProvider system extension.
        .executableTarget(name: "RiggsFilterExtension", dependencies: ["RiggsFilterCore"]),
        // The host app: activates the extension and enables the filter.
        .executableTarget(name: "RiggsFilterHost"),
        .testTarget(
            name: "RiggsFilterCoreTests",
            dependencies: ["RiggsFilterCore"],
            resources: [.copy("Fixtures")]  // ClientHellos captured from real clients
        ),
    ]
)
