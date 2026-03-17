// swift-tools-version: 5.9
import PackageDescription

// NOTE: System Extensions cannot be built with SwiftPM alone.
// This Package.swift is provided for code editing / syntax checking.
// The actual build uses the Xcode project or xcodebuild via the Makefile.
// See docs/DLP_IMPLEMENTATION_PLAN.md for build instructions.

let package = Package(
    name: "RiggsFilter",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "RiggsFilter",
            path: "Sources"
        ),
    ]
)
