// swift-tools-version: 5.9
// End-to-end tests for the Swift bindings of the Bitwarden SDK.
//
// This package depends on the `BitwardenSdk` package in
// `crates/bitwarden-uniffi/swift` through the `BitwardenSdk` symlink. That package
// brings in the prebuilt `BitwardenFFI.xcframework` (iOS only), so tests must
// target an iOS destination — see `test.sh`.
//
// SwiftPM derives package identity from the directory name. Both directories
// are named `swift`; the symlink gives the dependency a distinct identity.

import PackageDescription

let package = Package(
    name: "E2ETests",
    platforms: [
        .iOS(.v13),
    ],
    dependencies: [
        .package(path: "BitwardenSdk")
    ],
    targets: [
        .testTarget(
            name: "E2ETests",
            dependencies: [
                .product(name: "BitwardenSdk", package: "BitwardenSdk")
            ]
        )
    ]
)
