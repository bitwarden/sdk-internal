// swift-tools-version: 5.9
// Integration tests for the Swift bindings of the Bitwarden SDK.
//
// This package depends on the parent `BitwardenSdk` package via a local
// path dependency. The parent package brings in the prebuilt
// `BitwardenFFI.xcframework` (iOS only), so tests must target an iOS
// destination — typically run via `xcodebuild test -destination
// 'platform=iOS Simulator,...'`.

import PackageDescription

let package = Package(
    name: "IntegrationTests",
    platforms: [
        .iOS(.v13),
    ],
    dependencies: [
        .package(name: "BitwardenSdk", path: "..")
    ],
    targets: [
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                .product(name: "BitwardenSdk", package: "BitwardenSdk")
            ]
        )
    ]
)
