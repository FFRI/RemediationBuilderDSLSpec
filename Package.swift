// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RemediationBuilder",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "RemediationBuilder",
            targets: ["RemediationBuilder"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "RemediationBuilder"
        ),
    ]
)
