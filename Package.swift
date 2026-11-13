// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Aegis",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(path: "../app-kit"),
    ],
    targets: [
        .executableTarget(
            name: "aegis",
            dependencies: [.product(name: "MacAppKit", package: "app-kit")],
            path: "Sources"
        )
    ]
)
