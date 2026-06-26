// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "InterKnotAuth",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "InterKnotAuth",
            dependencies: []
        )
    ]
)
