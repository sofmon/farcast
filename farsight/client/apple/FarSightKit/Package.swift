// swift-tools-version: 6.2
//
// FarSightKit is the Apple client's logic and views (ADR 0021 decision 2); the
// app targets live in ../FarSight.xcodeproj. It depends on system frameworks
// only (decision 3), so it resolves nothing and builds offline, and every
// target carries decision 4's guardrails: Swift 6 language mode, strict memory
// safety, warnings as errors. ./check.sh adds the source gate and the full
// builds.

import PackageDescription

let guardrails: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .strictMemorySafety(),
    .treatAllWarnings(as: .error),
]

// Views and their state run on the main actor; values do not, so the map's
// geometry can be computed and tested anywhere.
let onMain: [SwiftSetting] = guardrails + [.defaultIsolation(MainActor.self)]

let package = Package(
    name: "FarSightKit",
    platforms: [.macOS(.v26), .iOS(.v26), .visionOS(.v26)],
    products: [
        .library(name: "FarSightCore", targets: ["FarSightCore"]),
        .library(name: "FarSightUI", targets: ["FarSightUI"]),
        .library(name: "FarSightFixtures", targets: ["FarSightFixtures"]),
    ],
    targets: [
        // Values, and the Connected view's contract: the world the map draws, where
        // everything sits on it, the camera, and the logic that turns the operator's
        // `farcast` output into a world. It runs no process itself (the macOS app
        // hands it one), and touches no network, key or view.
        .target(
            name: "FarSightCore",
            swiftSettings: guardrails
        ),
        // The app world map and its Liquid Glass HUD, over the backdrop.
        .target(
            name: "FarSightUI",
            dependencies: ["FarSightCore"],
            resources: [.copy("Backdrop/backdrop.heic")],
            swiftSettings: onMain
        ),
        // A world to draw until the read route exists (ADR 0021 decision 9,
        // step 1). Illustrative data, nothing read from a live instance.
        .target(
            name: "FarSightFixtures",
            dependencies: ["FarSightCore"],
            resources: [.copy("world.json")],
            swiftSettings: guardrails
        ),
        .testTarget(
            name: "FarSightCoreTests",
            dependencies: ["FarSightCore", "FarSightFixtures"],
            resources: [.copy("Vectors")],
            swiftSettings: guardrails
        ),
        .testTarget(
            name: "FarSightUITests",
            dependencies: ["FarSightUI", "FarSightCore", "FarSightFixtures"],
            swiftSettings: onMain
        ),
    ]
)
