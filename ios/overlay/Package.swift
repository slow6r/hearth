// swift-tools-version:6.0
//
// Только для локальной проверки: `swift test` гоняет логику HearthKit на Mac без
// Haskell-ядра и без Xcode-проекта. В приложение эти файлы попадают иначе —
// ios/scripts/sync-overlay.sh раскладывает SimpleXChat/Hearth в фреймворк SimpleXChat,
// а Package.swift и Tests/ пропускает.
//
// Языковой режим Swift 5 — как у проекта upstream (SWIFT_VERSION = 5.0): код должен
// собираться там, а не только здесь.
import PackageDescription

let package = Package(
    name: "HearthKit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HearthKit", targets: ["HearthKit"]),
    ],
    targets: [
        .target(name: "HearthKit", path: "SimpleXChat/Hearth"),
        .testTarget(name: "HearthKitTests", dependencies: ["HearthKit"], path: "Tests/HearthKitTests"),
    ],
    swiftLanguageModes: [.v5]
)
