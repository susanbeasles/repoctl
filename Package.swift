// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "repoctl", platforms: [.macOS(.v14)], products: [.executable(name: "repoctl", targets: ["repoctl"])], targets: [.executableTarget(name: "repoctl")])
