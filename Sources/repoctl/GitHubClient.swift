import Foundation
import Darwin

// Authentication remains in the user's selected gh account; never print tokens.
struct GitHubClient {
    let timeout: TimeInterval
    init(timeout: TimeInterval = 60) { self.timeout = timeout }

    func request(_ path: String, method: String = "GET", body: Any? = nil) throws -> Any {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        var args = ["gh", "api", "--hostname", "github.com", "--method", method,
                    "-H", "X-GitHub-Api-Version: 2026-03-10", path]
        // File-backed input also prevents a blocked helper from stalling a pipe write.
        if body != nil { args += ["--input", "-"] }
        process.arguments = args
        // File-backed output avoids pipe-buffer deadlock on large rule inventories.
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let outURL = directory.appendingPathComponent("out"), errURL = directory.appendingPathComponent("err")
        FileManager.default.createFile(atPath: outURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: errURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let outHandle = try FileHandle(forWritingTo: outURL), errHandle = try FileHandle(forWritingTo: errURL)
        defer { try? outHandle.close(); try? errHandle.close() }
        process.standardOutput = outHandle; process.standardError = errHandle
        let inputURL = directory.appendingPathComponent("input")
        let inputData = try body.map { try JSONSerialization.data(withJSONObject: $0) } ?? Data()
        FileManager.default.createFile(atPath: inputURL.path, contents: inputData, attributes: [.posixPermissions: 0o600])
        let inputHandle = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputHandle.close() }
        process.standardInput = inputHandle
        try require(timeout.isFinite && timeout > 0, "Invalid GitHub request timeout")
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if process.isRunning {
            process.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 2
            while process.isRunning && ProcessInfo.processInfo.systemUptime < grace { Thread.sleep(forTimeInterval: 0.02) }
            if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw Failure("GitHub request timed out: \(method) \(path); outcome is unknown for mutations. Inspect remote state before retrying.")
        }
        process.waitUntilExit()
        try require(process.terminationStatus == 0,
                    "GitHub request failed: \(method) \(path); run gh auth status and verify repository administration permission (exit \(process.terminationStatus))")
        let data = try Data(contentsOf: outURL)
        return data.isEmpty ? [:] : try JSONSerialization.jsonObject(with: data)
    }
    func rules(_ repo: String) throws -> [[String: Any]] {
        var result: [[String: Any]] = [], page = 1
        while page <= 20 {
            guard let items = try request("repos/\(repo)/rulesets?per_page=100&page=\(page)&includes_parents=true") as? [[String: Any]] else { throw Failure("Invalid ruleset list") }
            result += items
            try require(items.count <= 100, "Oversized ruleset page")
            if items.count < 100 { return result }; page += 1
        }
        throw Failure("Ruleset inventory exceeds 2000 entries; observation incomplete")
    }
}
