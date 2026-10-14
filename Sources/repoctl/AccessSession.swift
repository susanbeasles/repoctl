import Foundation
import Darwin

private final class AccessBytes: @unchecked Sendable {
    let lock = NSLock()
    let done = DispatchSemaphore(value: 0)
    private var bytes = Data()
    private var failed = false
    func append(_ data: Data) -> Bool {
        lock.withLock {
            if bytes.count + data.count > 16000 { failed = true; return false }
            bytes.append(data); return true
        }
    }
    func assertion() throws -> String {
        try lock.withLock {
            guard !failed, var value = String(data: bytes, encoding: .utf8) else {throw Failure("Existing Access session is unavailable")}
            if value.hasSuffix("\r\n") {value.removeLast(2)}
            else if value.hasSuffix("\n") {value.removeLast()}
            guard
                  value.range(of: "^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$", options: .regularExpression) != nil else { throw Failure("Existing Access session is unavailable") }
            return value
        }
    }
}

struct AccessSession {
    let executable: URL
    let timeout: TimeInterval
    init(executable: String, timeout: TimeInterval = 10) throws {
        let url = URL(fileURLWithPath: executable)
        guard executable.hasPrefix("/"), url.standardizedFileURL.path == executable,
              FileManager.default.isExecutableFile(atPath: executable), timeout.isFinite, timeout > 0, timeout <= 10 else { throw Failure("Installed Access CLI is unavailable") }
        self.executable = url; self.timeout = timeout
    }
    // Only cached-token retrieval. Never invokes login, curl, service tokens or
    // browser fallback; provider output stays in a bounded private memory pipe.
    func assertion(origin: String) throws -> String {
        _ = try OperatorClient(origin: origin)
        let process = Process(), pipe = Pipe(), captured = AccessBytes()
        process.executableURL = executable
        process.arguments = ["access", "token", "--app", origin]
        process.standardInput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice; process.standardOutput = pipe
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; captured.done.signal(); return }
            if !captured.append(data), process.isRunning { process.terminate() }
        }
        defer {pipe.fileHandleForReading.readabilityHandler = nil; try? pipe.fileHandleForReading.close()}
        do {try process.run()} catch {throw Failure("Installed Access CLI is unavailable")}
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {Thread.sleep(forTimeInterval: 0.01)}
        if process.isRunning {
            process.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 0.2
            while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {Thread.sleep(forTimeInterval: 0.01)}
            if process.isRunning {_ = kill(process.processIdentifier, SIGKILL)}
            process.waitUntilExit()
            throw Failure("Existing Access session lookup timed out; no login started")
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, captured.done.wait(timeout: .now()+1) == .success else {throw Failure("Existing Access session is unavailable; no login started")}
        return try captured.assertion()
    }
}
