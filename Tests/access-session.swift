import Foundation
struct Failure: Error {let message: String; init(_ message: String) {self.message = message}}
@main struct Check {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer {try? FileManager.default.removeItem(at: root)}
        let helper = root.appendingPathComponent("helper")
        func install(_ body: String) throws {
            try ("#!/bin/sh\n" + body).write(to: helper, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        }
        try install("[ \"$#\" = 4 ] && [ \"$1\" = access ] && [ \"$2\" = token ] && [ \"$3\" = --app ] && [ \"$4\" = https://operator.example ] || exit 3\nprintf synthetic.header.signature\n")
        let session = try AccessSession(executable: helper.path, timeout: 1)
        let assertion = try session.assertion(origin: "https://operator.example")
        precondition(assertion == "synthetic.header.signature")
        try install("printf 'synthetic.header.signature\\n'\n")
        let line = try session.assertion(origin: "https://operator.example")
        precondition(line == assertion)
        for body in ["exit 0\n", "printf SECRET >&2; exit 1\n", "printf 'invalid token'\n", "printf 'synthetic.header.signature\\n\\n'\n", "while :; do printf AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; done\n", "while :; do :; done\n"] {
            try install(body)
            let start = ProcessInfo.processInfo.systemUptime
            do {_ = try session.assertion(origin: "https://operator.example"); fatalError("Expected rejection")}
            catch {precondition(!String(describing: error).contains("SECRET"))}
            precondition(ProcessInfo.processInfo.systemUptime-start < 3)
        }
        let marker = root.appendingPathComponent("called")
        try install("touch '" + marker.path + "'\n")
        do {_ = try session.assertion(origin: "http://operator.example"); fatalError("Invalid origin accepted")} catch {}
        precondition(!FileManager.default.fileExists(atPath: marker.path))
        print("PASS: cached-token fixed arguments, bounded failure/overflow/hang, suppressed stderr and pre-process origin rejection; synthetic helper")
    }
}
