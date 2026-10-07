#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
cat > "$task_dir/main.swift" <<'SWIFT'
import Foundation
struct Failure: Error, CustomStringConvertible { let description: String; init(_ message: String) { description = message } }
func require(_ condition: Bool, _ message: String) throws { if !condition { throw Failure(message) } }
func check(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let client = GitHubClient(timeout: 0.2)
let mode = CommandLine.arguments[1]
if mode == "success" {
    let result = try client.request("fixture", method: "POST", body: ["sent": true]) as! [String: Any]
    check(result["sent"] as? Bool == true, "Input bytes did not reach helper")
} else {
    let started = ProcessInfo.processInfo.systemUptime
    do { _ = try client.request("fixture", method: "POST", body: ["sent": true]); fatalError("Failure accepted") }
    catch {
        let message = String(describing: error)
        check(!message.contains("SECRET-MARKER"), "Credential output leaked")
        if mode == "timeout" {
            check(message.contains("timed out") && message.contains("outcome is unknown"), "Ambiguous mutation not reported")
            check(ProcessInfo.processInfo.systemUptime - started < 4, "Timeout unbounded")
        } else { check(message.contains("GitHub request failed"), "Provider failure not reported") }
    }
}
print("PASS: " + mode)
SWIFT
swiftc Sources/repoctl/GitHubClient.swift "$task_dir/main.swift" -o "$task_dir/transport"
cat > "$task_dir/gh" <<'HELPER'
#!/bin/bash
case "$TRANSPORT_TEST_MODE" in
success) /bin/cat ;;
failure) echo 'SECRET-MARKER' >&2; exit 7 ;;
timeout) trap '' TERM; while :; do :; done ;;
esac
HELPER
chmod +x "$task_dir/gh"
for mode in success failure timeout; do
  PATH="$task_dir:$PATH" TRANSPORT_TEST_MODE="$mode" "$task_dir/transport" "$mode"
done
