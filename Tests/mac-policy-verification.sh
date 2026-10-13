#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
cat > "$task_dir/main.swift" <<'SWIFT'
import Foundation
import Security
struct Failure: Error, CustomStringConvertible { let description: String; init(_ message: String) { description = message } }
func require(_ condition: Bool, _ message: String) throws { if !condition { throw Failure(message) } }
var fixtureTrust: Trust?
func readTrust(_ path: String) throws -> Trust? { fixtureTrust }
func rejects(_ label: String, _ operation: () throws -> Void) {
 do { try operation(); fatalError("Accepted " + label) } catch { print("PASS: " + label + " denied") }
}
let path = CommandLine.arguments[1]
let original = Data("{\"repository\":\"fixture/repository\"}\n".utf8)
// Explicit temporary software fixture: no permanent key, no Keychain entry,
// no hardware enrollment claim and no replacement of an operator identity.
var error: Unmanaged<CFError>?
let attrs: [String: Any] = [kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits as String:256]
guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
      let publicKey = SecKeyCopyPublicKey(key),
      let pub = SecKeyCopyExternalRepresentation(publicKey, &error),
      let signature = SecKeyCreateSignature(key,.ecdsaSignatureMessageX962SHA256,payload(original,revision:1) as CFData,&error) else { fatalError("Fixture key/signature failed") }
fixtureTrust = Trust(format:1,provider:"fixture-software",publicKey:pub as Data,revision:1,acceptedSignature:signature as Data)
let seal = Seal(format:1,revision:1,signature:signature as Data)
try original.write(to: URL(fileURLWithPath:path))
try JSONEncoder().encode(seal).write(to: URL(fileURLWithPath:path+".seal.json"))
let verified = try verifiedPolicyData(path)
assert(verified == original)
try verifyPolicy(path)
try Data("{\"repository\":\"changed/repository\"}\n".utf8).write(to:URL(fileURLWithPath:path))
assert(verified == original) // Consumers retain the exact verified snapshot.
rejects("altered body") { _ = try verifiedPolicyData(path) }
try original.write(to:URL(fileURLWithPath:path))
try JSONEncoder().encode(Seal(format:1,revision:2,signature:signature as Data)).write(to:URL(fileURLWithPath:path+".seal.json"))
rejects("seal revision rollback/mismatch") { _ = try verifiedPolicyData(path) }
try JSONEncoder().encode(seal).write(to:URL(fileURLWithPath:path+".seal.json"))
try Data(repeating:65,count:1_048_577).write(to:URL(fileURLWithPath:path))
rejects("oversized body") { _ = try verifiedPolicyData(path) }
fixtureTrust=nil
rejects("missing enrollment") { _ = try verifiedPolicyData(path) }
print("PASS: native exact-byte v1 verification and retained verified snapshot; ephemeral software fixture only")
SWIFT
swiftc Sources/repoctl/PolicyVerification.swift "$task_dir/main.swift" -o "$task_dir/verify"
"$task_dir/verify" "$task_dir/policy.json"
swift build
