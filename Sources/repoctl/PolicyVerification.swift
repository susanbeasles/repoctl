import Foundation
import Security

struct Trust: Codable {
    let format: Int
    let provider: String
    let publicKey: Data
    let revision: Int
    let acceptedSignature: Data
}
struct Seal: Codable {
    let format: Int
    let revision: Int
    let signature: Data
}
func payload(_ data: Data, revision: Int) -> Data {
    // Exact-byte sealing deliberately makes formatting edits detectable too.
    var result = Data("repoctl-policy-v1\nrevision:\(revision)\n".utf8)
    result.append(data)
    return result
}
func verifySignature(_ data: Data, seal: Seal, trust: Trust) throws {
    try require(seal.format == 1 && trust.format == 1, "Unsupported seal version")
    try require(seal.revision == trust.revision && seal.signature == trust.acceptedSignature, "Unapproved revision or rollback detected")
    var error: Unmanaged<CFError>?
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256]
    guard let key = SecKeyCreateWithData(trust.publicKey as CFData, attrs as CFDictionary, &error) else { throw Failure("Invalid enrolled public key") }
    try require(SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
        payload(data, revision: seal.revision) as CFData, seal.signature as CFData, &error), "Policy signature invalid; operation blocked")
}
func verifiedPolicyData(_ path: String) throws -> Data {
    guard let trust = try readTrust(path) else { throw Failure("Policy is not enrolled; cannot verify as sealed") }
    let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    let seal = try JSONDecoder().decode(Seal.self, from: Data(contentsOf: URL(fileURLWithPath: path + ".seal.json")))
    try require(bytes.count <= 1_048_576, "Policy exceeds 1 MiB")
    try verifySignature(bytes, seal: seal, trust: trust)
    return bytes
}
func verifyPolicy(_ path: String) throws { _ = try verifiedPolicyData(path) }
