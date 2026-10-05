import Foundation
import Security
import CryptoKit

func approvalCommand(_ args: [String]) throws {
    let usage = "repoctl approval key POLICY\nrepoctl approval sign INTENT --policy POLICY --approve\nrepoctl approval sign-run RUN_INTENT --policy POLICY --approve\nrepoctl approval sign-enrollment INTENT --policy POLICY --approve\nUses the existing sealed policy key with a separate promotion domain. Keychain is software-backed; SEP has no fallback. Public-key enrollment on the validator/writer is separate."
    if args == ["approval", "--help"] { print(usage); return }
    try require(args.count >= 3, usage)
    let action = args[1]
    try require((action == "key" && args.count == 3) || (["sign", "sign-run", "sign-enrollment"].contains(action) && args.count == 6 && args[3] == "--policy" && args[5] == "--approve"), usage)
    let policy = account(action == "key" ? args[2] : args[4])
    try verifyPolicy(policy)
    guard let trust = try readTrust(policy), let key = try findKey(policy) else { throw Failure("Sealed policy signing key unavailable") }
    let publicKey = try publicBytes(key)
    try require(publicKey == trust.publicKey, "Signing key differs from sealed policy enrollment")
    let keyID = SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    if action == "key" {
        print(String(decoding: try JSONSerialization.data(withJSONObject: ["keyID": keyID, "publicKeyX963": publicKey.base64EncodedString(), "provider": trust.provider], options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)); return
    }
    if action == "sign-enrollment" {
        try signAppEnrollment(args[2], trust: trust, key: key, keyID: keyID)
        return
    }
    if action == "sign-run" {
        try signExecutionRun(args[2], policy: policy, trust: trust, key: key, keyID: keyID)
        return
    }
    let input = try Data(contentsOf: URL(fileURLWithPath: args[2]))
    try require(input.count <= 16000, "Intent too large")
    guard let intent = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { throw Failure("Invalid intent JSON") }
    let fields: Set<String> = ["repositoryID", "sequence", "previousDigest", "baseSHA", "commitSHA", "sourceSHA", "treeSHA", "policyDigest", "evidenceDigest", "archiveDigests", "nonce", "expiresAt"]
    try require(Set(intent.keys) == fields, "Unexpected intent fields")
    for name in ["baseSHA", "commitSHA", "sourceSHA", "treeSHA"] {
        guard let value = intent[name] as? String else { throw Failure("Missing \(name)") }
        try require(value.range(of: "^[a-f0-9]{40}$", options: .regularExpression) != nil, "Invalid \(name)")
    }
    guard let repositoryID = intent["repositoryID"] as? Int, let sequence = intent["sequence"] as? Int,
          let expires = intent["expiresAt"] as? Int else { throw Failure("Invalid numeric intent fields") }
    let now = Int(Date().timeIntervalSince1970 * 1000)
    try require(repositoryID > 0 && sequence > 0 && expires > now && expires <= now + 300000, "Invalid identity/sequence or intent lifetime (maximum five minutes)")
    let policyData = try Data(contentsOf: URL(fileURLWithPath: policy))
    let policySeal = try JSONDecoder().decode(Seal.self, from: Data(contentsOf: URL(fileURLWithPath: policy + ".seal.json")))
    try verifySignature(policyData, seal: policySeal, trust: trust)
    let policyDigest = SHA256.hash(data: policyData).map { String(format: "%02x", $0) }.joined()
    try require(intent["policyDigest"] as? String == policyDigest, "Intent does not bind this exact sealed policy")
    // Preserve exact reviewed bytes; the independent validator signs the same bytes.
    var message = Data("repoctl-promotion-owner-v1\n".utf8); message.append(input)
    FileHandle.standardError.write(Data("Approving repository \(repositoryID), sequence \(sequence), base \(intent["baseSHA"] ?? ""), candidate \(intent["commitSHA"] ?? ""), source \(intent["sourceSHA"] ?? ""). Authorize the enrolled \(trust.provider) key if prompted.\n".utf8))
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) else { throw Failure(error?.takeRetainedValue().localizedDescription ?? "Approval signing failed") }
    let envelope: [String: Any] = ["protocol": "repoctl-promotion-owner-v1", "keyID": keyID, "encoding": "der", "payload": input.base64EncodedString(), "signature": (signature as Data).base64EncodedString()]
    let output = args[2] + ".approval.json"
    try require(!FileManager.default.fileExists(atPath: output), "Approval output already exists; will not replace it")
    try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: output), options: .withoutOverwriting)
    print("Signed exact promotion intent for repository \(repositoryID), sequence \(sequence), candidate \(intent["commitSHA"] ?? ""). Wrote \(output). Provider: \(trust.provider). No remote action performed.")
}


func signExecutionRun(_ path: String, policy: String, trust: Trust, key: SecKey, keyID: String) throws {
    let input = try Data(contentsOf: URL(fileURLWithPath: path))
    try require(input.count <= 16000, "Execution intent too large")
    guard let body = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { throw Failure("Invalid execution intent JSON") }
    let fields: Set<String> = ["operationID", "approvalDigest", "repositoryID", "repository", "targetRef", "policyRevision", "policyDigest", "executorTrustDigest", "runID", "runAttempt", "expiresAt"]
    try require(Set(body.keys) == fields, "Unexpected execution intent fields")
    for name in ["operationID", "approvalDigest", "policyDigest", "executorTrustDigest"] {
        guard let value = body[name] as? String else { throw Failure("Missing \(name)") }
        try require(value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, "Invalid \(name)")
    }
    guard let repository = body["repository"] as? String, let target = body["targetRef"] as? String else { throw Failure("Missing target") }
    try require(repository.range(of: "^[-A-Za-z0-9_.]+/[-A-Za-z0-9_.]+$", options: .regularExpression) != nil && ["refs/heads/main", "refs/heads/master"].contains(target), "Invalid execution target")
    for name in ["repositoryID", "policyRevision", "runID", "runAttempt"] {
        guard let value = body[name] as? Int, value > 0 else { throw Failure("Invalid \(name)") }
    }
    guard let expires = body["expiresAt"] as? Int else { throw Failure("Invalid execution expiry") }
    let now = Int(Date().timeIntervalSince1970)
    try require(expires > now && expires <= now + 300, "Execution approval lifetime exceeds five minutes")
    let policyData = try Data(contentsOf: URL(fileURLWithPath: policy))
    let policyDigest = SHA256.hash(data: policyData).map { String(format: "%02x", $0) }.joined()
    try require(body["policyDigest"] as? String == policyDigest, "Execution does not bind this exact sealed policy")
    let policySeal = try JSONDecoder().decode(Seal.self, from: Data(contentsOf: URL(fileURLWithPath: policy + ".seal.json")))
    try verifySignature(policyData, seal: policySeal, trust: trust)
    let output = path + ".execution-approval.json"
    try require(!FileManager.default.fileExists(atPath: output), "Execution approval exists; will not replace it")
    FileHandle.standardError.write(Data("Approving executor run \(body["runID"] ?? ""), attempt \(body["runAttempt"] ?? ""), target \(repository) \(target), trust digest \(body["executorTrustDigest"] ?? ""), operation \(body["operationID"] ?? ""). Authorize the enrolled \(trust.provider) key if prompted.\n".utf8))
    var message = Data("repoctl-execution-owner-v1\n".utf8); message.append(input)
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) else { throw Failure(error?.takeRetainedValue().localizedDescription ?? "Execution approval signing failed") }
    let envelope: [String: Any] = ["protocol": "repoctl-execution-owner-v1", "keyID": keyID, "encoding": "der", "payload": input.base64EncodedString(), "signature": (signature as Data).base64EncodedString()]
    try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: output), options: .withoutOverwriting)
    print("Signed exact execution run approval. Wrote \(output). Provider: \(trust.provider). No remote action performed.")
}

func signAppEnrollment(_ path: String, trust: Trust, key: SecKey, keyID: String) throws {
    let input = try Data(contentsOf: URL(fileURLWithPath: path))
    try require(input.count <= 3000, "Enrollment intent too large")
    guard let body = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { throw Failure("Invalid enrollment intent JSON") }
    let fields: Set<String> = ["operationID", "ownerID", "role", "manifestDigest", "expiresAt"]
    try require(Set(body.keys) == fields, "Unexpected enrollment intent fields")
    for name in ["operationID", "manifestDigest"] {
        guard let value = body[name] as? String else { throw Failure("Missing \(name)") }
        try require(value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, "Invalid \(name)")
    }
    guard let owner = body["ownerID"] as? Int, owner > 0,
          let role = body["role"] as? String, ["writer", "validator", "builder", "release"].contains(role),
          let expires = body["expiresAt"] as? Int else { throw Failure("Invalid enrollment identity, role or expiry") }
    let now = Int(Date().timeIntervalSince1970)
    try require(expires > now && expires <= now + 300, "Enrollment approval lifetime exceeds five minutes")
    let output = path + ".enrollment-approval.json"
    try require(!FileManager.default.fileExists(atPath: output), "Enrollment approval exists; will not replace it")
    FileHandle.standardError.write(Data("Approving App enrollment for owner \(owner), role \(role), manifest digest \(body["manifestDigest"] ?? ""), operation \(body["operationID"] ?? ""). Authorize the enrolled \(trust.provider) key if prompted.\n".utf8))
    var message = Data("repoctl-app-enrollment-owner-v1\n".utf8); message.append(input)
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) else { throw Failure(error?.takeRetainedValue().localizedDescription ?? "Enrollment approval signing failed") }
    let envelope: [String: Any] = ["protocol": "repoctl-app-enrollment-owner-v1", "keyID": keyID, "encoding": "der", "payload": input.base64EncodedString(), "signature": (signature as Data).base64EncodedString()]
    try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: output), options: .withoutOverwriting)
    print("Signed exact App enrollment approval. Wrote \(output). Provider: \(trust.provider). No remote action performed.")
}
