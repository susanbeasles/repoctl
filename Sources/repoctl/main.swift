import Foundation
import Security
import Darwin

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}
func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message) }
}
func status(_ value: OSStatus) throws {
    if value != errSecSuccess { throw Failure(SecCopyErrorMessageString(value, nil) as String? ?? "Security error \(value)") }
}
let service = "repoctl.policy.v1"
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
func account(_ path: String) -> String {
    URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
}
func readTrust(_ path: String) throws -> Trust? {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: account(path),
        kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
    var result: CFTypeRef?
    let code = SecItemCopyMatching(query as CFDictionary, &result)
    if code == errSecItemNotFound { return nil }
    try status(code)
    guard let data = result as? Data else { throw Failure("Invalid trust record") }
    return try JSONDecoder().decode(Trust.self, from: data)
}
func writeTrust(_ trust: Trust, _ path: String) throws {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: account(path)]
    let data = try JSONEncoder().encode(trust)
    let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if update == errSecItemNotFound {
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        try status(SecItemAdd(add as CFDictionary, nil))
    } else { try status(update) }
}
func keyTag(_ path: String) -> Data { Data((service + ":" + account(path)).utf8) }
func findKey(_ path: String) throws -> SecKey? {
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyTag(path), kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecReturnRef as String: true]
    var result: CFTypeRef?
    let code = SecItemCopyMatching(query as CFDictionary, &result)
    if code == errSecItemNotFound { return nil }
    try status(code)
    guard let result else { throw Failure("Missing key reference") }
    return (result as! SecKey)
}
func createKey(_ path: String, provider: String) throws -> SecKey {
    try require(try findKey(path) == nil, "Key already exists; reuse it instead of replacing it")
    var error: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = provider == "sep" ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
        throw Failure(error?.takeRetainedValue().localizedDescription ?? "Cannot create access control")
    }
    var attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag(path)]]
    if provider == "sep" {
        var privateAttrs = attributes[kSecPrivateKeyAttrs as String] as! [String: Any]
        privateAttrs[kSecAttrAccessControl as String] = access
        attributes[kSecPrivateKeyAttrs as String] = privateAttrs
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw Failure(error?.takeRetainedValue().localizedDescription ?? "Cannot generate key; no provider fallback")
    }
    return key
}
func publicBytes(_ key: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let publicKey = SecKeyCopyPublicKey(key), let data = SecKeyCopyExternalRepresentation(publicKey, &error) else {
        throw Failure(error?.takeRetainedValue().localizedDescription ?? "Cannot export public key")
    }
    return data as Data
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
func verifyPolicy(_ path: String) throws {
    guard let trust = try readTrust(path) else { throw Failure("Policy is not enrolled; cannot verify as sealed") }
    let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    let seal = try JSONDecoder().decode(Seal.self, from: Data(contentsOf: URL(fileURLWithPath: path + ".seal.json")))
    try verifySignature(bytes, seal: seal, trust: trust)
}
func verifyExecutable() throws {
    // Installed bundle carries its expected signer requirement as a sealed resource.
    // Development builds without a bundle are explicitly unprotected.
    let bundle = Bundle.main
    guard let requirementString = bundle.object(forInfoDictionaryKey: "RepoctlSignerRequirement") as? String else { return }
    var requirement: SecRequirement?
    try status(SecRequirementCreateWithString(requirementString as CFString, [], &requirement))
    var code: SecStaticCode?
    try status(SecStaticCodeCreateWithPath(bundle.bundleURL as CFURL, [], &code))
    guard let code, let requirement else { throw Failure("Cannot inspect executable signature") }
    try status(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), requirement))
}
func run() throws {
    try verifyExecutable()
    let args = Array(CommandLine.arguments.dropFirst())
    if args.isEmpty || args == ["--help"] {
        print("""
        repoctl policy seal FILE [--provider sep|keychain] --approve
        repoctl policy verify FILE
        repoctl policy status FILE
        Signing default: SEP. No automatic fallback. Seal signs exact JSON bytes.
        This preview does not apply GitHub rules or promote branches.
        """)
        return
    }
    try require(args.count >= 3 && args[0] == "policy", "Unknown command; use --help")
    let action = args[1], path = account(args[2])
    if action == "verify" {
        try require(args.count == 3, "Unexpected arguments")
        try verifyPolicy(path); print("Verified approved policy")
    } else if action == "status" {
        try require(args.count == 3, "Unexpected arguments")
        if let trust = try readTrust(path) {
            try verifyPolicy(path)
            print("Sealed; provider=\(trust.provider); revision=\(trust.revision)")
        } else { print("Unsealed; no integrity enforcement") }
    } else if action == "seal" {
        var provider = "sep", approved = false, i = 3
        while i < args.count {
            if args[i] == "--approve" { approved = true; i += 1 }
            else if args[i] == "--provider" && i + 1 < args.count { provider = args[i + 1]; i += 2 }
            else { throw Failure("Unknown seal option") }
        }
        try require(approved, "Review the JSON first, then explicitly pass --approve")
        try require(["sep", "keychain"].contains(provider), "Supported providers: sep, keychain")
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try require(data.count <= 1_048_576, "Policy exceeds 1 MiB")
        let json = try JSONSerialization.jsonObject(with: data)
        try require(json is [String: Any], "Policy must be a JSON object")
        let previous = try readTrust(path)
        if let previous { try require(previous.provider == provider, "Provider changes require a future explicit rotation command") }
        let key: SecKey
        if let existing = try findKey(path) { key = existing }
        else {
            try require(previous == nil, "Enrolled signing key missing; refusing replacement")
            key = try createKey(path, provider: provider)
        }
        let pub = try publicBytes(key)
        if let previous { try require(previous.publicKey == pub, "Enrolled signer mismatch") }
        let revision = (previous?.revision ?? 0) + 1
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
            payload(data, revision: revision) as CFData, &error) else {
            throw Failure(error?.takeRetainedValue().localizedDescription ?? "Signing denied")
        }
        let seal = Seal(format: 1, revision: revision, signature: signature as Data)
        // Write first, then accept in Keychain. A crash between writes fails closed.
        try JSONEncoder().encode(seal).write(to: URL(fileURLWithPath: path + ".seal.json"), options: .atomic)
        try writeTrust(Trust(format: 1, provider: provider, publicKey: pub,
            revision: revision, acceptedSignature: signature as Data), path)
        try verifyPolicy(path)
        print("Sealed revision \(revision) with \(provider)")
    } else { throw Failure("Unknown policy command") }
}
do { try run() }
catch { FileHandle.standardError.write(Data("repoctl: \(error)\n".utf8)); exit(1) }
