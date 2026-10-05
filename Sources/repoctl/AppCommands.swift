import Foundation
import CryptoKit

func appCommand(_ args: [String]) throws {
    let usage = "repoctl app plan CONFIG\nProduces a reviewed GitHub App manifest and enrollment digest. No registration or remote write occurs. V1 roles: writer, validator, builder, release. Webhook subscriptions and custom permission sets require explicit supported profiles."
    if args == ["app", "--help"] { print(usage); return }
    try require(args.count == 3 && args[1] == "plan", usage)
    let input = try Data(contentsOf: URL(fileURLWithPath: args[2]))
    try require(input.count <= 65536, "App configuration exceeds 64 KiB")
    guard let config = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { throw Failure("Invalid App configuration") }
    try require(Set(config.keys) == Set(["format", "name", "owner", "role", "homepage", "callback", "repositories"]), "Unexpected App configuration fields")
    try require(config["format"] as? Int == 1, "Unsupported App configuration format")
    guard let name = config["name"] as? String, let owner = config["owner"] as? String, let role = config["role"] as? String else { throw Failure("Missing App name, owner or role") }
    try require(name.range(of: "^[A-Za-z0-9][A-Za-z0-9 -]{0,80}$", options: .regularExpression) != nil, "Invalid App name")
    try require(owner.range(of: "^[A-Za-z0-9][A-Za-z0-9-]{0,38}$", options: .regularExpression) != nil, "Invalid GitHub owner")
    let roles: [String: [String: String]] = ["writer": ["contents": "write"], "validator": ["contents": "read", "checks": "read", "actions": "read", "security_events": "read"], "builder": ["contents": "write", "pull_requests": "write"], "release": ["contents": "write"]]
    guard let permissions = roles[role] else { throw Failure("Unsupported App role") }
    var urls: [String: String] = [:]
    for field in ["homepage", "callback"] {
        guard let value = config[field] as? String, value.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 }), let url = URLComponents(string: value), url.scheme == "https", let host = url.host, !host.isEmpty, url.user == nil, url.password == nil, url.fragment == nil, url.query == nil else { throw Failure("Invalid HTTPS \(field)") }
        urls[field] = value
    }
    guard let repositories = config["repositories"] as? [String], !repositories.isEmpty, repositories.count <= 100 else { throw Failure("Select 1–100 repositories") }
    try require(Set(repositories).count == repositories.count && repositories.allSatisfy { $0.hasPrefix(owner + "/") && $0.range(of: "^[-A-Za-z0-9_.]+/[-A-Za-z0-9_.]+$", options: .regularExpression) != nil }, "Repositories must be unique and owned by the selected owner")
    let manifest: [String: Any] = ["name": name, "url": urls["homepage"]!, "redirect_url": urls["callback"]!, "public": false, "default_permissions": permissions, "default_events": [String](), "hook_attributes": ["active": false]]
    let bytes = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .withoutEscapingSlashes])
    let plan: [String: Any] = ["protocol": "repoctl-app-plan-v1", "owner": owner, "role": role, "repositories": repositories.sorted(), "manifest": manifest, "manifestBytes": bytes.base64EncodedString(), "manifestDigest": SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), "registrationState": "not_registered", "installationState": "not_installed"]
    print(String(decoding: try JSONSerialization.data(withJSONObject: plan, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self))
}
