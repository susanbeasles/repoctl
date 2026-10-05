import Foundation

func securityCommand(_ args: [String]) throws {
    let usage = "repoctl security inspect|plan|apply OWNER/REPO\nEnables secret scanning and push protection for public personal repositories. Does not enable Actions or CodeQL default setup. Requires gh authentication as the owner."
    if args.count == 1 || args.contains("--help") { print(usage); return }
    try require(args.count == 3 && ["inspect", "plan", "apply"].contains(args[1]), usage)
    let repo = args[2], client = GitHubClient()
    try require(repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil, "Invalid OWNER/REPO")
    guard let metadata = try client.request("repos/\(repo)") as? [String: Any] else { throw Failure("Invalid repository response") }
    func output(_ value: Any) throws {
        print(String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self))
    }
    if args[1] == "inspect" {
        try output(["repository": repo, "security_and_analysis": metadata["security_and_analysis"] ?? [:]]); return
    }
    guard let identity = try client.request("user") as? [String: Any], let owner = metadata["owner"] as? [String: Any] else { throw Failure("Missing owner identity") }
    try require(owner["type"] as? String == "User" && identity["id"] as? Int == owner["id"] as? Int, "Personal security setup requires the repository owner")
    try require(metadata["private"] as? Bool == false && metadata["archived"] as? Bool == false && metadata["fork"] as? Bool == false, "Requires an active public non-fork repository")
    try require((metadata["permissions"] as? [String: Any])?["admin"] as? Bool == true, "Repository administration permission required")
    let desired: [String: Any] = ["secret_scanning": ["status": "enabled"], "secret_scanning_push_protection": ["status": "enabled"]]
    if args[1] == "plan" {
        try output(["repository": repo, "security_and_analysis": desired, "codeql": "pending integration-only workflow", "malware_scan": "not provided by this command"]); return
    }
    _ = try client.request("repos/\(repo)", method: "PATCH", body: ["security_and_analysis": desired])
    guard let updated = try client.request("repos/\(repo)") as? [String: Any], let security = updated["security_and_analysis"] as? [String: Any] else { throw Failure("Cannot verify security settings") }
    for name in desired.keys {
        try require((security[name] as? [String: Any])?["status"] as? String == "enabled", "Security setting not enabled: \(name)")
    }
    try output(["repository": repo, "verified": desired])
}
