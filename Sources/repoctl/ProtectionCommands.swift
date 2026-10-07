import Foundation

func promotionProtection(ownerID: Int, writerID: Int) -> [[String: Any]] {
    let protected = ["~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master"]
    func rule(_ name: String, types: [String], bypass: [[String: Any]] = []) -> [String: Any] {
        let rules: [[String: Any]] = types.map { type in
            type == "update" ? ["type": type, "parameters": ["update_allows_fetch_and_merge": false]] : ["type": type]
        }
        return ["name": "repoctl/promotion-v1/" + name, "target": "branch", "enforcement": "active",
                "conditions": ["ref_name": ["include": protected, "exclude": [String]()]],
                "rules": rules, "bypass_actors": bypass]
    }
    var desired = bootstrapRules(ownerID: ownerID).filter { $0["name"] as? String != "repoctl/bootstrap-v1/protected-locked" }
    desired += [rule("main-lifecycle", types: ["creation", "deletion"]),
                rule("main-integrity", types: ["non_fast_forward", "required_linear_history", "required_signatures"]),
                rule("main-writer", types: ["update"], bypass: [["actor_id": writerID, "actor_type": "Integration", "bypass_mode": "always"]])]
    return desired
}
func protectionCommand(_ args: [String]) throws {
    let usage = "repoctl protect plan|apply|verify OWNER/REPO --writer-app SLUG [--actions-app SLUG]\nPersonal repositories only. Default branch must exist. Main becomes App-only; no human bypass. This command does not deploy or test the promotion service."
    if args == ["protect", "--help"] { print(usage); return }
    try require(args.count == 5 || args.count == 7, usage)
    let action = args[1], repo = args[2], slug = args[4]
    if args.count == 7 { try require(args[5] == "--actions-app" && args[6].range(of: "^[A-Za-z0-9-]+$", options: .regularExpression) != nil, usage) }
    try require(["plan", "apply", "verify"].contains(action) && args[3] == "--writer-app", usage)
    try require(repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil && slug.range(of: "^[A-Za-z0-9-]+$", options: .regularExpression) != nil, "Invalid repository/App slug")
    let client = GitHubClient()
    guard let user = try client.request("user") as? [String: Any],
          let metadata = try client.request("repos/\(repo)") as? [String: Any],
          let owner = metadata["owner"] as? [String: Any], let ownerID = owner["id"] as? Int,
          let app = try client.request("apps/\(slug)") as? [String: Any], let writerID = app["id"] as? Int else { throw Failure("Cannot resolve owner/repository/App identity") }
    try require(owner["type"] as? String == "User" && user["id"] as? Int == ownerID && (metadata["permissions"] as? [String: Any])?["admin"] as? Bool == true, "Exact personal owner/admin required")
    try require(metadata["fork"] as? Bool != true && metadata["archived"] as? Bool != true, "Active nonfork repository required")
    try require((app["permissions"] as? [String: Any])?["contents"] as? String == "write", "Writer App must request Contents write")
    try require((app["permissions"] as? [String: Any])?["administration"] as? String != "write", "Writer App must not hold repository Administration write")
    guard let branch = metadata["default_branch"] as? String, let encoded = branch.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else { throw Failure("Missing default branch") }
    _ = try client.request("repos/\(repo)/branches/\(encoded)")
    let desired = promotionProtection(ownerID: ownerID, writerID: writerID)
    if action == "plan" {
        print(String(decoding: try JSONSerialization.data(withJSONObject: ["repository": repo, "writer_app": app["slug"] ?? slug, "writer_app_id": writerID, "rulesets": desired, "warning": "Main will reject human updates. App installation/service readiness must be validated before applying. No remote changes made."], options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)); return
    }
    // Validate the exact selected Actions authority before any protection mutations.
    // No flag means owner-only Actions. Additional automation requires explicit intent.
    let actionsArgs = ["actions", "verify", repo] + (args.count == 7 ? ["--app", args[6]] : [])
    try actionsCommand(actionsArgs)
    let inventory = try client.rules(repo)
    let obsolete = inventory.filter { $0["name"] as? String == "repoctl/bootstrap-v1/protected-locked" }
    try require(obsolete.count <= 1, "Duplicate obsolete bootstrap ruleset")
    if let old = obsolete.first {
        guard old["source_type"] as? String == "Repository", (old["source"] as? String)?.lowercased() == repo.lowercased(), let id = old["id"] as? Int,
              let actual = try client.request("repos/\(repo)/rulesets/\(id)") as? [String: Any],
              let expected = bootstrapRules(ownerID: ownerID).first(where: { $0["name"] as? String == "repoctl/bootstrap-v1/protected-locked" }) else { throw Failure("Cannot safely migrate bootstrap lock") }
        try require(sameJSON(normalizedRule(actual), expected), "Bootstrap lock was edited; review before migration")
    }
    // Preflight every managed collision before any mutations.
    for rule in desired {
        let matches = inventory.filter { $0["name"] as? String == rule["name"] as? String }
        try require(matches.count <= 1, "Duplicate managed ruleset")
        if let match = matches.first { try require(match["source_type"] as? String == "Repository" && (match["source"] as? String)?.lowercased() == repo.lowercased(), "Inherited managed-name collision") }
    }
    if action == "apply" {
        for rule in desired {
            if let old = inventory.first(where: { $0["name"] as? String == rule["name"] as? String }), let id = old["id"] as? Int {
                _ = try client.request("repos/\(repo)/rulesets/\(id)", method: "PUT", body: rule)
            } else { _ = try client.request("repos/\(repo)/rulesets", method: "POST", body: rule) }
        }
        _ = try client.request("repos/\(repo)/immutable-releases", method: "PUT")
    }
    let current = try client.rules(repo)
    for rule in desired {
        let matches = current.filter { $0["name"] as? String == rule["name"] as? String }
        guard matches.count == 1, let id = matches[0]["id"] as? Int, let actual = try client.request("repos/\(repo)/rulesets/\(id)") as? [String: Any] else { throw Failure("Managed rule missing/duplicated") }
        try require(sameJSON(normalizedRule(actual), rule), "Protection drift detected: \(rule["name"] ?? "")")
    }
    try actionsCommand(actionsArgs) // Recheck authority before releasing the bootstrap lock.
    // Remove the all-writers lock only after the replacement constraints verify.
    if action == "apply", let old = obsolete.first, let id = old["id"] as? Int { _ = try client.request("repos/\(repo)/rulesets/\(id)", method: "DELETE") }
    let finalRules = try client.rules(repo)
    try require(!finalRules.contains { $0["name"] as? String == "repoctl/bootstrap-v1/protected-locked" }, "Obsolete bootstrap lock still blocks the writer")
    let releases = try client.request("repos/\(repo)/immutable-releases") as? [String: Any]
    try require(releases?["enabled"] as? Bool == true, "Immutable releases not enabled")
    print("Verified App-only main updates, no-bypass integrity/lifecycle rules, owner working branches, immutable tags/releases. App readiness and unmanaged/inherited interactions still require behavioral validation.")
}
