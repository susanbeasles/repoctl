import Foundation

func repositoryBaseline(_ bytes: Data) throws -> [String: Any] {
    let keys = ["protocol", "repository", "repository_id", "owner_id", "default_branch", "settings", "rulesets", "actions_policies", "actions_permissions", "selected_actions", "workflow_permissions", "immutable_releases"]
    guard let baseline = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          Set(baseline.keys) == Set(keys), baseline["protocol"] as? String == "repoctl-repository-baseline-v1",
          let repo = baseline["repository"] as? String,
          repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil,
          let repositoryID = baseline["repository_id"] as? Int, repositoryID > 0,
          let ownerID = baseline["owner_id"] as? Int, ownerID > 0,
          let branch = baseline["default_branch"] as? String, !branch.isEmpty,
          let settings = baseline["settings"] as? [String: Any],
          Set(settings.keys) == Set(["archived", "fork", "allow_auto_merge", "delete_branch_on_merge"]),
          settings.values.allSatisfy({ $0 is Bool }), settings["archived"] as? Bool == false, settings["fork"] as? Bool == false,
          let rules = baseline["rulesets"] as? [[String: Any]], !rules.isEmpty, rules.count <= 2000,
          let policies = baseline["actions_policies"] as? [[String: Any]], !policies.isEmpty, policies.count <= 2000,
          let actions = baseline["actions_permissions"] as? [String: Any], actions["enabled"] as? Bool == true,
          let allowed = actions["allowed_actions"] as? String, ["all", "local_only", "selected"].contains(allowed),
          (allowed == "selected" ? baseline["selected_actions"] is [String: Any] : baseline["selected_actions"] is NSNull),
          let workflow = baseline["workflow_permissions"] as? [String: Any],
          workflow["default_workflow_permissions"] as? String == "read", workflow["can_approve_pull_request_reviews"] as? Bool == false,
          let immutable = baseline["immutable_releases"] as? [String: Any], immutable["enabled"] as? Bool == true else { throw Failure("Invalid or incomplete approved repository baseline") }
    for (items, bodyFields) in [(rules, Set(["name", "target", "enforcement", "conditions", "rules", "bypass_actors"])), (policies, Set(["name", "enforcement", "conditions", "rules"]))] {
        var seen = Set<Int>()
        for item in items {
            guard Set(item.keys) == Set(["id", "source", "source_type", "body"]), let id = item["id"] as? Int, id > 0,
                  seen.insert(id).inserted, let source = item["source"] as? String, !source.isEmpty,
                  let type = item["source_type"] as? String, ["Repository", "Organization", "Enterprise"].contains(type),
                  let body = item["body"] as? [String: Any], Set(body.keys) == bodyFields,
                  let entries = body["rules"] as? [[String: Any]], !entries.isEmpty,
                  body["conditions"] is [String: Any], let name = body["name"] as? String, !name.isEmpty,
                  body["enforcement"] as? String == "active" else { throw Failure("Invalid or duplicate baseline inventory") }
        }
    }
    return baseline
}

func verifyRepositoryBaseline(_ baseline: [String: Any], client: GitHubClient) throws {
    let repo = baseline["repository"] as! String
    func metadata() throws -> [String: Any] {
        guard let user = try client.request("user") as? [String: Any],
              let value = try client.request("repos/\(repo)") as? [String: Any],
              value["id"] as? Int == baseline["repository_id"] as? Int,
              (value["full_name"] as? String)?.lowercased() == repo.lowercased(),
              let owner = value["owner"] as? [String: Any], owner["type"] as? String == "User",
              owner["id"] as? Int == baseline["owner_id"] as? Int, user["id"] as? Int == baseline["owner_id"] as? Int,
              value["default_branch"] as? String == baseline["default_branch"] as? String else { throw Failure("Repository/owner/default branch differs from approved baseline") }
        var settings: [String: Any] = [:]
        for key in (baseline["settings"] as! [String: Any]).keys { settings[key] = value[key] }
        try require(sameJSON(settings, baseline["settings"]!), "Repository settings drift")
        return value
    }
    _ = try metadata()
    func inventory(_ items: [[String: Any]], rules: Bool) throws -> [[String: Any]] {
        var seen = Set<Int>(), result: [[String: Any]] = []
        for item in items {
            guard let id = item["id"] as? Int, id > 0, seen.insert(id).inserted,
                  let source = item["source"] as? String, let type = item["source_type"] as? String,
                  let body = try client.request("repos/\(repo)/\(rules ? "rulesets" : "actions/policies")/\(id)") as? [String: Any], body["id"] as? Int == id else { throw Failure("Incomplete, foreign or duplicate observed inventory") }
            result.append(["id": id, "source": source, "source_type": type, "body": rules ? normalizedRule(body) : normalizedActions(body)])
        }
        return result.sorted { ($0["id"] as! Int) < ($1["id"] as! Int) }
    }
    func compare(_ actual: Any, _ key: String) throws { try require(sameJSON(actual, baseline[key]!), "Approved baseline drift: \(key)") }
    func checkInventories() throws {
        for (items, key, rules) in [(try client.rules(repo), "rulesets", true), (try actionPolicies(client, repo), "actions_policies", false)] {
            let expected = (baseline[key] as! [[String: Any]]).sorted { ($0["id"] as! Int) < ($1["id"] as! Int) }
            try require(sameJSON(try inventory(items, rules: rules), expected), "Approved baseline drift: \(key)")
        }
    }
    func checkSettings() throws {
        try compare(client.request("repos/\(repo)/actions/permissions"), "actions_permissions")
        if (baseline["actions_permissions"] as! [String: Any])["allowed_actions"] as? String == "selected" {
            try compare(client.request("repos/\(repo)/actions/permissions/selected-actions"), "selected_actions")
        }
        try compare(client.request("repos/\(repo)/actions/permissions/workflow"), "workflow_permissions")
        try compare(client.request("repos/\(repo)/immutable-releases"), "immutable_releases")
    }
    try checkInventories(); try checkSettings()
    // Catch observed drift during collection. This is a configuration check,
    // not an atomic provider transaction or a promotion authorization.
    _ = try metadata(); try checkInventories(); try checkSettings()
}

func doctorCommand(_ args: [String]) throws {
    let usage = "repoctl doctor [--baseline FILE]\nDefault: .repoctl-baseline.json. Requires existing exact-byte policy enrollment/seal. Read-only approved configuration drift check."
    if args == ["doctor", "--help"] { print(usage); return }
    try require(args == ["doctor"] || (args.count == 3 && args[1] == "--baseline"), usage)
    let path = account(args.count == 3 ? args[2] : ".repoctl-baseline.json")
    let bytes = try verifiedPolicyData(path)
    let baseline = try repositoryBaseline(bytes)
    try verifyRepositoryBaseline(baseline, client: GitHubClient())
    try require(try verifiedPolicyData(path) == bytes, "Approved baseline changed during verification")
    print("Verified observed configuration against the enrolled baseline for \(baseline["repository"]!). No changes made. Effective enforcement, controller evidence and production hardware policy remain separate requirements.")
}
