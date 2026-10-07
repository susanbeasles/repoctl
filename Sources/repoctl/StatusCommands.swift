import Foundation

// Observation only: provider settings do not prove behavioral enforcement or
// independently retained controller evidence. No credentials appear in output.
func statusCommand(_ args: [String]) throws {
    let usage = "repoctl status [OWNER/REPO]\nWithout a target, reads repository from .repoctl.json. Read-only provider observation; controller evidence remains separate."
    if args == ["status", "--help"] { print(usage); return }
    try require(args.count == 1 || args.count == 2, usage)
    let repo: String
    if args.count == 2 { repo = args[1] }
    else {
        let url = URL(fileURLWithPath: ".repoctl.json")
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        try require((attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576, "Repository configuration exceeds 1 MiB")
        guard let config = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any],
              let configured = config["repository"] as? String else { throw Failure(".repoctl.json must identify repository as OWNER/REPO") }
        repo = configured
    }
    try require(repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil, "Invalid OWNER/REPO")
    let client = GitHubClient()
    guard let user = try client.request("user") as? [String: Any],
          let metadata = try client.request("repos/\(repo)") as? [String: Any],
          let owner = metadata["owner"] as? [String: Any], let ownerID = owner["id"] as? Int,
          let repositoryID = metadata["id"] as? Int, repositoryID > 0,
          let name = metadata["full_name"] as? String, name.lowercased() == repo.lowercased(),
          let branch = metadata["default_branch"] as? String,
          let encoded = branch.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else { throw Failure("Invalid repository identity") }
    try require(owner["type"] as? String == "User" && user["id"] as? Int == ownerID,
                "Status requires authentication as the exact personal repository owner")
    guard let tip = try client.request("repos/\(repo)/git/ref/heads/\(encoded)") as? [String: Any],
          tip["ref"] as? String == "refs/heads/\(branch)",
          let object = tip["object"] as? [String: Any], object["type"] as? String == "commit",
          let sha = object["sha"] as? String,
          sha.range(of: "^[a-f0-9]{40}$", options: .regularExpression) != nil else { throw Failure("Invalid default branch observation") }
    // Missing permissions must remain visible as a failed observation, never an
    // empty inventory or a green compliance result.
    let inventory = try client.rules(repo)
    let policies = try actionPolicies(client, repo)
    let permissions = try client.request("repos/\(repo)/actions/permissions")
    let workflow = try client.request("repos/\(repo)/actions/permissions/workflow")
    let immutable = try client.request("repos/\(repo)/immutable-releases")
    let summary = inventory.map { rule -> [String: Any] in
        var result: [String: Any] = [:]
        for key in ["id", "name", "target", "enforcement", "source", "source_type"] { result[key] = rule[key] }
        return result
    }
    let policySummary = policies.map { policy -> [String: Any] in
        var result: [String: Any] = [:]
        for key in ["id", "name", "enforcement", "source", "source_type"] { result[key] = policy[key] }
        return result
    }
    // Ref and immutable numeric identity must remain stable across collection.
    guard let finalMetadata = try client.request("repos/\(repo)") as? [String: Any],
          finalMetadata["id"] as? Int == repositoryID,
          (finalMetadata["owner"] as? [String: Any])?["id"] as? Int == ownerID,
          (finalMetadata["full_name"] as? String)?.lowercased() == repo.lowercased(),
          finalMetadata["default_branch"] as? String == branch,
          let finalTip = try client.request("repos/\(repo)/git/ref/heads/\(encoded)") as? [String: Any],
          finalTip["ref"] as? String == tip["ref"] as? String,
          sameJSON(finalTip["object"] ?? [:], object) else { throw Failure("Repository identity or tip changed during observation; rerun status") }
    let output: [String: Any] = ["protocol": "repoctl-provider-status-v1", "repository": name,
        "repository_id": repositoryID, "owner_id": ownerID, "default_branch": branch, "default_tip": sha,
        "archived": metadata["archived"] ?? NSNull(), "fork": metadata["fork"] ?? NSNull(),
        "rulesets": summary, "actions_policies": policySummary, "actions_permissions": permissions,
        "workflow_permissions": workflow, "immutable_releases": immutable,
        "qualification": "observed-not-verified", "controller_evidence": ["state": "unavailable", "reason": "Authenticated operator evidence transport is not configured"],
        "warning": "Settings observation is not policy approval, effective enforcement, pending-operation status or promotion authorization. No remote changes made."]
    print(String(decoding: try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self))
}
