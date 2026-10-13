import Foundation

let managedActionsName = "repoctl/v1/actions"
func actionsPolicy(ownerID: Int, appID: Int? = nil) -> [String: Any] {
    var actors: [[String: Any]] = [["id": ownerID, "type": "User"]]
    if let appID { actors.append(["id": appID, "type": "App"]) }
    return ["name": managedActionsName, "enforcement": "active",
            "conditions": ["workflow_path": ["include": ["~ALL"], "exclude": [String]()]],
            "rules": [
        ["type": "restrict_actions_actors", "parameters": ["allowed_actors": actors]],
        ["type": "restrict_action_events", "parameters": ["allowed_events": ["push", "workflow_dispatch", "workflow_call"]]]
    ]]
}
func actionPolicies(_ client: GitHubClient, _ repo: String) throws -> [[String: Any]] {
    var result: [[String: Any]] = [], page = 1
    while page <= 20 {
        guard let response = try client.request("repos/\(repo)/actions/policies?per_page=100&page=\(page)&has_parents=true") as? [String: Any],
              let items = response["policies"] as? [[String: Any]] else { throw Failure("Invalid Actions policy inventory") }
        try require(items.count <= 100, "Oversized Actions policy page")
        result += items
        if items.count < 100 { return result }
        page += 1
    }
    throw Failure("Actions policy inventory exceeds 2000 entries; observation incomplete")
}
func normalizedActions(_ policy: [String: Any]) -> [String: Any] {
    var result: [String: Any] = [:]
    for key in ["name", "enforcement", "rules", "conditions"] { result[key] = policy[key] }
    return result
}
func reconcileActions(_ client: GitHubClient, _ repo: String, _ desired: [String: Any], apply: Bool) throws {
    let matches = try actionPolicies(client, repo).filter { $0["name"] as? String == managedActionsName }
    try require(matches.count <= 1, "Duplicate managed Actions policy")
    if let old = matches.first {
        try require(old["source_type"] as? String == "Repository" && (old["source"] as? String)?.lowercased() == repo.lowercased(), "Managed Actions name collides with inherited policy")
        guard let id = old["id"] as? Int else { throw Failure("Missing Actions policy ID") }
        let actual = try client.request("repos/\(repo)/actions/policies/\(id)") as? [String: Any]
        if !sameJSON(normalizedActions(actual ?? [:]), desired) {
            try require(apply, "Managed Actions policy differs from requested owner/App configuration")
            _ = try client.request("repos/\(repo)/actions/policies/\(id)", method: "PUT", body: desired)
        }
    } else {
        try require(apply, "Managed Actions policy is missing")
        _ = try client.request("repos/\(repo)/actions/policies", method: "POST", body: desired)
    }
    if apply {
        // Confirm actor/event enforcement and narrow the workflow token before
        // enabling workflows. Preserve allowed_actions and existing allowlists.
        try reconcileActions(client, repo, desired, apply: false)
        _ = try client.request("repos/\(repo)/actions/permissions/workflow", method: "PUT", body: ["default_workflow_permissions": "read", "can_approve_pull_request_reviews": false])
        let workflow = try client.request("repos/\(repo)/actions/permissions/workflow") as? [String: Any]
        try require(workflow?["default_workflow_permissions"] as? String == "read" && workflow?["can_approve_pull_request_reviews"] as? Bool == false,
                    "Workflow token policy not confirmed; Actions was not enabled")
        // Repeat policy observation after the token change; a concurrent drift
        // must not be silently repaired or followed by Actions activation.
        try reconcileActions(client, repo, desired, apply: false)
        _ = try client.request("repos/\(repo)/actions/permissions", method: "PUT", body: ["enabled": true])
    }
}
func actionsCommand(_ args: [String]) throws {
    let usage = "repoctl actions inspect|plan|apply|verify OWNER/REPO [--app SLUG]\nOwner-only push/dispatch/call; no outsider/fork PR triggers. App is optional and explicitly authorized. No promotion pipeline installed."
    if args == ["actions", "--help"] { print(usage); return }
    try require(args.count == 3 || args.count == 5, usage)
    let action = args[1], repo = args[2]
    try require(["inspect", "plan", "apply", "verify"].contains(action) && repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil, usage)
    let client = GitHubClient()
    guard let user = try client.request("user") as? [String: Any],
          let metadata = try client.request("repos/\(repo)") as? [String: Any],
          let owner = metadata["owner"] as? [String: Any], let ownerID = owner["id"] as? Int else { throw Failure("Invalid owner identity") }
    try require(owner["type"] as? String == "User" && user["id"] as? Int == ownerID && (metadata["permissions"] as? [String: Any])?["admin"] as? Bool == true, "Authenticate as this personal repository's owner/admin")
    var appID: Int?
    if args.count == 5 {
        try require(args[3] == "--app" && args[4].range(of: "^[A-Za-z0-9-]+$", options: .regularExpression) != nil, usage)
        guard let app = try client.request("apps/\(args[4])") as? [String: Any], let id = app["id"] as? Int else { throw Failure("Cannot resolve GitHub App") }
        appID = id
    }
    let desired = actionsPolicy(ownerID: ownerID, appID: appID)
    if action == "inspect" || action == "plan" {
        let output: [String: Any] = action == "plan" ? ["repository": repo, "actions_enabled": true, "policy": desired, "default_token_permissions": "read", "automatic_pr_approval": false] : ["permissions": try client.request("repos/\(repo)/actions/permissions"), "policies": try actionPolicies(client, repo)]
        print(String(decoding: try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)); return
    }
    try reconcileActions(client, repo, desired, apply: action == "apply")
    let enabled = try client.request("repos/\(repo)/actions/permissions") as? [String: Any]
    let workflow = try client.request("repos/\(repo)/actions/permissions/workflow") as? [String: Any]
    try require(enabled?["enabled"] as? Bool == true && workflow?["default_workflow_permissions"] as? String == "read" && workflow?["can_approve_pull_request_reviews"] as? Bool == false, "Actions settings drift detected")
    print("Verified Actions enabled with managed owner/event restrictions. Existing action allowlists and other policies preserved. Promotion remains separate.")
}
