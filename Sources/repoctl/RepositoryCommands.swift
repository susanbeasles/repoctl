import Foundation

// Authentication remains in the user's selected gh account; never print tokens.
struct GitHubClient {
    func request(_ path: String, method: String = "GET", body: Any? = nil) throws -> Any {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        var args = ["gh", "api", "--hostname", "github.com", "--method", method,
                    "-H", "X-GitHub-Api-Version: 2026-03-10", path]
        let input = Pipe()
        if body != nil { args += ["--input", "-"] }
        process.arguments = args
        process.standardInput = input
        // File-backed output avoids pipe-buffer deadlock on large rule inventories.
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let outURL = directory.appendingPathComponent("out"), errURL = directory.appendingPathComponent("err")
        FileManager.default.createFile(atPath: outURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: errURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let outHandle = try FileHandle(forWritingTo: outURL), errHandle = try FileHandle(forWritingTo: errURL)
        defer { try? outHandle.close(); try? errHandle.close() }
        process.standardOutput = outHandle; process.standardError = errHandle
        try process.run()
        if let body { input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: body)) }
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
        try require(process.terminationStatus == 0,
                    "GitHub request failed: \(method) \(path); run gh auth status and verify repository administration permission (exit \(process.terminationStatus))")
        let data = try Data(contentsOf: outURL)
        return data.isEmpty ? [:] : try JSONSerialization.jsonObject(with: data)
    }
    func rules(_ repo: String) throws -> [[String: Any]] {
        var result: [[String: Any]] = [], page = 1
        while true {
            guard let items = try request("repos/\(repo)/rulesets?per_page=100&page=\(page)&includes_parents=true") as? [[String: Any]] else { throw Failure("Invalid ruleset list") }
            result += items
            if items.count < 100 { return result }; page += 1
        }
    }
}
func normalizedRule(_ rule: [String: Any]) -> [String: Any] {
    var result: [String: Any] = [:]
    for key in ["name", "target", "enforcement", "conditions", "rules", "bypass_actors"] { result[key] = rule[key] }
    return result
}
func sameJSON(_ a: Any, _ b: Any) -> Bool {
    guard let first = try? JSONSerialization.data(withJSONObject: a, options: [.sortedKeys]),
          let second = try? JSONSerialization.data(withJSONObject: b, options: [.sortedKeys]) else { return false }
    return first == second
}
func bootstrapRules(ownerID: Int) -> [[String: Any]] {
    let protected = ["~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master"]
    func rule(_ name: String, target: String, include: [String], exclude: [String] = [],
              types: [String], bypass: [[String: Any]] = []) -> [String: Any] {
        let rules: [[String: Any]] = types.map { type in
            type == "update" ? ["type": type, "parameters": ["update_allows_fetch_and_merge": false]] : ["type": type]
        }
        return ["name": "repoctl/bootstrap-v1/" + name, "target": target, "enforcement": "active",
                "conditions": ["ref_name": ["include": include, "exclude": exclude]],
                "rules": rules, "bypass_actors": bypass]
    }
    return [
        rule("owner-branches", target: "branch", include: ["~ALL"], exclude: protected,
             types: ["creation", "update", "deletion"],
             bypass: [["actor_id": ownerID, "actor_type": "User", "bypass_mode": "always"]]),
        rule("protected-locked", target: "branch", include: protected,
             types: ["creation", "update", "deletion", "non_fast_forward", "required_linear_history", "required_signatures"]),
        rule("tags", target: "tag", include: ["~ALL"], types: ["update", "deletion"]),
        rule("tag-creation", target: "tag", include: ["~ALL"], types: ["creation"],
             bypass: [["actor_id": ownerID, "actor_type": "User", "bypass_mode": "always"]])
    ]
}
func repositoryCommand(_ args: [String]) throws {
    try require(args.count >= 3, "Usage: repoctl repo inspect|plan|apply|verify OWNER/REPO [--accept-locked-bootstrap]")
    let action = args[1], repo = args[2]
    try require(repo.range(of: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", options: .regularExpression) != nil, "Invalid OWNER/REPO")
    try require(["inspect", "plan", "apply", "verify"].contains(action), "Unknown repo command")
    try require(args.count == 3 || (action == "apply" && Array(args.dropFirst(3)) == ["--accept-locked-bootstrap"]), "Unexpected options")
    let client = GitHubClient()
    guard let identity = try client.request("user") as? [String: Any],
          let metadata = try client.request("repos/\(repo)") as? [String: Any],
          let owner = metadata["owner"] as? [String: Any], let ownerID = owner["id"] as? Int,
          let repositoryID = metadata["id"] as? Int else { throw Failure("Invalid repository identity") }
    let inventory = try client.rules(repo)
    if action == "inspect" {
        print(String(decoding: try JSONSerialization.data(withJSONObject: ["repository": metadata, "authenticated_user": identity, "rulesets": inventory], options: [.prettyPrinted, .sortedKeys]), as: UTF8.self))
        return
    }
    try require(owner["type"] as? String == "User" && identity["id"] as? Int == ownerID,
                "Personal bootstrap requires authentication as the exact repository owner; organizations need a separate profile")
    try require((metadata["permissions"] as? [String: Any])?["admin"] as? Bool == true, "Repository administration permission required")
    try require(metadata["archived"] as? Bool != true && metadata["fork"] as? Bool != true, "Archived/fork repository not supported by bootstrap")
    guard let branch = metadata["default_branch"] as? String,
          let encoded = branch.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else { throw Failure("Missing default branch") }
    _ = try client.request("repos/\(repo)/branches/\(encoded)") // Seed must exist before locking.
    let desired = bootstrapRules(ownerID: ownerID)
    if action == "plan" {
        let plan: [String: Any] = ["profile": "locked-bootstrap", "repository_id": repositoryID,
            "repository": repo, "authenticated_user_id": ownerID, "rulesets": desired,
            "actions_enabled": true, "immutable_releases": true,
            "warning": "Main is locked to every writer, including owner. No promotion App is configured. Working branches remain owner-only. Tags cannot move/delete; only owner may create them in this phase. No remote changes made."]
        print(String(decoding: try JSONSerialization.data(withJSONObject: plan, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)); return
    }
    if action == "apply" {
        try require(args.last == "--accept-locked-bootstrap", "Review repo plan first; apply requires --accept-locked-bootstrap because main will reject all updates and no promotion writer is configured")
        // Fail before mutation if a managed name collides with inherited rules.
        for rule in desired {
            let matches = inventory.filter { $0["name"] as? String == rule["name"] as? String }
            try require(matches.count <= 1, "Duplicate managed ruleset name; resolve before apply")
            if let match = matches.first {
                try require(match["source_type"] as? String == "Repository" && (match["source"] as? String)?.lowercased() == repo.lowercased(), "Managed ruleset name collides with an inherited ruleset")
            }
        }
        // Require an explicitly configured Actions policy; never disable Actions.
        try actionsCommand(["actions", "verify", repo])
        for rule in desired {
            if let old = inventory.first(where: { $0["name"] as? String == rule["name"] as? String }), let id = old["id"] as? Int {
                let actual = try client.request("repos/\(repo)/rulesets/\(id)")
                if let actual = actual as? [String: Any], sameJSON(normalizedRule(actual), rule) { continue }
                _ = try client.request("repos/\(repo)/rulesets/\(id)", method: "PUT", body: rule)
            } else { _ = try client.request("repos/\(repo)/rulesets", method: "POST", body: rule) }
        }
        _ = try client.request("repos/\(repo)/immutable-releases", method: "PUT")
        // No automatic rollback removes safety rules if a later call fails. Rerun to resume.
    }
    try actionsCommand(["actions", "verify", repo])
    let current = try client.rules(repo)
    for rule in desired {
        let matches = current.filter { $0["name"] as? String == rule["name"] as? String }
        try require(matches.count == 1, "Ruleset missing/duplicated: \(rule["name"] ?? "")")
        guard let id = matches[0]["id"] as? Int,
              let actual = try client.request("repos/\(repo)/rulesets/\(id)") as? [String: Any] else { throw Failure("Invalid ruleset response") }
        try require(sameJSON(normalizedRule(actual), rule), "Managed ruleset drift detected: \(rule["name"] ?? "")")
    }
    let actions = try client.request("repos/\(repo)/actions/permissions") as? [String: Any]
    let releases = try client.request("repos/\(repo)/immutable-releases") as? [String: Any]
    try require(actions?["enabled"] as? Bool == true, "Actions must be enabled")
    try require(releases?["enabled"] as? Bool == true, "Immutable releases are not enabled")
    print("Verified managed locked-bootstrap configuration for \(repo). Inherited/unmanaged rules preserved; behavioral enforcement tests and promotion setup remain pending.")
}
