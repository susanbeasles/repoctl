import Foundation

func enrollmentCommand(_ args: [String]) throws {
    let usage = "repoctl app status|reconcile OPERATION --approval REFERENCE --controller HTTPS_ORIGIN --access ABSOLUTE_CLOUDFLARED_PATH\nUses an existing application-scoped Access session; never starts login or prints credentials."
    guard args.count == 9, let action = OperatorClient.Action(rawValue: args[1]) else {throw Failure(usage)}
    var options: [String: String] = [:]
    for index in stride(from: 3, to: args.count, by: 2) {
        let flag = args[index]
        guard ["--approval", "--controller", "--access"].contains(flag), options[flag] == nil else {throw Failure(usage)}
        options[flag] = args[index+1]
    }
    guard let reference = options["--approval"], let origin = options["--controller"], let executable = options["--access"],
          args[2].range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
          reference.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {throw Failure(usage)}
    let client = try OperatorClient(origin: origin), session = try AccessSession(executable: executable)
    let result = try client.request(action, operationID: args[2], approvalReference: reference, assertion: session.assertion(origin: origin))
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    print(String(decoding: try encoder.encode(result), as: UTF8.self))
}
