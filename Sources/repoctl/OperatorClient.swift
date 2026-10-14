import Foundation

struct EnrollmentStatus: Codable {
    let protocolName: String
    let operationID: String
    let state: String
    let appID: Int?
    enum CodingKeys: String, CodingKey { case protocolName = "protocol", operationID, state, appID }
}

// Delegate owns one bounded response. Synchronization protects callback/state
// access; the private assertion stays in the ephemeral request, never output.
private final class OperatorReply: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var denied = false
    let done = DispatchSemaphore(value: 0)
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        let valid = (response as? HTTPURLResponse)?.statusCode == 200 && response.expectedContentLength <= 65536
        lock.withLock { if !valid { denied = true } }
        completionHandler(valid ? .allow : .cancel)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let cancel = lock.withLock { () -> Bool in
            if bytes.count + data.count > 65536 { denied = true; return true }
            bytes.append(data); return false
        }
        if cancel { dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        lock.withLock { denied = true }; completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.withLock { if error != nil { denied = true } }; done.signal()
    }
    func data() throws -> Data {
        try lock.withLock {
            guard !denied else { throw Failure("Operator request denied or outcome uncertain; reconcile remote state before retrying") }
            return bytes
        }
    }
}

struct OperatorClient {
    enum Action: String { case status, reconcile }
    let origin: URL
    let configuration: URLSessionConfiguration
    init(origin: String, configuration: URLSessionConfiguration = .ephemeral) throws {
        guard let parts = URLComponents(string: origin), parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              ["", "/"].contains(parts.path), parts.port == nil || parts.port == 443,
              let url = parts.url else { throw Failure("Operator origin must be an exact HTTPS origin") }
        self.origin = url; self.configuration = configuration
    }
    func request(_ action: Action, operationID: String, approvalReference: String, assertion: String) throws -> EnrollmentStatus {
        let hash = "^[a-f0-9]{64}$"
        guard operationID.range(of: hash, options: .regularExpression) != nil,
              approvalReference.range(of: hash, options: .regularExpression) != nil,
              assertion.utf8.count <= 16000,
              assertion.range(of: "^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$", options: .regularExpression) != nil else { throw Failure("Invalid operator enrollment request") }
        let reply = OperatorReply()
        let config = configuration.copy() as! URLSessionConfiguration
        config.urlCache = nil; config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.httpAdditionalHeaders = nil; config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false; config.timeoutIntervalForRequest = 10; config.timeoutIntervalForResource = 10
        let session = URLSession(configuration: config, delegate: reply, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: origin.appendingPathComponent("v1/operator/enrollment/"+action.rawValue))
        request.httpMethod = "POST"; request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(assertion, forHTTPHeaderField: "Cf-Access-Jwt-Assertion")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["operationID": operationID, "approvalReference": approvalReference])
        let task = session.dataTask(with: request); task.resume()
        guard reply.done.wait(timeout: .now()+12) == .success else { task.cancel(); throw Failure("Operator request timed out; reconcile remote state before retrying") }
        let result: EnrollmentStatus
        do { result = try JSONDecoder().decode(EnrollmentStatus.self, from: reply.data()) }
        catch { throw Failure("Operator request denied or outcome uncertain; reconcile remote state before retrying") }
        guard result.protocolName == "repoctl-operator-enrollment-v1", result.operationID == operationID,
              ["ready", "exchanging", "staged", "active"].contains(result.state), result.appID == nil || result.appID! > 0 else { throw Failure("Operator enrollment response binding differs") }
        return result
    }
}
