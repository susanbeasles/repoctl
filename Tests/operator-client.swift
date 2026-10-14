import Foundation
struct Failure: Error { let message: String; init(_ message: String) {self.message = message} }
private final class FixtureState: @unchecked Sendable {
    let lock = NSLock()
    var mode = "good"
    var calls = 0
    var requests: [URLRequest] = []
    func select(_ value: String) {lock.withLock {mode = value}}
}
private final class Fixture: URLProtocol, @unchecked Sendable {
    static let state = FixtureState()
    override class func canInit(with request: URLRequest) -> Bool {true}
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {request}
    override func startLoading() {
        let mode = Self.state.lock.withLock {Self.state.calls += 1; Self.state.requests.append(request); return Self.state.mode}
        let operation = String(repeating: "a", count: 64)
        var body: [String: Any] = ["protocol": "repoctl-operator-enrollment-v1", "operationID": operation, "state": "active", "appID": 12, "token": "SECRET"]
        if mode == "foreign" {body["operationID"] = String(repeating: "b", count: 64)}
        if mode == "state" {body["state"] = "unverified"}
        let response = HTTPURLResponse(url: request.url!, statusCode: mode == "denied" ? 403 : 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let data = mode == "oversized" ? Data(repeating: 65, count: 65537) : try! JSONSerialization.data(withJSONObject: body)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
@main struct Check {
    static func main() throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [Fixture.self]; config.httpAdditionalHeaders = ["Authorization": "SECRET", "Cookie": "SECRET"]
        let client = try OperatorClient(origin: "https://operator.example", configuration: config)
        let operation = String(repeating: "a", count: 64), reference = String(repeating: "b", count: 64)
        let result = try client.request(.status, operationID: operation, approvalReference: reference, assertion: "synthetic.header.signature")
        precondition(result.operationID == operation && result.appID == 12)
        let output = try JSONEncoder().encode(result)
        precondition(!String(decoding: output, as: UTF8.self).contains("SECRET"))
        for mode in ["foreign", "state", "denied", "oversized"] {
            Fixture.state.select(mode)
            do { _ = try client.request(.reconcile, operationID: operation, approvalReference: reference, assertion: "synthetic.header.signature"); fatalError("Expected rejection") }
            catch {precondition(!String(describing: error).contains("SECRET"))}
        }
        let requests = Fixture.state.lock.withLock {Fixture.state.requests}
        precondition(requests.count == 5)
        for request in requests {
            precondition(request.httpMethod == "POST" && request.url?.host == "operator.example")
            precondition(request.value(forHTTPHeaderField: "Cf-Access-Jwt-Assertion") == "synthetic.header.signature")
            precondition(request.value(forHTTPHeaderField: "Cookie") == nil && request.value(forHTTPHeaderField: "Authorization") == nil)
        }
        for origin in ["http://operator.example", "https://name:SECRET@operator.example", "https://operator.example/path", "https://operator.example?token=SECRET"] {
            do {_ = try OperatorClient(origin: origin); fatalError("Invalid origin accepted")} catch {}
        }
        let before = Fixture.state.lock.withLock {Fixture.state.calls}
        do {_ = try client.request(.status, operationID: operation, approvalReference: reference, assertion: "SECRET\r\nX: injected"); fatalError("Invalid assertion accepted")} catch {}
        precondition(Fixture.state.lock.withLock {Fixture.state.calls} == before)
        print("PASS: native ephemeral operator transport, exact binding, denied/oversized response, token-free projection and pre-network origin/header validation; synthetic transport")
    }
}
