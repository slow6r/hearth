import XCTest
@testable import HearthKit

/// Транспорт до device API на заглушке вместо сети: какие запросы уходят, как читаются
/// ответы и чего клиент не отправляет вовсе. TLS здесь не участвует — он в HearthPinningTests.
final class HearthNodeClientTests: XCTestCase {
    private let code = "H7K4P9QXM3TV"

    private let bundle = """
    {"v":1,"smp":["smp://fp1:pass1@relay.example.org:8443"],"xftp":["xftp://fp2:pass2@relay.example.org:5443"],"ice":["stun:relay.example.org:3478"],"net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},"issued":"2026-09-10T12:00:00Z","device":"iphone-15"}
    """

    override func setUp() {
        super.setUp()
        StubProtocol.set(.init(status: 500, body: Data()))
    }

    private func client() throws -> HearthNodeClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        let node = try HearthNode(host: "relay.example.org", port: 7444)
        let anchor = try XCTUnwrap(HearthNode.certificate(fromPEM: Fixtures.caPEM))
        return HearthNodeClient(node: node, anchor: anchor, session: config)
    }

    private func expect(_ expected: HearthNodeError, file: StaticString = #filePath, line: UInt = #line,
                        _ operation: () async throws -> Void) async {
        do {
            try await operation()
            XCTFail("ожидалась ошибка \(expected)", file: file, line: line)
        } catch let error as HearthNodeError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("не та ошибка: \(error)", file: file, line: line)
        }
    }

    private func expectBadResponse(file: StaticString = #filePath, line: UInt = #line, _ operation: () async throws -> Void) async {
        do {
            try await operation()
            XCTFail("ожидался badResponse", file: file, line: line)
        } catch HearthNodeError.badResponse {
        } catch {
            XCTFail("не та ошибка: \(error)", file: file, line: line)
        }
    }

    func testAGoodCodeReturnsTheBundleAndTheBytesAsReceived() async throws {
        StubProtocol.set(.init(status: 200, body: Data(bundle.utf8)))
        let (parsed, raw) = try await client().claim(code: code, deviceName: "iPhone", installId: "install-1")
        XCTAssertEqual(parsed.device, "iphone-15")
        XCTAssertEqual(raw, Data(bundle.utf8))
    }

    func testTheClaimRequestHasTheShapeTheNodeExpects() async throws {
        StubProtocol.set(.init(status: 200, body: Data(bundle.utf8)))
        let name = "  " + String(repeating: "я", count: 60) + "  "
        _ = try await client().claim(code: " h7k4-p9qx-m3tv ", deviceName: name, installId: " install-1 ")

        let request = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertEqual(StubProtocol.requests.count, 1)
        XCTAssertEqual(request.url?.absoluteString, "https://relay.example.org:7444/claim")
        XCTAssertEqual(request.httpMethod, "POST")
        // Узел хранит канонический вид и сравнивает посимвольно.
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-hearth-invite-token"), code)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: String])
        XCTAssertEqual(body["name"], String(repeating: "я", count: 48))
        XCTAssertEqual(body["install_id"], "install-1")
        XCTAssertEqual(body["platform"], "ios")
    }

    func testAnIncompleteCodeNeverReachesTheNode() async throws {
        let client = try client()
        await expect(.badRequest) { _ = try await client.claim(code: "H7K4-P9QX", deviceName: "iPhone", installId: "i") }
        XCTAssertTrue(StubProtocol.requests.isEmpty, "неполный код не должен тратить попытку у узла")
    }

    func testNodeRefusalsAreMappedToWhatAPersonCanActOn() async throws {
        let client = try client()
        for (status, expected) in [(401, HearthNodeError.refused), (429, .throttled), (409, .noSlots), (400, .badRequest),
                                   (500, .status(500)), (302, .status(302)), (404, .status(404))] {
            StubProtocol.set(.init(status: status, body: Data("unknown invite".utf8)))
            await expect(expected) { _ = try await client.claim(code: code, deviceName: "iPhone", installId: "i") }
        }
    }

    func testABundleTheClientRefusesIsNotSilentlyAccepted() async throws {
        let client = try client()
        StubProtocol.set(.init(status: 200, body: Data(#"{"v":1}"#.utf8)))
        await expectBadResponse { _ = try await client.claim(code: code, deviceName: "iPhone", installId: "i") }
        let foreign = bundle.replacingOccurrences(of: "stun:relay.example.org:3478", with: "stun:stun.simplex.im:443")
        StubProtocol.set(.init(status: 200, body: Data(foreign.utf8)))
        await expectBadResponse { _ = try await client.claim(code: code, deviceName: "iPhone", installId: "i") }
    }

    func testAnOversizedResponseIsRefused() async throws {
        let client = try client()
        StubProtocol.set(.init(status: 200, body: Data(repeating: 0x20, count: 70 * 1024)))
        await expectBadResponse { _ = try await client.claim(code: code, deviceName: "iPhone", installId: "i") }
    }

    func testDeviceNamesAreCutByCharactersTheNodeCounts() {
        XCTAssertEqual(HearthNodeClient.deviceName("  iPhone 15 Pro  "), "iPhone 15 Pro")
        // Флаг — два Unicode-символа: 30 флагов = 60 символов у узла, режем по целым флагам.
        let flags = HearthNodeClient.deviceName(String(repeating: "🇷🇺", count: 30))
        XCTAssertEqual(flags.unicodeScalars.count, 48)
        XCTAssertEqual(flags, String(repeating: "🇷🇺", count: 24))
    }

    func testTurnCredentialsAreFetchedWithTheDeviceToken() async throws {
        let body = #"{"username":"1757160000","credential":"c2VjcmV0","ice":["stun:relay.example.org:3478","turn:1757160000:c2VjcmV0@relay.example.org:3478"],"expires":"2026-10-14T00:00:00Z"}"#
        StubProtocol.set(.init(status: 200, body: Data(body.utf8)))
        let ice = try await client().turnCredentials(deviceToken: Fixtures.deviceToken)
        XCTAssertEqual(ice.count, 2)
        let request = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertEqual(request.url?.absoluteString, "https://relay.example.org:7444/turn-credentials")
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-hearth-device-token"), Fixtures.deviceToken)
        XCTAssertNil(request.value(forHTTPHeaderField: "x-hearth-invite-token"))
    }

    func testTurnDisabledOnTheNodeIs404() async throws {
        let client = try client()
        StubProtocol.set(.init(status: 404, body: Data("turn is disabled".utf8)))
        await expect(.status(404)) { _ = try await client.turnCredentials(deviceToken: Fixtures.deviceToken) }
    }

    func testAForeignTurnFromTheNodeIsRefused() async throws {
        let client = try client()
        let body = #"{"username":"u","credential":"c","ice":["turn:u:c@evil.example:3478"]}"#
        StubProtocol.set(.init(status: 200, body: Data(body.utf8)))
        await expectBadResponse { _ = try await client.turnCredentials(deviceToken: Fixtures.deviceToken) }
    }

    func testABadDeviceTokenNeverReachesTheNode() async throws {
        let client = try client()
        await expect(.badRequest) { _ = try await client.turnCredentials(deviceToken: "abc") }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    func testRedirectsAreRefused() throws {
        let client = try client()
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let url = try XCTUnwrap(URL(string: "https://relay.example.org:7444/claim"))
        let task = session.dataTask(with: url)
        let response = try XCTUnwrap(HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: ["Location": "https://evil.example/"]))
        var followed: URLRequest? = URLRequest(url: url)
        client.pinning.urlSession(session, task: task, willPerformHTTPRedirection: response,
                                  newRequest: URLRequest(url: try XCTUnwrap(URL(string: "https://evil.example/")))) { followed = $0 }
        XCTAssertNil(followed)
    }

    func testChallengesOtherThanOurServerTrustAreCancelled() throws {
        let client = try client()
        for (host, method) in [("relay.example.org", NSURLAuthenticationMethodHTTPBasic),
                               ("relay.example.org", NSURLAuthenticationMethodClientCertificate),
                               ("evil.example", NSURLAuthenticationMethodServerTrust),
                               // Метод верный, но доверия в пространстве нет — проверять нечего.
                               ("relay.example.org", NSURLAuthenticationMethodServerTrust)] {
            let space = URLProtectionSpace(host: host, port: 7444, protocol: "https", realm: nil, authenticationMethod: method)
            let challenge = URLAuthenticationChallenge(protectionSpace: space, proposedCredential: nil, previousFailureCount: 0,
                                                       failureResponse: nil, error: nil, sender: NoSender())
            let (disposition, credential) = client.pinning.decide(challenge)
            XCTAssertEqual(disposition, .cancelAuthenticationChallenge, "\(host) \(method)")
            XCTAssertNil(credential)
        }
    }

    func testABuildWithoutNodeOrCertificateIsIncomplete() throws {
        let nodeOnly = try Fixtures.resourceBundle(["hearth_node.json": Data(#"{"host":"relay.example.org"}"#.utf8)], testCase: self)
        XCTAssertThrowsError(try HearthNodeClient.baked(in: nodeOnly)) { XCTAssertEqual($0 as? HearthNodeError, .incompleteBuild) }
        let caOnly = try Fixtures.resourceBundle(["hearth_ca.pem": Data(Fixtures.caPEM.utf8)], testCase: self)
        XCTAssertThrowsError(try HearthNodeClient.baked(in: caOnly)) { XCTAssertEqual($0 as? HearthNodeError, .incompleteBuild) }
        let both = try Fixtures.resourceBundle([
            "hearth_node.json": Data(#"{"host":"relay.example.org"}"#.utf8),
            "hearth_ca.pem": Data(Fixtures.caPEM.utf8),
        ], testCase: self)
        XCTAssertEqual(try HearthNodeClient.baked(in: both).node.host, "relay.example.org")
    }
}

final class NoSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
}

/// Узел-заглушка: отвечает заданным статусом и телом и запоминает запросы.
final class StubProtocol: URLProtocol {
    struct Reply {
        var status: Int
        var body: Data
    }

    private static let lock = NSLock()
    private static var reply = Reply(status: 500, body: Data())
    private static var recorded: [URLRequest] = []

    static func set(_ newReply: Reply) {
        lock.lock()
        reply = newReply
        recorded = []
        lock.unlock()
    }

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var copy = request
        // URLSession переносит тело в поток — достаём обратно, чтобы тест мог его прочитать.
        if copy.httpBody == nil, let stream = copy.httpBodyStream {
            copy.httpBody = Self.readAll(stream)
        }
        Self.lock.lock()
        Self.recorded.append(copy)
        let reply = Self.reply
        Self.lock.unlock()

        guard let url = request.url,
              let response = HTTPURLResponse(url: url, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: nil)
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readAll(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return data
    }
}
