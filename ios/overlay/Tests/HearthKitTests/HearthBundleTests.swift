import XCTest
@testable import HearthKit

/// The device-side half of the bundle contract (port of `HearthBundleTest.kt`, plus what
/// the node checks and the Android client did not).
///
/// Not ported: the importer tests (`HearthOnboardingImporter`) — orchestration against the
/// chat core lives in the app target, not in HearthKit.
final class HearthBundleTests: XCTestCase {
    private let host = "relay.example.org"

    private let valid = """
    {"v":1,
     "smp":["smp://fp1:pass1@relay.example.org:5223"],
     "xftp":["xftp://fp2:pass2@relay.example.org:5443"],
     "ice":["stun:relay.example.org:3478",
            "turn:1757160000:aGVhcnRoK2NyZWQ=@relay.example.org:3478"],
     "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
     "issued":"2026-09-06T12:00:00Z",
     "device":"mama-pixel8"}
    """

    private func parse(_ s: String) throws -> HearthBundle {
        try HearthBundle.parse(Data(s.utf8))
    }

    private func withNode(_ node: String) -> String {
        valid.replacingOccurrences(of: #""device":"mama-pixel8"}"#, with: #""device":"mama-pixel8","node":\#(node)}"#)
    }

    func testParsesTheDocumentHearthdProduces() throws {
        let bundle = try parse(valid)
        XCTAssertEqual(bundle.v, 1)
        XCTAssertEqual(bundle.device, "mama-pixel8")
        XCTAssertEqual(bundle.expectedHost, host)
        XCTAssertEqual(bundle.ice.count, 2)
        XCTAssertFalse(bundle.net.presetsEnabled)
        XCTAssertNil(bundle.node)
    }

    func testParsesWhatClaimReturns() throws {
        // Ответ /claim с узла, где релей на 8443, а TURN выключен до STUN.
        let claimed = """
        {"v":1,
         "smp":["smp://fp1:pass1@relay.example.org:8443"],
         "xftp":["xftp://fp2:pass2@relay.example.org:5443"],
         "ice":["stun:relay.example.org:3478"],
         "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
         "issued":"2026-09-10T12:00:00Z",
         "device":"xiaomi-22101316g"}
        """
        XCTAssertEqual(try parse(claimed).device, "xiaomi-22101316g")
    }

    func testRejectsAPublicRelay() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@relay.example.org:5223", with: "smp://fp1:pass1@smp8.simplex.im:5223")),
                             "a foreign relay must never be accepted")
    }

    func testRejectsAPublicStun() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "stun:relay.example.org:3478", with: "stun:stun.simplex.im:443")),
                             "a public STUN would leak the caller's address")
    }

    func testRejectsAMixedHostBundle() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "xftp://fp2:pass2@relay.example.org:5443", with: "xftp://fp2:pass2@other.example.org:5443")))
    }

    func testRejectsTurnWithoutCredentials() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "turn:1757160000:aGVhcnRoK2NyZWQ=@relay.example.org:3478", with: "turn:relay.example.org:3478")))
    }

    func testRejectsCredentialsTheClientWouldDiscard() {
        // A '/' in the credential starts a URI path; parseRTCIceServers then returns nil
        // for the whole list and the client silently falls back to public servers.
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "aGVhcnRoK2NyZWQ=", with: "aGVhcnRo/2NyZWQ=")))
    }

    func testRejectsEnabledOperatorPresets() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""presetsEnabled":false"#, with: #""presetsEnabled":true"#)))
    }

    func testRejectsNonInstantDelivery() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""ntfMode":"instant""#, with: #""ntfMode":"periodic""#)))
    }

    func testRejectsNonAlwaysPrivateRouting() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""privateRouting":"always""#, with: #""privateRouting":"unknown""#)))
    }

    func testRejectsARelayAddressWithoutAPassword() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp1@")))
        // An empty password is no password (bundle.rs).
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp1:@")))
    }

    func testRejectsAnUnsupportedVersion() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""v":1"#, with: #""v":2"#)))
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try parse("not json"))
        XCTAssertThrowsError(try parse(""))
        XCTAssertThrowsError(try parse("{}"))
    }

    func testAcceptsABareIpHost() throws {
        let bundle = try parse(valid.replacingOccurrences(of: "relay.example.org", with: "203.0.113.10"))
        XCTAssertEqual(bundle.expectedHost, "203.0.113.10")
    }

    func testRejectsSeparatorsInFingerprintAndPassword() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://f/p1:pass1@")))
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp1:pa/ss1@")))
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp1:pa:ss1@")))
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp1:pa ss1@")))
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "smp://fp1:pass1@", with: "smp://fp@1:pass1@")))
    }

    func testRejectsBadRelayPorts() {
        for port in [":0", ":70000", ":+5223", ""] {
            XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: "relay.example.org:5223", with: "relay.example.org\(port)")), port)
        }
    }

    func testRejectsMissingCallsAndBlankDevice() {
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""device":"mama-pixel8""#, with: #""device":"  ""#)))
        let noIce = """
        {"v":1,"smp":["smp://fp1:pass1@relay.example.org:5223"],
         "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
         "issued":"2026-09-06T12:00:00Z","device":"d"}
        """
        XCTAssertThrowsError(try parse(noIce), "without ICE the client would fall back to public servers")
        XCTAssertThrowsError(try parse(valid.replacingOccurrences(of: #""smp":["smp://fp1:pass1@relay.example.org:5223"]"#, with: #""smp":[]"#)))
    }

    func testXftpIsOptional() throws {
        let noXftp = valid.replacingOccurrences(of: #""xftp":["xftp://fp2:pass2@relay.example.org:5443"],"#, with: "")
        XCTAssertEqual(try parse(noXftp).xftp, [])
    }

    func testAcceptsTheNodeSectionForThisHost() throws {
        let bundle = try parse(withNode(#"{"host":"RELAY.example.org","port":7444,"token":"\#(Fixtures.deviceToken)"}"#))
        XCTAssertEqual(bundle.node, HearthNodeApi(host: "RELAY.example.org", port: 7444, token: Fixtures.deviceToken))
    }

    func testRejectsANodeSectionPointingElsewhere() {
        // A tampered bundle must not move later device-API calls to another server.
        XCTAssertThrowsError(try parse(withNode(#"{"host":"evil.example","port":7444,"token":"\#(Fixtures.deviceToken)"}"#)))
    }

    func testRejectsABadNodePortOrToken() {
        XCTAssertThrowsError(try parse(withNode(#"{"host":"relay.example.org","port":0,"token":"\#(Fixtures.deviceToken)"}"#)))
        XCTAssertThrowsError(try parse(withNode(#"{"host":"relay.example.org","port":70000,"token":"\#(Fixtures.deviceToken)"}"#)))
        XCTAssertThrowsError(try parse(withNode(#"{"host":"relay.example.org","port":7444,"token":"\#(Fixtures.deviceToken.uppercased())"}"#)))
        XCTAssertThrowsError(try parse(withNode(#"{"host":"relay.example.org","port":7444,"token":"abc"}"#)))
        XCTAssertThrowsError(try parse(withNode(#"{"host":"relay.example.org","port":7444,"token":"\#(String(repeating: "g", count: 64))"}"#)))
    }

    func testRejectsADocumentOverTheQrBudget() throws {
        let base = try parse(valid)
        let padded = valid.replacingOccurrences(of: #""device":"mama-pixel8""#, with: #""device":"\#(String(repeating: "d", count: 1024))""#)
        XCTAssertThrowsError(try parse(padded))
        XCTAssertLessThanOrEqual(Data(valid.utf8).count, HearthBundle.maxBytes)
        XCTAssertEqual(base.device, "mama-pixel8")
    }

    func testErrorsNeverQuoteTheRelayPassword() {
        let foreign = valid.replacingOccurrences(of: "xftp://fp2:pass2@relay.example.org:5443", with: "xftp://fp2:pass2@other.example.org:5443")
        XCTAssertThrowsError(try parse(foreign)) { error in
            XCTAssertFalse(String(describing: error).contains("pass2"), "\(error)")
        }
    }

    func testRoundTripsThroughCodable() throws {
        let bundle = try parse(withNode(#"{"host":"relay.example.org","port":7444,"token":"\#(Fixtures.deviceToken)"}"#))
        let again = try JSONDecoder().decode(HearthBundle.self, from: JSONEncoder().encode(bundle))
        XCTAssertEqual(again, bundle)
        XCTAssertNoThrow(try again.validate())
    }
}
