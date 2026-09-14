import XCTest
@testable import HearthKit

/// ICE entries and TURN refresh (port of `HearthTurnPolicyTest.kt`, plus the iOS parser).
///
/// Not ported: `without_a_known_host_the_old_behaviour_stays` — on iOS the expected host is
/// always known (it comes with the claimed bundle), so the API has no "no host" mode.
final class HearthIceTests: XCTestCase {
    private let host = "relay.myhearth.ru"

    private func payload(_ ice: [String], expires: String? = nil) throws -> Data {
        var object: [String: Any] = ["username": "u", "credential": "c", "ice": ice]
        if let expires = expires { object["expires"] = expires }
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func validated(_ ice: [String]) throws -> [String] {
        try HearthTurnCredentials.parse(payload(ice)).validated(expectedHost: host)
    }

    func testOurOwnTurnIsAccepted() throws {
        XCTAssertEqual(try validated(["stun:\(host):3478", "turn:u:c@\(host):3478"]).count, 2)
    }

    func testAForeignTurnIsRefused() {
        // Главный случай: узел захвачен и уводит звонки через чужой сервер, которому
        // достаются адреса обоих собеседников.
        XCTAssertThrowsError(try validated(["turn:u:c@evil.example:3478"]))
    }

    func testAPublicStunIsRefused() {
        XCTAssertThrowsError(try validated(["stun:stun.l.google.com:19302"]))
    }

    func testOneForeignEntryPoisonsTheWholeList() {
        XCTAssertThrowsError(try validated(["stun:\(host):3478", "turn:u:c@evil.example:3478"]))
    }

    func testAnEmptyListIsRefused() {
        XCTAssertThrowsError(try validated([]))
    }

    func testANewlineIsRefused() {
        XCTAssertThrowsError(try validated(["stun:\(host):3478\nstun:evil.example:3478"]))
    }

    func testExpiresIsOptionalAndGarbageIsRefused() throws {
        XCTAssertEqual(try HearthTurnCredentials.parse(payload(["stun:\(host):3478"])).expires, "")
        XCTAssertEqual(try HearthTurnCredentials.parse(payload(["stun:\(host):3478"], expires: "2026-10-14T00:00:00Z")).expires, "2026-10-14T00:00:00Z")
        XCTAssertThrowsError(try HearthTurnCredentials.parse(Data("{}".utf8)))
    }

    func testWhatTheNodeMintsIsAccepted() {
        // configgen/turn.rs: bare unix expiry as the username, base64 HMAC without '/'.
        for entry in [
            "stun:\(host):3478",
            "turn:1757160000:aGVhcnRoK2NyZWQ=@\(host):3478",
            "turn:1757160000:a+b=@\(host):3478",
            "stuns:\(host):5349",
            "turns:1757160000:aGVhcnRoK2NyZWQ=@\(host):5349?transport=tcp",
            "stun:RELAY.myhearth.ru:3478",
        ] {
            XCTAssertNoThrow(try HearthIce.requireEntry(entry, expectedHost: host), entry)
        }
        XCTAssertNoThrow(try HearthIce.requireEntry("stun:203.0.113.10:3478", expectedHost: "203.0.113.10"))
    }

    func testEntriesTheIosClientWouldDiscardAreRefused() {
        for entry in [
            "stun:\(host)",                            // no port: URL.port is nil
            "turn:u:c@\(host):3478/x",                 // a path
            "turn:u:c@\(host):3478 ",                  // whitespace
            "STUN:\(host):3478",                       // the client compares schemes case-sensitively
            "turn:u@\(host):3478",                     // no credential
            "turn:u:c/d@\(host):3478",                 // '/' in credentials
            "turn:u:c@evil@\(host):3478",              // two '@'
            "turn:\(host):3478",
            "stun:\(host):0",
            "stun:\(host):70000",
            "stun::3478",
            "http://\(host):3478",
            "",
        ] {
            XCTAssertThrowsError(try HearthIce.requireEntry(entry, expectedHost: host), entry.debugDescription)
        }
    }

    func testTheCopiedParserReadsWhatTheClientReads() {
        XCTAssertEqual(
            HearthIce.clientParse("turns:1757160000:aGVhcnRoK2NyZWQ=@\(host):5349?transport=tcp"),
            HearthIce.Parsed(scheme: "turns", host: host, port: 5349, user: "1757160000", password: "aGVhcnRoK2NyZWQ=")
        )
        XCTAssertEqual(HearthIce.clientParse("stun:\(host):3478"), HearthIce.Parsed(scheme: "stun", host: host, port: 3478, user: nil, password: nil))
        XCTAssertNil(HearthIce.clientParse("stun:\(host)"))
    }

    func testNoExpectedHostMeansNothingIsAccepted() {
        XCTAssertThrowsError(try HearthIce.requireEntry("stun:\(host):3478", expectedHost: ""))
    }
}
