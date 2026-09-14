import XCTest
@testable import HearthKit

/// Вшитый адрес узла (ADR 0012) и адрес push-сервера в нём (ADR 0016).
final class HearthNodeTests: XCTestCase {
    private let valid = #"{"host":"relay.example.org","port":7444}"#

    private func parse(_ s: String) throws -> HearthNode {
        try HearthNode.parse(Data(s.utf8))
    }

    private func ntfNode(_ ntf: String) -> String {
        #"{"host":"relay.example.org","port":7444,"ntf":"\#(ntf)"}"#
    }

    func testParsesWhatTheBakeScriptWrites() throws {
        let node = try parse(valid)
        XCTAssertEqual(node.host, "relay.example.org")
        XCTAssertEqual(node.port, 7444)
        XCTAssertNil(node.ntf)
    }

    func testPortDefaultsToDeviceApi() throws {
        XCTAssertEqual(try parse(#"{"host":"h.example"}"#).port, HearthNode.defaultPort)
    }

    func testRefusesAUrlInsteadOfAHost() {
        // Подставлять из файла произвольный адрес нельзя даже когда файл свой.
        XCTAssertThrowsError(try parse(#"{"host":"https://evil.example/"}"#))
    }

    func testRefusesAnImpossiblePort() {
        XCTAssertThrowsError(try parse(#"{"host":"h.example","port":0}"#))
        XCTAssertThrowsError(try parse(#"{"host":"h.example","port":70000}"#))
    }

    func testIgnoresUnknownKeysButNotWrongTypes() throws {
        XCTAssertEqual(try parse(#"{"host":"h.example","extra":1}"#).host, "h.example")
        XCTAssertThrowsError(try parse(#"{"host":"h.example","port":"7444"}"#))
        XCTAssertThrowsError(try parse(#"{"port":7444}"#))
    }

    func testRefusesGarbageAndOversize() {
        XCTAssertThrowsError(try parse("not json"))
        XCTAssertThrowsError(try HearthNode.parse(Data()))
        let padding = String(repeating: "x", count: 5000)
        XCTAssertThrowsError(try parse(#"{"host":"h.example","pad":"\#(padding)"}"#))
    }

    func testAcceptsTheNodesOwnPushServer() throws {
        let ntf = "ntf://\(Fixtures.ntfFingerprint)@relay.example.org:5227"
        XCTAssertEqual(try parse(ntfNode(ntf)).ntf, ntf)
        // Регистр хоста не важен, как и везде при сравнении с узлом.
        XCTAssertNoThrow(try parse(ntfNode("ntf://\(Fixtures.ntfFingerprint)@RELAY.example.org:5227")))
        XCTAssertNil(try parse(#"{"host":"relay.example.org","ntf":null}"#).ntf)
    }

    func testRefusesAForeignPushServer() {
        // Главный случай: push-сервер SimpleX получил бы токен устройства и расписание уведомлений.
        XCTAssertThrowsError(try parse(ntfNode("ntf://\(Fixtures.ntfFingerprint)@ntf3.simplex.im:443")))
    }

    func testRefusesPushServerAddressesOfTheWrongShape() {
        for bad in [
            "ntf://fp:password@relay.example.org:5227",       // пароля у push-сервера нет
            "ntf://@relay.example.org:5227",                  // нет отпечатка
            "ntf://fp@relay.example.org",                     // нет порта
            "ntf://fp@relay.example.org:0",
            "ntf://fp@relay.example.org:99999",
            "ntf://fp@relay.example.org,abc.onion:5227",      // список хостов
            "smp://fp@relay.example.org:5227",                // не та схема
            "ntf://fp/x@relay.example.org:5227",
            "ntf://fp@relay.example.org:5227 ntf://fp@relay.example.org:1", // пробел разбил бы переменную ядра
        ] {
            XCTAssertThrowsError(try parse(ntfNode(bad)), bad)
        }
    }

    func testLoadsTheBakedNodeFromResources() throws {
        let bundle = try Fixtures.resourceBundle(["hearth_node.json": Data(valid.utf8)], testCase: self)
        XCTAssertEqual(HearthNode.loadBaked(from: bundle)?.host, "relay.example.org")
    }

    func testAMissingOrBrokenBakedNodeIsNil() throws {
        XCTAssertNil(HearthNode.loadBaked(from: try Fixtures.resourceBundle([:], testCase: self)))
        let broken = try Fixtures.resourceBundle(["hearth_node.json": Data(#"{"host":"https://x/"}"#.utf8)], testCase: self)
        XCTAssertNil(HearthNode.loadBaked(from: broken))
    }

    func testLoadsTheBakedCA() throws {
        let good = try Fixtures.resourceBundle(["hearth_ca.pem": Data(Fixtures.caPEM.utf8)], testCase: self)
        XCTAssertNotNil(HearthNode.loadBakedCA(from: good))
        let bad = try Fixtures.resourceBundle(["hearth_ca.pem": Data("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----".utf8)], testCase: self)
        XCTAssertNil(HearthNode.loadBakedCA(from: bad))
        XCTAssertNil(HearthNode.loadBakedCA(from: try Fixtures.resourceBundle([:], testCase: self)))
    }

    func testPEMMayCarrySurroundingText() {
        XCTAssertNotNil(HearthNode.certificate(fromPEM: "subject=CN=hearth\n" + Fixtures.caPEM + "\ntrailer"))
        XCTAssertNil(HearthNode.certificate(fromPEM: "no certificate here"))
    }
}
