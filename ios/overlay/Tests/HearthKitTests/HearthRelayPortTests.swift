import XCTest
@testable import HearthKit

/// Переписывание адреса своего релея на порт 8443 (port of `HearthRelayPortTest.kt`).
///
/// Ошибка здесь не падает, а тихо оставляет телефон на порту, который режут. Поэтому
/// проверяется каждый случай, включая те, которые трогать нельзя.
final class HearthRelayPortTests: XCTestCase {
    private let host = "relay.myhearth.ru"
    private let fp = "dl4E-N71pfkpNzTLXnI5sHuAeT-zDx21sCkqMCQNk9M="

    func testAnExplicit5223MovesTo8443() {
        XCTAssertEqual(HearthRelayPort.migrate("smp://\(fp):pass_123-x@\(host):5223", ownHost: host), "smp://\(fp):pass_123-x@\(host):8443")
    }

    func testAMissingPortMeans5223AndAlsoMoves() {
        XCTAssertEqual(HearthRelayPort.migrate("smp://\(fp):p@\(host)", ownHost: host), "smp://\(fp):p@\(host):8443")
    }

    func testAlreadyOn8443IsLeftAlone() {
        XCTAssertNil(HearthRelayPort.migrate("smp://\(fp):p@\(host):8443", ownHost: host))
    }

    func testTheInspected443AlsoMoves() {
        // 443 выдавался один день, пока не выяснилось, что провайдер его досматривает.
        XCTAssertEqual(HearthRelayPort.migrate("smp://\(fp):p@\(host):443", ownHost: host), "smp://\(fp):p@\(host):8443")
    }

    func testSomeoneElsesServerIsLeftAlone() {
        XCTAssertNil(HearthRelayPort.migrate("smp://\(fp):p@smp8.simplex.im:5223", ownHost: host))
    }

    func testXftpIsLeftAlone() {
        // У XFTP свой порт, 443 на этом адресе уже занят SMP.
        XCTAssertNil(HearthRelayPort.migrate("xftp://\(fp):p@\(host):5443", ownHost: host))
    }

    func testADeliberateCustomPortIsLeftAlone() {
        XCTAssertNil(HearthRelayPort.migrate("smp://\(fp):p@\(host):7000", ownHost: host))
    }

    func testHostComparisonIgnoresCaseAndSpaces() {
        XCTAssertEqual(HearthRelayPort.migrate("  smp://\(fp):p@RELAY.myhearth.ru:5223  ", ownHost: host), "smp://\(fp):p@RELAY.myhearth.ru:8443")
    }

    func testAListOfHostsWithOursMoves() {
        XCTAssertEqual(
            HearthRelayPort.migrate("smp://\(fp):p@\(host),backup.myhearth.ru:5223", ownHost: host),
            "smp://\(fp):p@\(host),backup.myhearth.ru:8443"
        )
    }

    func testGarbageIsLeftAlone() {
        XCTAssertNil(HearthRelayPort.migrate("не адрес", ownHost: host))
        XCTAssertNil(HearthRelayPort.migrate("", ownHost: host))
        XCTAssertNil(HearthRelayPort.migrate("smp://\(fp):p@\(host):99999", ownHost: host))
    }
}
