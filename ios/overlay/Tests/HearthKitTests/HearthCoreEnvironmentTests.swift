import XCTest
@testable import HearthKit

/// Окружение ядра: адрес push-сервера или пустота — и никогда серверы SimpleX (ADR 0016).
final class HearthCoreEnvironmentTests: XCTestCase {
    private let ntf = "ntf://\(Fixtures.ntfFingerprint)@relay.example.org:5227"

    private var current: String? {
        getenv(HearthCoreEnvironment.ntfServersVariable).map { String(cString: $0) }
    }

    override func tearDown() {
        unsetenv(HearthCoreEnvironment.ntfServersVariable)
        super.tearDown()
    }

    func testTheVariableNameMatchesTheCorePatch() {
        XCTAssertEqual(HearthCoreEnvironment.ntfServersVariable, "HEARTH_NTF_SERVERS")
    }

    func testNoNodeMeansNoPushServers() {
        XCTAssertEqual(HearthCoreEnvironment.prepare(node: nil), "")
        // Выставлено именно пустое значение, а не «не задано» — ядро трактует оба одинаково,
        // но пустое не даёт унаследовать чужое значение из окружения процесса.
        XCTAssertEqual(current, "")
    }

    func testANodeWithoutAPushServerMeansNoPushServers() throws {
        XCTAssertEqual(HearthCoreEnvironment.prepare(node: try HearthNode(host: "relay.example.org")), "")
        XCTAssertEqual(current, "")
    }

    func testTheNodesPushServerReachesTheCore() throws {
        let node = try HearthNode(host: "relay.example.org", ntf: ntf)
        XCTAssertEqual(HearthCoreEnvironment.prepare(node: node), ntf)
        XCTAssertEqual(current, ntf)
    }

    func testAnInvalidAddressNeverReachesTheCore() {
        let foreign = HearthNode(unchecked: "relay.example.org", port: 7444, ntf: "ntf://\(Fixtures.ntfFingerprint)@ntf3.simplex.im:443")
        XCTAssertEqual(HearthCoreEnvironment.prepare(node: foreign), "")
        XCTAssertEqual(current, "")
    }

    func testPreparingAgainOverwritesAStaleValue() throws {
        setenv(HearthCoreEnvironment.ntfServersVariable, "ntf://stale@ntf4.simplex.im:443", 1)
        HearthCoreEnvironment.prepare(node: nil)
        XCTAssertEqual(current, "")
    }
}
