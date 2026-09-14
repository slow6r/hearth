import Foundation
import XCTest

enum Fixtures {
    /// Любой сертификат — как непрозрачный якорь для клиентов, у которых TLS подменён
    /// заглушкой. Срок годности значения не имеет: проверка цепочки тут не выполняется.
    static let caPEM = """
    -----BEGIN CERTIFICATE-----
    MIIBdTCCARygAwIBAgIUVdEtoOqWLB1U0fhiWUcKcWOKHOcwCgYIKoZIzj0EAwIw
    GTEXMBUGA1UEAwwOaGVhcnRoIHRlc3QgQ0EwHhcNMjYwOTE0MTEzNDE3WhcNMjYx
    MDE0MTEzNDE3WjAZMRcwFQYDVQQDDA5oZWFydGggdGVzdCBDQTBZMBMGByqGSM49
    AgEGCCqGSM49AwEHA0IABGi9LqNjEKTHPvoB4+AAN/dFXxiiCpGTb/kjC+CrTOL8
    YbiiNPlzX2/cII1z5uG7KL93sPL7rfsVBzb/jiWEBVmjQjBAMA8GA1UdEwEB/wQF
    MAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQpF6SNojMu/Zk2moBeVPsJ
    IcEkXzAKBggqhkjOPQQDAgNHADBEAiBR/RchvQLr/TsjqOn+WvI41GMhlTuLiaRZ
    gtKRV+I8EwIgFMT5y0i7h3mDrmY4Kp4YBxM45n1RZVmdmwLdRYWwsaQ=
    -----END CERTIFICATE-----
    """

    static let ntfFingerprint = "KmpZNNXiVZJx_G2T7jRUmDFxWXM3OAnunz3uLT0tqAA="

    static let deviceToken = String(repeating: "0123456789abcdef", count: 4)

    /// Каталог с файлами как псевдо-бундл ресурсов. Удаляется после теста.
    static func resourceBundle(_ files: [String: Data], testCase: XCTestCase) throws -> Bundle {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hearth-res-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        testCase.addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        for (name, data) in files {
            try data.write(to: dir.appendingPathComponent(name))
        }
        return try XCTUnwrap(Bundle(url: dir), "каталог не открылся как Bundle")
    }
}
