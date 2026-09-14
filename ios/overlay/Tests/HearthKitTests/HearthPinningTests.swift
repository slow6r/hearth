import Security
import XCTest
@testable import HearthKit

/// Проверка TLS device API на настоящих сертификатах: CA и серверный сертификат
/// выпускаются openssl при каждом прогоне — со сроком в 30 дней, потому что Apple не
/// принимает серверные сертификаты длиннее 825 дней, а зашитый в тест истёк бы.
///
/// Нет openssl — тесты пропускаются (XCTSkip), а не падают.
final class HearthPinningTests: XCTestCase {
    private let host = "relay.example.org"

    private struct Chain {
        let caPEM: String
        let ca: SecCertificate
        let leaf: SecCertificate
        let otherCA: SecCertificate
    }

    func testOurCAAndOurHostAreTrusted() throws {
        let chain = try makeChain()
        XCTAssertTrue(HearthPinningDelegate.trusts(try serverTrust(chain.leaf), host: host, anchor: chain.ca))
    }

    func testAnotherHostIsRefused() throws {
        let chain = try makeChain()
        XCTAssertFalse(HearthPinningDelegate.trusts(try serverTrust(chain.leaf), host: "evil.example", anchor: chain.ca))
    }

    func testACertificateFromAnotherCAIsRefused() throws {
        // Ровно то, что делает перехватывающий прокси с профилем на телефоне: сертификат
        // на наше имя, но от своего корня.
        let chain = try makeChain()
        XCTAssertFalse(HearthPinningDelegate.trusts(try serverTrust(chain.leaf), host: host, anchor: chain.otherCA))
    }

    func testTheBakedCAIsTheOneThatDecides() throws {
        let chain = try makeChain()
        let resources = try Fixtures.resourceBundle(["hearth_ca.pem": Data(chain.caPEM.utf8)], testCase: self)
        let anchor = try XCTUnwrap(HearthNode.loadBakedCA(from: resources))
        XCTAssertTrue(HearthPinningDelegate.trusts(try serverTrust(chain.leaf), host: host, anchor: anchor))
    }

    // MARK: -

    private func serverTrust(_ leaf: SecCertificate) throws -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(leaf, SecPolicyCreateSSL(true, host as CFString), &trust)
        XCTAssertEqual(status, errSecSuccess)
        return try XCTUnwrap(trust)
    }

    private func makeChain() throws -> Chain {
        let candidates = ["/usr/local/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/bin/openssl"]
        guard let openssl = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("openssl не найден")
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hearth-pin-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }

        try """
        [req]
        distinguished_name = dn
        x509_extensions = v3_ca
        prompt = no
        [dn]
        CN = hearth test CA
        [v3_ca]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        """.write(to: dir.appendingPathComponent("ca.cnf"), atomically: true, encoding: .utf8)
        try """
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        extendedKeyUsage = serverAuth
        subjectAltName = DNS:\(host)
        authorityKeyIdentifier = keyid
        """.write(to: dir.appendingPathComponent("leaf.ext"), atomically: true, encoding: .utf8)

        let steps: [[String]] = [
            ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"],
            ["req", "-x509", "-new", "-key", "ca.key", "-days", "30", "-sha256", "-config", "ca.cnf", "-out", "ca.pem"],
            ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "other.key"],
            ["req", "-x509", "-new", "-key", "other.key", "-days", "30", "-sha256", "-config", "ca.cnf", "-out", "other.pem"],
            ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key"],
            ["req", "-new", "-key", "leaf.key", "-subj", "/CN=\(host)", "-out", "leaf.csr"],
            ["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-days", "30", "-sha256", "-extfile", "leaf.ext", "-out", "leaf.pem"],
        ]
        for args in steps {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: openssl)
            process.arguments = args
            process.currentDirectoryURL = dir
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw XCTSkip("\(openssl) \(args.first ?? "") завершился с кодом \(process.terminationStatus)")
            }
        }

        func pem(_ name: String) throws -> String {
            try String(contentsOf: dir.appendingPathComponent(name), encoding: .utf8)
        }
        let caPEM = try pem("ca.pem")
        return Chain(
            caPEM: caPEM,
            ca: try XCTUnwrap(HearthNode.certificate(fromPEM: caPEM)),
            leaf: try XCTUnwrap(HearthNode.certificate(fromPEM: pem("leaf.pem"))),
            otherCA: try XCTUnwrap(HearthNode.certificate(fromPEM: pem("other.pem")))
        )
    }
}
