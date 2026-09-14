//
//  HearthNode.swift
//  Hearth
//
//  Адрес узла, вшитый в сборку (ADR 0012, 0016).
//

import Foundation
import Security

/// `hearth_node.json` в ресурсах фреймворка: `{"host","port","ntf"}`.
///
/// Только то, что и так видно в любом соединении с узлом: хост, порт device API и
/// адрес push-сервера. Ни паролей релеев, ни токенов — входной секрет приносит человек
/// (код доступа).
///
/// Адрес push-сервера здесь, а не в bundle, по одной причине: ядро читает его ровно
/// один раз, при создании контроллера (`HEARTH_NTF_SERVERS`, ADR 0016). На первом
/// запуске ядро поднимается раньше, чем узел отдаст bundle, и адрес из bundle дошёл бы
/// до ядра только после перезапуска приложения.
public struct HearthNode: Equatable {
    public static let defaultPort = 7444
    static let maxBytes = 4 * 1024
    static let maxPemBytes = 16 * 1024

    /// Хост узла — тот же, что в адресах релеев.
    public let host: String
    /// Порт device API.
    public let port: Int
    /// `ntf://<отпечаток>@<host>:<port>` или `nil`, если push-сервера у узла нет.
    public let ntf: String?

    public init(host: String, port: Int = HearthNode.defaultPort, ntf: String? = nil) throws {
        // Хост, а не URL: подставлять из файла произвольный адрес нельзя даже когда файл
        // свой — однажды он окажется не своим.
        guard Self.isHost(host) else { throw HearthValidationError("недопустимый адрес узла") }
        guard (1...65535).contains(port) else { throw HearthValidationError("недопустимый порт: \(port)") }
        if let ntf = ntf { try Self.validateNtf(ntf, host: host) }
        self.init(unchecked: host, port: port, ntf: ntf)
    }

    init(unchecked host: String, port: Int, ntf: String?) {
        self.host = host
        self.port = port
        self.ntf = ntf
    }

    public static func parse(_ data: Data) throws -> HearthNode {
        guard data.count <= maxBytes else { throw HearthValidationError("hearth_node.json больше 4 КБ") }
        let raw: Raw
        do {
            raw = try JSONDecoder().decode(Raw.self, from: data)
        } catch {
            throw HearthValidationError("hearth_node.json не разобран")
        }
        return try HearthNode(host: raw.host, port: raw.port ?? defaultPort, ntf: raw.ntf)
    }

    /// Вшитый адрес узла или `nil` — сборка неполная, и экран кода должен сказать это прямо.
    public static func loadBaked(from bundle: Bundle) -> HearthNode? {
        guard let url = bundle.url(forResource: "hearth_node", withExtension: "json"),
              let data = read(url, limit: maxBytes)
        else { return nil }
        return try? parse(data)
    }

    /// Корневой сертификат узла: им и только им проверяется TLS device API.
    public static func loadBakedCA(from bundle: Bundle) -> SecCertificate? {
        guard let url = bundle.url(forResource: "hearth_ca", withExtension: "pem"),
              let data = read(url, limit: maxPemBytes),
              let pem = String(data: data, encoding: .utf8)
        else { return nil }
        return certificate(fromPEM: pem)
    }

    /// Первый сертификат из PEM.
    static func certificate(fromPEM pem: String) -> SecCertificate? {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let b = pem.range(of: begin),
              let e = pem.range(of: end, range: b.upperBound..<pem.endIndex)
        else { return nil }
        let body = pem[b.upperBound..<e.lowerBound].filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: String(body)) else { return nil }
        return SecCertificateCreateWithData(nil, der as CFData)
    }

    /// `ntf://<отпечаток>@<host>:<port>`.
    ///
    /// Строже, чем формат upstream, и нарочно:
    /// - хост ровно хост узла — push-сервер третьей стороны получил бы токен устройства
    ///   и расписание его уведомлений;
    /// - без пароля и без списка хостов через запятую — у нашего push-сервера нет ни того,
    ///   ни другого;
    /// - без пробелов: ядро делит `HEARTH_NTF_SERVERS` по пробелам, и один адрес
    ///   превратился бы в два мусорных.
    static func validateNtf(_ ntf: String, host: String) throws {
        let prefix = "ntf://"
        guard ntf.hasPrefix(prefix) else { throw HearthValidationError("адрес push-сервера должен начинаться с ntf://") }
        guard !HearthText.hasWhitespace(ntf) else { throw HearthValidationError("в адресе push-сервера пробел") }
        let rest = ntf.dropFirst(prefix.count)
        guard let at = rest.lastIndex(of: "@") else { throw HearthValidationError("в адресе push-сервера нет отпечатка") }
        let fingerprint = rest[..<at]
        guard !fingerprint.isEmpty, fingerprint.unicodeScalars.allSatisfy(isFingerprintScalar) else {
            throw HearthValidationError("отпечаток push-сервера не в base64url (или в адресе есть пароль)")
        }
        let hostPort = rest[rest.index(after: at)...]
        guard let colon = hostPort.lastIndex(of: ":") else { throw HearthValidationError("в адресе push-сервера нет порта") }
        guard HearthText.sameHost(hostPort[..<colon], host) else {
            throw HearthValidationError("push-сервер не на узле \(host)")
        }
        guard HearthText.port(hostPort[hostPort.index(after: colon)...]) != nil else {
            throw HearthValidationError("недопустимый порт push-сервера")
        }
    }

    static func isHost(_ host: String) -> Bool {
        (1...253).contains(host.utf8.count) && host.utf8.allSatisfy { c in
            (48...57).contains(c) || (65...90).contains(c) || (97...122).contains(c) || c == 46 || c == 45
        }
    }

    private static func isFingerprintScalar(_ s: Unicode.Scalar) -> Bool {
        switch s {
        case "A"..."Z", "a"..."z", "0"..."9", "-", "_", "=": return true
        default: return false
        }
    }

    private static func read(_ url: URL, limit: Int) -> Data? {
        if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > limit {
            return nil
        }
        guard let data = try? Data(contentsOf: url), data.count <= limit else { return nil }
        return data
    }

    private struct Raw: Decodable {
        let host: String
        let port: Int?
        let ntf: String?
    }
}
