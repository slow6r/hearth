//
//  HearthNodeClient.swift
//  Hearth
//
//  Транспорт до device API узла: заведение по коду и свежие креды TURN.
//

import Foundation
import Security

public enum HearthNodeError: Error, Equatable {
    /// 401: код неизвестен, истрачен, отозван или просрочен — узел их не различает намеренно.
    case refused
    /// 429: слишком много неудачных попыток с этого адреса.
    case throttled
    /// 409: узел не может завести ещё одно устройство.
    case noSlots
    /// 400, или запрос не ушёл в сеть, потому что был бы отвергнут (неполный код).
    case badRequest
    case status(Int)
    case transport(String)
    case badResponse(String)
    /// В сборке нет адреса узла или его сертификата.
    case incompleteBuild
}

/// Клиент device API.
///
/// TLS проверяется ТОЛЬКО корневым сертификатом узла из сборки: системные корни не
/// участвуют, так что ни публичный CA, ни установленный на телефон профиль с чужим
/// корнем не подменят узел. Имя в сертификате обязано совпасть с `node.host`.
public final class HearthNodeClient {
    /// Узел отвергает имя длиннее 64 символов, и раньше делал это ПОСЛЕ того, как
    /// списал использование одноразового кода. Режем с запасом.
    public static let maxDeviceNameLength = 48
    static let maxBodyBytes = 64 * 1024
    static let connectTimeout: TimeInterval = 15
    static let totalTimeout: TimeInterval = 30
    static let inviteHeader = "x-hearth-invite-token"
    static let deviceTokenHeader = "x-hearth-device-token"

    public let node: HearthNode
    private let session: URLSession
    let pinning: HearthPinningDelegate

    public init(node: HearthNode, anchor: SecCertificate, session configuration: URLSessionConfiguration = .ephemeral) {
        self.node = node
        let config = (configuration.copy() as? URLSessionConfiguration) ?? .ephemeral
        config.timeoutIntervalForRequest = Self.connectTimeout
        config.timeoutIntervalForResource = Self.totalTimeout
        config.waitsForConnectivity = false
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        pinning = HearthPinningDelegate(host: node.host, anchor: anchor)
        session = URLSession(configuration: config, delegate: pinning, delegateQueue: nil)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    /// Клиент на вшитом узле. Нет адреса или сертификата — `incompleteBuild`.
    public static func baked(in bundle: Bundle, session: URLSessionConfiguration = .ephemeral) throws -> HearthNodeClient {
        guard let node = HearthNode.loadBaked(from: bundle), let anchor = HearthNode.loadBakedCA(from: bundle) else {
            throw HearthNodeError.incompleteBuild
        }
        return HearthNodeClient(node: node, anchor: anchor, session: session)
    }

    /// `POST /claim`: завести это устройство по коду доступа и получить bundle.
    ///
    /// `installId` должен быть одним и тем же при повторе: узел по нему узнаёт повтор
    /// после оборванного ответа и отдаёт тот же bundle, не списывая код второй раз.
    public func claim(code: String, deviceName: String, installId: String) async throws -> (bundle: HearthBundle, raw: Data) {
        let canonical = HearthAccessCode.normalize(code)
        // Неполный код заворачиваем здесь: сходить в сеть и вернуться с отказом — это те же
        // слова, но через три секунды и с потраченной попыткой у ограничителя узла.
        guard HearthAccessCode.isValid(canonical) else { throw HearthNodeError.badRequest }

        let body = ClaimBody(
            name: Self.deviceName(deviceName),
            installId: installId.trimmingCharacters(in: .whitespacesAndNewlines),
            platform: "ios"
        )
        var request = try makeRequest(path: "/claim", method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(canonical, forHTTPHeaderField: Self.inviteHeader)
        do {
            request.httpBody = try JSONEncoder().encode(body)
        } catch {
            throw HearthNodeError.badRequest
        }

        let raw = try await send(request)
        do {
            return (try HearthBundle.parse(raw), raw)
        } catch {
            throw HearthNodeError.badResponse(Self.describe(error))
        }
    }

    /// `GET /turn-credentials`: свежий список ICE, проверенный против `node.host`.
    public func turnCredentials(deviceToken: String) async throws -> [String] {
        let token = deviceToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard HearthBundle.isDeviceToken(token) else { throw HearthNodeError.badRequest }
        var request = try makeRequest(path: "/turn-credentials", method: "GET")
        request.setValue(token, forHTTPHeaderField: Self.deviceTokenHeader)
        let raw = try await send(request)
        do {
            return try HearthTurnCredentials.parse(raw).validated(expectedHost: node.host)
        } catch {
            throw HearthNodeError.badResponse(Self.describe(error))
        }
    }

    /// Имя устройства для реестра: без крайних пробелов и не длиннее
    /// `maxDeviceNameLength` Unicode-символов — узел считает именно их, а не байты и не
    /// графемы. Графема целиком или никак: флаг, разрезанный пополам, в реестре не нужен.
    static func deviceName(_ raw: String) -> String {
        var out = ""
        var count = 0
        for ch in raw.trimmingCharacters(in: .whitespacesAndNewlines) {
            let n = ch.unicodeScalars.count
            if count + n > maxDeviceNameLength { break }
            out.append(ch)
            count += n
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func makeRequest(path: String, method: String) throws -> URLRequest {
        var c = URLComponents()
        c.scheme = "https"
        c.host = node.host
        c.port = node.port
        c.path = path
        guard let url = c.url else { throw HearthNodeError.incompleteBuild }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: Self.connectTimeout)
        request.httpMethod = method
        request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    private func send(_ request: URLRequest) async throws -> Data {
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request)
        } catch {
            throw HearthNodeError.transport(Self.describe(error))
        }
        defer { bytes.task.cancel() }
        guard let http = response as? HTTPURLResponse else { throw HearthNodeError.badResponse("ответ не HTTP") }
        switch http.statusCode {
        case 200: break
        case 400: throw HearthNodeError.badRequest
        case 401: throw HearthNodeError.refused
        case 409: throw HearthNodeError.noSlots
        case 429: throw HearthNodeError.throttled
        default: throw HearthNodeError.status(http.statusCode)
        }
        if http.expectedContentLength > Int64(Self.maxBodyBytes) {
            throw HearthNodeError.badResponse("ответ узла больше 64 КБ")
        }
        var data = Data()
        do {
            for try await byte in bytes {
                data.append(byte)
                if data.count > Self.maxBodyBytes { throw HearthNodeError.badResponse("ответ узла больше 64 КБ") }
            }
        } catch let error as HearthNodeError {
            throw error
        } catch {
            throw HearthNodeError.transport(Self.describe(error))
        }
        return data
    }

    static func describe(_ error: Error) -> String {
        if let e = error as? HearthValidationError { return e.reason }
        if let e = error as? URLError { return "URLError \(e.code.rawValue)" }
        return String(describing: error)
    }

    private struct ClaimBody: Encodable {
        let name: String
        let installId: String
        let platform: String

        enum CodingKeys: String, CodingKey {
            case name
            case installId = "install_id"
            case platform
        }
    }
}

/// Проверка TLS и запрет редиректов для device API.
final class HearthPinningDelegate: NSObject, URLSessionTaskDelegate {
    let host: String
    let anchor: SecCertificate

    init(host: String, anchor: SecCertificate) {
        self.host = host
        self.anchor = anchor
    }

    func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let (disposition, credential) = decide(challenge)
        completionHandler(disposition, credential)
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let (disposition, credential) = decide(challenge)
        completionHandler(disposition, credential)
    }

    /// Редиректов нет: адрес узла берётся из сборки и больше ниоткуда.
    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    /// Только проверка сервера, только наш хост, только наш корень. Всё прочее — отказ.
    func decide(_ challenge: URLAuthenticationChallenge) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              HearthText.sameHost(space.host, host),
              let trust = space.serverTrust,
              Self.trusts(trust, host: host, anchor: anchor)
        else { return (.cancelAuthenticationChallenge, nil) }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Цепочка сервера сходится к `anchor` и только к нему, имя совпадает с `host`.
    static func trusts(_ trust: SecTrust, host: String, anchor: SecCertificate) -> Bool {
        let policy = SecPolicyCreateSSL(true, host as CFString)
        guard SecTrustSetPolicies(trust, policy) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
        else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}
