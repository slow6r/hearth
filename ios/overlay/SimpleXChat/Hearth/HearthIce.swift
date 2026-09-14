//
//  HearthIce.swift
//  Hearth
//
//  ICE-серверы: только свой STUN/TURN, и только в том виде, который клиент не выбросит.
//

import Foundation

public enum HearthIce {
    static let schemes: Set<String> = ["stun", "stuns", "turn", "turns"]

    /// `scheme:[user:credential@]host:port[?query]`.
    ///
    /// The strictness here is not pedantry. `parseRTCIceServers` in
    /// `Shared/Views/Call/WebRTC.swift` returns nil for the WHOLE list if any single entry
    /// fails to parse, and `WebRTCClient` then falls back to its built-in **public**
    /// STUN/TURN. A malformed entry would not break calls loudly — it would quietly route
    /// them through a third party.
    ///
    /// Two checks run: the Android/node rules (host, port, credentials without '/'), and
    /// then the entry is fed to an exact copy of the iOS parser — the only judge that
    /// matters on this platform.
    public static func requireEntry(_ entry: String, expectedHost: String) throws {
        guard !expectedHost.isEmpty else { throw HearthValidationError("no expected host for ICE entries") }
        guard !HearthText.hasWhitespace(entry) else { throw HearthValidationError("ICE entry contains whitespace") }
        guard let schemeColon = entry.firstIndex(of: ":"), schemes.contains(String(entry[..<schemeColon])) else {
            throw HearthValidationError("unsupported ICE scheme")
        }
        let scheme = String(entry[..<schemeColon])
        var rest = entry[entry.index(after: schemeColon)...]
        if let q = rest.firstIndex(of: "?") { rest = rest[..<q] }
        // hearthd never puts '@' into credentials; a second '@' means two parsers could
        // disagree about where the host starts.
        guard rest.filter({ $0 == "@" }).count <= 1 else { throw HearthValidationError("ICE entry has more than one '@'") }
        let at = rest.lastIndex(of: "@")
        let hostPort = at.map { rest[rest.index(after: $0)...] } ?? rest
        guard let portColon = hostPort.lastIndex(of: ":"), !hostPort[..<portColon].isEmpty else {
            throw HearthValidationError("ICE entry has no host")
        }
        let host = hostPort[..<portColon]
        guard HearthText.sameHost(host, expectedHost) else {
            throw HearthValidationError(
                "ICE entry points at \(host), not at \(expectedHost) — a public STUN/TURN would leak the caller's address"
            )
        }
        guard HearthText.port(hostPort[hostPort.index(after: portColon)...]) != nil else {
            throw HearthValidationError("bad port in ICE entry")
        }
        if scheme.hasPrefix("turn") {
            let userInfo = at.map { rest[..<$0] } ?? ""
            guard userInfo.contains(":") else { throw HearthValidationError("TURN entry without credentials") }
            // A '/' would start a URI path and make the client discard the entry — and with
            // it the whole list. hearthd guarantees this never happens.
            guard !userInfo.contains("/") else { throw HearthValidationError("TURN credentials contain '/'") }
        }

        guard let parsed = clientParse(entry) else {
            throw HearthValidationError("the iOS client would discard this ICE entry, and with it the whole list")
        }
        guard HearthText.sameHost(parsed.host, expectedHost) else {
            throw HearthValidationError("the iOS client reads a different host from this ICE entry")
        }
        if scheme.hasPrefix("turn") {
            guard let user = parsed.user, !user.isEmpty, let password = parsed.password, !password.isEmpty else {
                throw HearthValidationError("the iOS client loses the TURN credentials of this entry")
            }
        }
    }

    struct Parsed: Equatable {
        let scheme: String
        let host: String
        let port: Int
        let user: String?
        let password: String?
    }

    /// Exact copy of `parseRTCIceServer` from `Shared/Views/Call/WebRTC.swift` (v7.0.1).
    /// Keep in sync on rebase: if upstream changes the parser, this copy must change too.
    static func clientParse(_ str: String) -> Parsed? {
        var s = replaceScheme(str, "stun:")
        s = replaceScheme(s, "stuns:")
        s = replaceScheme(s, "turn:")
        s = replaceScheme(s, "turns:")
        if let u: URL = URL(string: s),
           let scheme = u.scheme,
           let host = u.host,
           let port = u.port,
           u.path == "" && (scheme == "stun" || scheme == "stuns" || scheme == "turn" || scheme == "turns") {
            return Parsed(scheme: scheme, host: host, port: port, user: u.user, password: u.password)
        }
        return nil
    }

    private static func replaceScheme(_ s: String, _ scheme: String) -> String {
        s.starts(with: scheme)
            ? s.replacingOccurrences(of: scheme, with: scheme + "//", options: .anchored, range: nil)
            : s
    }
}

/// Ответ `GET /turn-credentials` (ADR 0010).
///
/// Креды TURN — подпись с датой и протухают по календарю. Отказ самый неприятный:
/// сообщения ходят, а звонки — как повезёт. Поэтому обновление — часть запуска, а не кнопка.
public struct HearthTurnCredentials: Codable, Equatable {
    public let username: String
    public let credential: String
    /// Строки ICE в том же виде, что в bundle.
    public let ice: [String]
    public let expires: String

    public init(username: String, credential: String, ice: [String], expires: String = "") {
        self.username = username
        self.credential = credential
        self.ice = ice
        self.expires = expires
    }

    enum CodingKeys: String, CodingKey {
        case username, credential, ice, expires
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = try c.decode(String.self, forKey: .username)
        credential = try c.decode(String.self, forKey: .credential)
        ice = try c.decode([String].self, forKey: .ice)
        expires = try c.decodeIfPresent(String.self, forKey: .expires) ?? ""
    }

    public static func parse(_ data: Data) throws -> HearthTurnCredentials {
        do {
            return try JSONDecoder().decode(HearthTurnCredentials.self, from: data)
        } catch {
            throw HearthValidationError("ответ узла с кредами TURN не разобран")
        }
    }

    /// Проверенный список ICE — или ошибка, и тогда настройки трогать нельзя.
    ///
    /// Проверка та же, что у bundle, и это принципиально: bundle пришёл в обмен на код,
    /// а креды приходят от узла по сети, то есть от стороны, которую после захвата мы
    /// доверенной не считаем. Узел мог бы вернуть ICE на ЧУЖОЙ TURN, и адреса собеседников
    /// достались бы третьей стороне. `expectedHost` — из применённого bundle, не из ответа.
    public func validated(expectedHost: String) throws -> [String] {
        // Пустой список записать хуже, чем не трогать настройки: старые креды хотя бы могут
        // быть ещё живы, а пустой ICE — гарантированная тишина.
        guard !ice.isEmpty else { throw HearthValidationError("узел вернул пустой список ICE") }
        guard !ice.contains(where: { $0.contains("\n") || $0.contains("\r") }) else {
            throw HearthValidationError("в строке ICE перевод строки")
        }
        for entry in ice { try HearthIce.requireEntry(entry, expectedHost: expectedHost) }
        return ice
    }
}
