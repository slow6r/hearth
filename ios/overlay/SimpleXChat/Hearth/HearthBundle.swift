//
//  HearthBundle.swift
//  Hearth
//
//  Bundle — документ, которым узел настраивает устройство (ответ `POST /claim`).
//

import Foundation

/// Client bundle as `hearthd` mints it (`hearthd/src/model/bundle.rs`).
///
/// Both string formats inside are upstream's, verified against v7.0.1:
///  - relays: `smp://<fingerprint>:<password>@host:port`
///  - ICE:    `scheme:[user:credential@]host:port[?query]`
///
/// The node already checked all of it. Checking again on the device means a tampered or
/// stale document cannot quietly point a phone at a foreign relay. This validation is
/// the union of the Android client's and the node's own: what Kotlin skipped (the `node`
/// section, the 1 KB budget, character rules for fingerprints and passwords) is checked
/// here too.
public struct HearthBundle: Codable, Equatable {
    public static let supportedVersion = 1
    /// ТЗ Приложение B: bundle fits a QR code.
    public static let maxBytes = 1024

    public let v: Int
    public let smp: [String]
    public let xftp: [String]
    /// ICE entries as strings, exactly what `parseRTCIceServers` accepts.
    public let ice: [String]
    public let net: HearthNetPrefs
    public let issued: String
    public let device: String
    /// Device API of the node: fresh TURN credentials. `nil` — node without device API.
    public let node: HearthNodeApi?

    public init(
        v: Int, smp: [String], xftp: [String] = [], ice: [String] = [], net: HearthNetPrefs,
        issued: String, device: String, node: HearthNodeApi? = nil
    ) {
        self.v = v
        self.smp = smp
        self.xftp = xftp
        self.ice = ice
        self.net = net
        self.issued = issued
        self.device = device
        self.node = node
    }

    enum CodingKeys: String, CodingKey {
        case v, smp, xftp, ice, net, issued, device, node
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        smp = try c.decode([String].self, forKey: .smp)
        xftp = try c.decodeIfPresent([String].self, forKey: .xftp) ?? []
        ice = try c.decodeIfPresent([String].self, forKey: .ice) ?? []
        net = try c.decode(HearthNetPrefs.self, forKey: .net)
        issued = try c.decode(String.self, forKey: .issued)
        device = try c.decode(String.self, forKey: .device)
        node = try c.decodeIfPresent(HearthNodeApi.self, forKey: .node)
    }

    /// Decode and validate the node's response, byte for byte as received.
    public static func parse(_ data: Data) throws -> HearthBundle {
        guard !data.isEmpty else { throw HearthValidationError("bundle is empty") }
        // The node refuses to mint more than this; a bigger document is not the node's.
        guard data.count <= maxBytes else {
            throw HearthValidationError("bundle is \(data.count) bytes, over the \(maxBytes) byte budget")
        }
        let bundle: HearthBundle
        do {
            bundle = try JSONDecoder().decode(HearthBundle.self, from: data)
        } catch {
            throw HearthValidationError("bundle is not valid JSON")
        }
        try bundle.validate()
        return bundle
    }

    /// The host every address in this bundle points at: the host of `smp[0]`, or "" if none.
    public var expectedHost: String {
        smp.first.flatMap { HearthAddress.host(of: $0) } ?? ""
    }

    /// Reject anything that would take this device outside the family contour.
    public func validate() throws {
        guard v == Self.supportedVersion else { throw HearthValidationError("unsupported bundle version \(v)") }
        guard !smp.isEmpty else { throw HearthValidationError("bundle has no SMP servers") }
        guard !device.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw HearthValidationError("bundle has no device id")
        }

        let host = expectedHost
        guard !host.isEmpty else { throw HearthValidationError("SMP address has no host") }
        for uri in smp { try HearthAddress.requireServer(uri, scheme: "smp", expectedHost: host) }
        for uri in xftp { try HearthAddress.requireServer(uri, scheme: "xftp", expectedHost: host) }

        // Calls: our own STUN/TURN only. A public STUN would hand the caller's address to
        // a third party.
        guard !ice.isEmpty else { throw HearthValidationError("bundle has no ICE servers") }
        for entry in ice { try HearthIce.requireEntry(entry, expectedHost: host) }

        guard net.privateRouting == "always" else { throw HearthValidationError("privateRouting must be `always`") }
        guard !net.presetsEnabled else { throw HearthValidationError("public operator presets must stay disabled") }
        guard net.ntfMode == "instant" else { throw HearthValidationError("notification mode must be `instant`") }

        if let node = node {
            // The device API host comes from here and from nowhere else — a document the
            // API itself serves later must not be able to move the device elsewhere.
            guard HearthText.sameHost(node.host, host) else {
                throw HearthValidationError("device API points at \(node.host), not at \(host)")
            }
            guard (1...65535).contains(node.port) else { throw HearthValidationError("bad device API port \(node.port)") }
            guard Self.isDeviceToken(node.token) else { throw HearthValidationError("device token is not 64 lowercase hex") }
        }
    }

    /// `random_hex(32)` on the node: 64 lowercase hex characters.
    static func isDeviceToken(_ token: String) -> Bool {
        token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

public struct HearthNetPrefs: Codable, Equatable {
    public let privateRouting: String
    public let presetsEnabled: Bool
    public let ntfMode: String

    public init(privateRouting: String, presetsEnabled: Bool, ntfMode: String) {
        self.privateRouting = privateRouting
        self.presetsEnabled = presetsEnabled
        self.ntfMode = ntfMode
    }
}

/// Адрес device API и токен ЭТОГО устройства.
public struct HearthNodeApi: Codable, Equatable {
    public let host: String
    public let port: Int
    /// Секрет устройства. Уходит заголовком, не в URL: URL оседает в логах.
    public let token: String

    public init(host: String, port: Int, token: String) {
        self.host = host
        self.port = port
        self.token = token
    }
}

enum HearthAddress {
    /// `<scheme>://<fingerprint>:<password>@<host>:<port>`.
    ///
    /// Every address in one bundle must point at the same host: a bundle that mixes hosts
    /// means either a mistake or an attempt to slip one foreign server into the set.
    /// Messages never quote the address — it carries the relay password.
    static func requireServer(_ uri: String, scheme: String, expectedHost: String) throws {
        let prefix = scheme + "://"
        guard uri.hasPrefix(prefix) else { throw HearthValidationError("expected a \(prefix) address") }
        guard !HearthText.hasWhitespace(uri) else { throw HearthValidationError("\(scheme) address contains whitespace") }
        let auth = uri.dropFirst(prefix.count)
        guard let at = auth.lastIndex(of: "@"), at > auth.startIndex else {
            throw HearthValidationError("\(scheme) address has no fingerprint")
        }
        let credentials = auth[..<at]
        // Upstream requires a password to create queues; without one the relay is open.
        guard let colon = credentials.firstIndex(of: ":") else {
            throw HearthValidationError("\(scheme) address carries no relay password")
        }
        let fingerprint = credentials[..<colon]
        let password = credentials[credentials.index(after: colon)...]
        guard !fingerprint.isEmpty, !fingerprint.contains(where: { $0 == "@" || $0 == "/" }) else {
            throw HearthValidationError("\(scheme) fingerprint is empty or contains a separator")
        }
        guard !password.isEmpty else { throw HearthValidationError("\(scheme) address carries no relay password") }
        // Upstream: "any printable ASCII characters without whitespace, '@', ':' and '/'".
        guard !password.contains(where: { $0 == ":" || $0 == "@" || $0 == "/" }) else {
            throw HearthValidationError("\(scheme) password contains ':', '@' or '/'")
        }

        let hostPort = auth[auth.index(after: at)...]
        guard let portColon = hostPort.lastIndex(of: ":") else { throw HearthValidationError("\(scheme) address has no port") }
        let host = hostPort[..<portColon]
        guard !host.isEmpty else { throw HearthValidationError("\(scheme) address has no host") }
        guard HearthText.sameHost(host, expectedHost) else {
            throw HearthValidationError("\(scheme) address points at \(host), not at \(expectedHost)")
        }
        guard HearthText.port(hostPort[hostPort.index(after: portColon)...]) != nil else {
            throw HearthValidationError("bad port in \(scheme) address")
        }
    }

    static func host(of uri: String) -> String? {
        guard let scheme = uri.range(of: "://") else { return nil }
        let auth = uri[scheme.upperBound...]
        guard !auth.isEmpty else { return nil }
        let hostPort = auth.lastIndex(of: "@").map { auth[auth.index(after: $0)...] } ?? auth
        guard let colon = hostPort.lastIndex(of: ":") else { return nil }
        let host = hostPort[..<colon]
        return host.isEmpty ? nil : String(host)
    }
}
