//
//  HearthRelayPort.swift
//  Hearth
//
//  Порт, на котором телефоны ходят к своему релею.
//

import Foundation

/// # Почему 8443, а не 443 и не 5223
///
/// Домашний провайдер узла на входе досматривает порты 443 и 5223 и выбрасывает именно
/// TLS-приветствие клиента SimpleX. Тот же пакет на любой другой порт доходит; проверено
/// на двадцати портах (`docs/deploy-fels-2026-09-09.md`). 8443 — обычный «альтернативный
/// HTTPS», его пропускают и офисные сети. Релей слушает и старые порты, так что
/// переписывание ничего не ломает.
public enum HearthRelayPort {
    public static let webPort = 8443
    static let smpDefaultPort = 5223
    /// Порты, с которых переводим: родной SMP и тот, что выдавался до обнаружения DPI.
    static let moveFrom: Set<Int> = [smpDefaultPort, 443]

    // smp://<отпечаток>:<пароль>@<хост[,хост…]>[:порт]
    private static let pattern = try? NSRegularExpression(pattern: "^(smp://[^@/?# ]+@)([A-Za-z0-9.,-]+)(?::([0-9]{1,5}))?$")

    /// Адрес своего релея, переведённый на 8443, или `nil`, если трогать нечего.
    ///
    /// Переписываем только SMP, только свой хост и только порты 5223 (явный или
    /// подразумеваемый) и 443. Чужие серверы, XFTP (у него свой порт) и нестандартные
    /// порты, которые кто-то задал сознательно, не трогаем.
    public static func migrate(_ address: String, ownHost: String) -> String? {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        let ns = trimmed as NSString
        let full = NSRange(location: 0, length: ns.length)
        guard let regex = pattern,
              let m = regex.firstMatch(in: trimmed, options: [], range: full),
              m.range == full
        else { return nil }
        let prefix = ns.substring(with: m.range(at: 1))
        let hosts = ns.substring(with: m.range(at: 2))
        guard hosts.split(separator: ",", omittingEmptySubsequences: false).contains(where: { HearthText.sameHost($0, ownHost) }) else {
            return nil
        }
        let portRange = m.range(at: 3)
        let current = portRange.location == NSNotFound ? smpDefaultPort : (Int(ns.substring(with: portRange)) ?? -1)
        guard moveFrom.contains(current) else { return nil }
        return "\(prefix)\(hosts):\(webPort)"
    }
}
