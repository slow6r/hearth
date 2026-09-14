//
//  HearthCoreEnvironment.swift
//  Hearth
//
//  Окружение Haskell-ядра, которое выставляется до его запуска (ADR 0016, ios/patches/0101).
//

import Foundation

public enum HearthCoreEnvironment {
    /// Читается ядром в `_defaultNtfServers` (патч 0101): адреса `ntf://` через пробел.
    public static let ntfServersVariable = "HEARTH_NTF_SERVERS"

    /// Выставить окружение ядра. Вызывать до `haskell_init*` — во всех трёх процессах:
    /// приложение, NSE, Share Extension.
    ///
    /// Ядро читает переменную один раз за процесс, при создании контроллера. Поэтому
    /// значение выставляется всегда, даже пустое: пустая строка означает «push-серверов
    /// нет», а не «возьми серверы SimpleX». Адрес, не прошедший проверку, тоже даёт пустую
    /// строку — сломанные уведомления лучше тихой утечки токена третьей стороне.
    @discardableResult
    public static func prepare(node: HearthNode?) -> String {
        var value = ""
        if let node = node, let ntf = node.ntf, (try? HearthNode.validateNtf(ntf, host: node.host)) != nil {
            value = ntf
        }
        setenv(ntfServersVariable, value, 1)
        return value
    }
}
