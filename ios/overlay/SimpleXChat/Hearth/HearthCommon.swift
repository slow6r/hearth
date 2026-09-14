//
//  HearthCommon.swift
//  Hearth
//
//  Общие мелочи проверки, которые должны совпадать у всех документов узла.
//

import Foundation

/// Документ из сборки или с узла не прошёл проверку.
///
/// `reason` годится и в лог, и на экран. Самих адресов релеев в нём нет намеренно:
/// в адресе пароль релея, а текст ошибки оседает в логах.
public struct HearthValidationError: Error, Equatable, LocalizedError, CustomStringConvertible {
    public let reason: String

    public init(_ reason: String) {
        self.reason = reason
    }

    public var errorDescription: String? { reason }
    public var description: String { reason }
}

enum HearthText {
    /// Сравнение хостов без учёта регистра — только ASCII, как `eq_ignore_ascii_case`
    /// в hearthd. Юникодное сравнение сочло бы равными хосты, которые узел различает.
    static func sameHost<A: StringProtocol, B: StringProtocol>(_ a: A, _ b: B) -> Bool {
        let x = Array(a.utf8)
        let y = Array(b.utf8)
        guard x.count == y.count else { return false }
        return zip(x, y).allSatisfy { lower($0) == lower($1) }
    }

    /// Порт: только цифры (без знака и пробелов), 1...65535.
    static func port<S: StringProtocol>(_ s: S) -> Int? {
        guard (1...5).contains(s.utf8.count), s.utf8.allSatisfy({ (48...57).contains($0) }),
              let value = Int(s), (1...65535).contains(value)
        else { return nil }
        return value
    }

    static func hasWhitespace<S: StringProtocol>(_ s: S) -> Bool {
        s.unicodeScalars.contains { CharacterSet.whitespacesAndNewlines.contains($0) }
    }

    private static func lower(_ c: UInt8) -> UInt8 {
        (65...90).contains(c) ? c + 32 : c
    }
}
