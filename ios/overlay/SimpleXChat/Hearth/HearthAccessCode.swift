//
//  HearthAccessCode.swift
//  Hearth
//
//  Код доступа — то, что человек получает лично и вводит руками (ADR 0012).
//

import Foundation

/// Зеркало серверного `hearthd/src/model/code.rs`.
///
/// Раскладка одна и та же, и это важнее, чем кажется: если клиент и узел разойдутся в
/// том, что считать «тем же кодом», человек с правильной бумажкой получит отказ.
///
/// Алфавит Крокфорда: 32 знака, без `I`, `L`, `O`, `U`. Ввод прощает человека — регистр
/// любой, дефисы и пробелы не важны, а `O`, `I` и `L` читаются как `0` и `1`.
///
/// Правило намеренно только для ASCII, как `to_ascii_uppercase` в Rust. Юникодный
/// верхний регистр (так делал Android) превращает, например, турецкую `ı` в `I` и дальше
/// в `1` — а узел её просто выбрасывает, и коды расходятся.
public enum HearthAccessCode {
    public static let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /// Знаков в коде. 12 × 5 бит = 60 бит.
    public static let length = 12

    static let group = 4

    private static let alphabetBytes = Set(alphabet.utf8)

    /// Привести введённое к тому виду, в каком код хранится на узле. Длину не проверяет.
    public static func normalize(_ raw: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in raw.unicodeScalars where scalar.isASCII {
            var value = UInt8(scalar.value)
            if (97...122).contains(value) { value -= 32 }
            switch value {
            // Человек видит «ноль» и печатает «О», видит «единицу» и печатает «I».
            case 79: out.append("0")
            case 73, 76: out.append("1")
            default:
                // Всё прочее — дефисы, пробелы, перевод строки из буфера обмена — выкидываем.
                if alphabetBytes.contains(value) { out.append(Unicode.Scalar(value)) }
            }
        }
        return String(out)
    }

    /// Похоже ли это на полный код: правильная длина и только знаки алфавита.
    public static func isValid(_ code: String) -> Bool {
        code.utf8.count == length && code.utf8.allSatisfy { alphabetBytes.contains($0) }
    }

    /// Разбить на группы для показа: `H7K4-P9QX-M3TV`.
    public static func formatGroups(_ code: String) -> String {
        var groups: [String] = []
        var current = ""
        for ch in code {
            current.append(ch)
            if current.count == group {
                groups.append(current)
                current = ""
            }
        }
        if !current.isEmpty { groups.append(current) }
        return groups.joined(separator: "-")
    }

    /// Показать ровно то, что человек набрал, но группами и не длиннее кода.
    public static func formatAsTyped(_ raw: String) -> String {
        formatGroups(String(normalize(raw).prefix(length)))
    }

    /// Где окажется знак с позиции `offset` после расстановки дефисов.
    ///
    /// Поле хранит код без дефисов, а показывает с ними; без пересчёта курсор уезжает
    /// после каждой правки. Чистая арифметика — и проверяется тестом, а не пальцами.
    public static func displayOffset(_ offset: Int) -> Int {
        let o = min(max(offset, 0), length)
        return o + (o > group ? 1 : 0) + (o > group * 2 ? 1 : 0)
    }

    /// Обратное преобразование: позиция в показанной строке — в позицию в коде.
    public static func codeOffset(_ displayed: Int) -> Int {
        let d = min(max(displayed, 0), length + 2)
        let o: Int
        if d <= group {
            o = d
        } else if d <= group * 2 + 1 {
            o = d - 1
        } else {
            o = d - 2
        }
        return min(max(o, 0), length)
    }
}
