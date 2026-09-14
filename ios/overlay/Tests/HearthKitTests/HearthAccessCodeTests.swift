import XCTest
@testable import HearthKit

/// Контракт кода доступа — зеркало `hearthd/src/model/code.rs`.
///
/// Эти тесты стерегут одну вещь: клиент и узел должны одинаково понимать, что такое
/// «тот же самый код».
final class HearthAccessCodeTests: XCTestCase {
    private let canonical = "H7K4P9QXM3TV"

    func testForgivesHowAPersonTypesIt() {
        for typed in ["H7K4-P9QX-M3TV", "h7k4 p9qx m3tv", "  H7K4P9QXM3TV\n", "h7k4-p9qx-m3tv\r\n"] {
            XCTAssertEqual(HearthAccessCode.normalize(typed), canonical, "ввод: \(typed.debugDescription)")
        }
    }

    func testMapsTheThreeConfusableLetters() {
        // Крокфорд: человек видит ноль и печатает «О», видит единицу и печатает «I».
        XCTAssertEqual(HearthAccessCode.normalize("OIL"), "011")
        XCTAssertEqual(HearthAccessCode.normalize("oil"), "011")
    }

    func testAFullCodeIsValidAndAShortOneIsNot() {
        XCTAssertTrue(HearthAccessCode.isValid(canonical))
        XCTAssertFalse(HearthAccessCode.isValid(String(canonical.dropLast())))
        XCTAssertFalse(HearthAccessCode.isValid(""))
    }

    func testLettersOutsideTheAlphabetNeverSurvive() {
        // `U` в алфавите нет вовсе, поэтому и в нормализованном виде его быть не может.
        XCTAssertFalse(HearthAccessCode.normalize("UUUUUUUUUUUU").contains("U"))
    }

    func testGroupsAreShownAsDictated() {
        XCTAssertEqual(HearthAccessCode.formatGroups(canonical), "H7K4-P9QX-M3TV")
    }

    func testAFormattedCodeNormalizesBackToItself() {
        XCTAssertEqual(HearthAccessCode.normalize(HearthAccessCode.formatGroups(canonical)), canonical)
    }

    func testTypingMoreThanTwelveCharactersDoesNotGrowTheCode() {
        XCTAssertEqual(HearthAccessCode.formatAsTyped(canonical + "ZZZZ"), "H7K4-P9QX-M3TV")
    }

    func testNormalizationIsAsciiOnlyLikeTheNode() {
        // Юникодный верхний регистр сделал бы из «ı» букву I, а из неё — 1. Узел такие знаки
        // выбрасывает, и коды разошлись бы.
        XCTAssertEqual(HearthAccessCode.normalize("ı"), "")
        XCTAssertEqual(HearthAccessCode.normalize("ｌ"), "")
        XCTAssertEqual(HearthAccessCode.normalize("ß"), "")
        // Кириллические двойники латиницы не превращаются в латиницу.
        XCTAssertEqual(HearthAccessCode.normalize("Н7К4"), "74")
    }

    func testIsValidWantsTheCanonicalForm() {
        XCTAssertFalse(HearthAccessCode.isValid("h7k4p9qxm3tv"), "нижний регистр — ещё не нормализованный код")
        XCTAssertFalse(HearthAccessCode.isValid("H7K4P9QXM3TU"))
        XCTAssertFalse(HearthAccessCode.isValid("H7K4-P9QX-M3"))
        XCTAssertFalse(HearthAccessCode.isValid("H7K4P9QXM3T\u{0661}"))
    }

    func testTheOldHexTokenIsNotACode() {
        let hex = String(repeating: "0123456789abcdef", count: 4)
        XCTAssertFalse(HearthAccessCode.isValid(hex))
        XCTAssertFalse(HearthAccessCode.isValid(HearthAccessCode.normalize(hex)))
    }

    // MARK: курсор в поле ввода (HearthCodeFieldTest)

    func testOffsetsSkipOverTheDashes() {
        XCTAssertEqual(HearthAccessCode.displayOffset(0), 0)
        XCTAssertEqual(HearthAccessCode.displayOffset(4), 4)
        XCTAssertEqual(HearthAccessCode.displayOffset(5), 6)
        XCTAssertEqual(HearthAccessCode.displayOffset(8), 9)
        XCTAssertEqual(HearthAccessCode.displayOffset(9), 11)
        XCTAssertEqual(HearthAccessCode.displayOffset(12), 14)
    }

    func testACursorInTheShownStringMapsBackToTheCode() {
        XCTAssertEqual(HearthAccessCode.codeOffset(0), 0)
        XCTAssertEqual(HearthAccessCode.codeOffset(4), 4)
        XCTAssertEqual(HearthAccessCode.codeOffset(5), 4)
        XCTAssertEqual(HearthAccessCode.codeOffset(9), 8)
        XCTAssertEqual(HearthAccessCode.codeOffset(10), 8)
        XCTAssertEqual(HearthAccessCode.codeOffset(14), 12)
    }

    func testTheMappingRoundTripsForEveryPosition() {
        for offset in 0...HearthAccessCode.length {
            XCTAssertEqual(HearthAccessCode.codeOffset(HearthAccessCode.displayOffset(offset)), offset, "позиция \(offset)")
        }
    }

    func testOffsetsNeverLeaveTheString() {
        XCTAssertEqual(HearthAccessCode.displayOffset(-5), 0)
        XCTAssertEqual(HearthAccessCode.displayOffset(99), 14)
        XCTAssertEqual(HearthAccessCode.codeOffset(-5), 0)
        XCTAssertEqual(HearthAccessCode.codeOffset(99), HearthAccessCode.length)
    }
}
