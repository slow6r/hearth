package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Контракт кода доступа — зеркало `hearthd/src/model/code.rs`.
 *
 * Эти тесты стерегут одну вещь: клиент и узел должны одинаково понимать, что такое
 * «тот же самый код». Если они разойдутся, человек с правильной бумажкой получит
 * отказ, и разбираться будут по звонку, а не здесь.
 */
class HearthAccessCodeTest {

  private val canonical = "H7K4P9QXM3TV"

  @Test
  fun forgivesHowAPersonTypesIt() {
    for (typed in listOf(
      "H7K4-P9QX-M3TV",
      "h7k4 p9qx m3tv",
      "  H7K4P9QXM3TV\n",
      "h7k4-p9qx-m3tv\r\n",
    )) {
      assertEquals(canonical, HearthAccessCode.normalize(typed), "ввод: $typed")
    }
  }

  @Test
  fun mapsTheThreeConfusableLetters() {
    // Крокфорд: человек видит ноль и печатает «О», видит единицу и печатает «I».
    assertEquals("011", HearthAccessCode.normalize("OIL"))
    assertEquals("011", HearthAccessCode.normalize("oil"))
  }

  @Test
  fun aFullCodeIsValidAndAShortOneIsNot() {
    assertTrue(HearthAccessCode.isValid(canonical))
    assertFalse(HearthAccessCode.isValid(canonical.dropLast(1)))
    assertFalse(HearthAccessCode.isValid(""))
  }

  @Test
  fun lettersOutsideTheAlphabetNeverSurvive() {
    // `U` в алфавите нет вовсе, поэтому и в нормализованном виде его быть не может.
    assertFalse(HearthAccessCode.normalize("UUUUUUUUUUUU").contains('U'))
  }

  @Test
  fun groupsAreShownAsDictated() {
    assertEquals("H7K4-P9QX-M3TV", HearthAccessCode.formatGroups(canonical))
  }

  @Test
  fun aFormattedCodeNormalizesBackToItself() {
    assertEquals(canonical, HearthAccessCode.normalize(HearthAccessCode.formatGroups(canonical)))
  }

  @Test
  fun typingMoreThanTwelveCharactersDoesNotGrowTheCode() {
    val typed = HearthAccessCode.formatAsTyped(canonical + "ZZZZ")
    assertEquals("H7K4-P9QX-M3TV", typed)
  }
}
