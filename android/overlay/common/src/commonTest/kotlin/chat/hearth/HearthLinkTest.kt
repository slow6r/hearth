package chat.hearth

import chat.simplex.common.model.hearthLinkToCore
import chat.simplex.common.model.simplexChatLink
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Своя схема ссылок-приглашений.
 *
 * Наружу человек видит `hearth:/…`, ядру уходит `simplex:/…`. Подмена живёт в двух
 * функциях и больше нигде, поэтому проверяется здесь: ошибка в них не выглядит как
 * ошибка, она выглядит как «QR не сканируется», и разбираться пришлось бы вдвоём по
 * телефону.
 */
class HearthLinkTest {

  private val core = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40relay.example.org"

  @Test
  fun outwardsTheSchemeIsOurs() {
    assertEquals("hearth:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40relay.example.org", simplexChatLink(core))
  }

  @Test
  fun theRoundTripIsExact() {
    // Ровно то же, что ушло — включая якорь и процентное кодирование: ядро разбирает
    // строку целиком, и потерянный символ там не «почти работает».
    assertEquals(core, hearthLinkToCore(simplexChatLink(core)))
  }

  @Test
  fun linksIssuedBeforeTheSwitchStillOpen() {
    assertEquals(core, hearthLinkToCore(core))
  }

  @Test
  fun aLinkFromStockSimpleXStillOpens() {
    // Кто-то пришлёт ссылку из обычного SimpleX — открыть её мы обязаны.
    val fromStock = "https://simplex.chat/invitation#/?v=2-7&smp=x"
    assertEquals("simplex:/invitation#/?v=2-7&smp=x", hearthLinkToCore(fromStock))
  }

  @Test
  fun surroundingSpacesAreTrimmed() {
    // Вставка из буфера почти всегда приносит перевод строки на конце.
    assertEquals(core, hearthLinkToCore("  " + simplexChatLink(core) + "\n"))
  }

  @Test
  fun somethingElseIsLeftAlone() {
    // Не ссылка-приглашение — не наше дело: пусть разбирается ядро и скажет своё.
    assertEquals("не ссылка вовсе", hearthLinkToCore("не ссылка вовсе"))
    assertEquals("https://example.org/x", hearthLinkToCore("https://example.org/x"))
  }
}
