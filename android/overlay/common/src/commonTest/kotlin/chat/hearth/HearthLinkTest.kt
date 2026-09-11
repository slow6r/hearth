package chat.hearth

import chat.simplex.common.model.hearthLinkToCore
import chat.simplex.common.model.hearthLinksToCore
import chat.simplex.common.model.simplexChatLink
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Своя схема ссылок-приглашений.
 *
 * Наружу человек видит `hearth:/…` и `hearth://…`, ядру уходит ровно то, что оно
 * выдало. Подмена живёт в двух функциях, поэтому проверяется здесь: ошибка в них
 * выглядит не как ошибка, а как «QR не сканируется», и разбираться пришлось бы вдвоём
 * по телефону.
 */
class HearthLinkTest {

  private val full = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40relay.example.org"

  // Формат коротких ссылок взят из живых ссылок и тестов ядра: хост — сервер, где
  // лежит приглашение, после «#» — данные, у своего сервера ещё и параметры.
  private val shortInvitation =
    "https://relay.myhearth.ru/i#9sBaQl3759sivr1nRraBqnalQzXZixl9/jwM_JDNTdfQQ6nwm9kkKNLC1INvAQg-t9eL7r-fjT_Y"
  private val shortAddress =
    "https://relay.myhearth.ru:5223/a#KKcTdpWmVWZO7WH4WswN_oHFg-DpwHbKmtgmXIZumRc?c=dl4E-N71pfk&p=5223"

  @Test
  fun aFullLinkGetsOurScheme() {
    assertEquals("hearth:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40relay.example.org", simplexChatLink(full))
  }

  @Test
  fun aShortLinkKeepsItsServerAndChangesOnlyTheScheme() {
    // Хост не трогаем: принимающая сторона пойдёт за приглашением именно на этот сервер.
    assertEquals(
      "hearth://relay.myhearth.ru/i#9sBaQl3759sivr1nRraBqnalQzXZixl9/jwM_JDNTdfQQ6nwm9kkKNLC1INvAQg-t9eL7r-fjT_Y",
      simplexChatLink(shortInvitation),
    )
  }

  @Test
  fun everyRoundTripIsExact() {
    // Ровно то же, что ушло — включая порт, якорь, слеш в данных и параметры: ядро
    // разбирает строку целиком, и потерянный символ там не «почти работает».
    for (link in listOf(full, shortInvitation, shortAddress)) {
      assertEquals(link, hearthLinkToCore(simplexChatLink(link)))
    }
  }

  @Test
  fun aLinkInsideTextIsReturnedToTheCore() {
    // Так человек и вставляет: с подписью вокруг.
    val text = "вот моя ссылка: ${simplexChatLink(shortInvitation)} — жду"
    assertEquals("вот моя ссылка: $shortInvitation — жду", hearthLinksToCore(text))
  }

  @Test
  fun bothFormsInOneTextAreReturned() {
    val text = "${simplexChatLink(full)}\n${simplexChatLink(shortAddress)}"
    assertEquals("$full\n$shortAddress", hearthLinksToCore(text))
  }

  @Test
  fun linksIssuedBeforeTheSwitchStillOpen() {
    assertEquals(full, hearthLinkToCore(full))
    assertEquals(shortInvitation, hearthLinkToCore(shortInvitation))
  }

  @Test
  fun aFullLinkFromStockSimpleXStillOpens() {
    assertEquals("simplex:/invitation#/?v=2-7&smp=x", hearthLinkToCore("https://simplex.chat/invitation#/?v=2-7&smp=x"))
  }

  @Test
  fun surroundingSpacesAreTrimmed() {
    // Вставка из буфера почти всегда приносит перевод строки на конце.
    assertEquals(shortInvitation, hearthLinkToCore("  " + simplexChatLink(shortInvitation) + "\n"))
  }

  @Test
  fun anOrdinaryWebLinkIsNotDecorated() {
    // Украшается только короткая ссылка ядра: «/буква#». Обычный адрес сайта — нет.
    assertEquals("https://example.org/news", simplexChatLink("https://example.org/news"))
    assertEquals("https://example.org/page#top", simplexChatLink("https://example.org/page#top"))
  }

  @Test
  fun aWordThatMerelyEndsInHearthIsLeftAlone() {
    assertEquals("myhearth://x и a.hearth:/y", hearthLinksToCore("myhearth://x и a.hearth:/y"))
    assertEquals("не ссылка вовсе", hearthLinkToCore("не ссылка вовсе"))
  }
}
