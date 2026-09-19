package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Приведение к узлу не отбирает связь.
 *
 * Раньше телефон с профилем и пустым `hearthDeviceId` (восстановление из архива,
 * очистка данных приложения системой) на КАЖДОМ запуске уводился в экран узла, а тот
 * подменял собой весь интерфейс. Выхода не было: код доступа требует и владельца узла,
 * и доступного узла. Складываясь со сценарием «узел недоступен неделю», это давало
 * состояние без выхода вовсе — человек с полностью рабочей базой не видел ни одного
 * чата.
 *
 * Здесь проверяется правило видимости плашки, которая пришла на место того экрана.
 */
class HearthNodeSetupTest {

  private val today = 20_000L

  @Test
  fun an_enrolled_phone_sees_nothing() {
    assertFalse(hearthNodeBannerVisible(notOnNode = false, dismissedDay = null, today = today))
    // И закрытая когда-то плашка не возвращается, когда возвращаться уже не с чем.
    assertFalse(hearthNodeBannerVisible(notOnNode = false, dismissedDay = today - 100, today = today))
  }

  @Test
  fun a_phone_that_is_not_on_the_node_is_told_about_it() {
    assertTrue(hearthNodeBannerVisible(notOnNode = true, dismissedDay = null, today = today))
  }

  @Test
  fun closing_the_banner_really_closes_it() {
    // Главное свойство: плашка ЗАКРЫВАЕМАЯ. Иначе это тот же локаут, только в профиль.
    assertFalse(hearthNodeBannerVisible(notOnNode = true, dismissedDay = today, today = today))
    assertFalse(
      hearthNodeBannerVisible(
        notOnNode = true,
        dismissedDay = today,
        today = today + HearthNodeSetup.SNOOZE_DAYS - 1,
      )
    )
  }

  @Test
  fun the_banner_comes_back_by_itself() {
    // Состояние настоящее и чинить его надо: незаведённое устройство не отзывается,
    // если потеряется. Поэтому «позже», а не «никогда».
    assertTrue(
      hearthNodeBannerVisible(
        notOnNode = true,
        dismissedDay = today,
        today = today + HearthNodeSetup.SNOOZE_DAYS,
      )
    )
  }

  @Test
  fun clocks_moved_backwards_do_not_hide_the_banner_for_years() {
    // Дату на этих телефонах переводят руками. Одно неверное значение не должно
    // прятать плашку на годы вперёд.
    assertTrue(hearthNodeBannerVisible(notOnNode = true, dismissedDay = today + 5_000, today = today))
  }

  @Test
  fun a_restored_archive_is_not_a_first_run() {
    // База с профилем при пустых hearth-настройках — это восстановление архива или
    // очистка данных приложения системой, а не чистая установка. План шагов их уже
    // различает; текст экрана подключения — тоже, иначе «Код доступа» посреди
    // рабочего дня читается как «приложение забыло всё».
    assertTrue(HearthNodeText.RESTORED_TITLE != HearthOnboardingText.CODE_TITLE)
    assertTrue(HearthNodeText.RESTORED_BODY != HearthOnboardingText.CODE_BODY)
    assertTrue(HearthNodeText.RESTORED_LATER.isNotBlank(), "выход с экрана обязан быть подписан")
  }

  @Test
  fun the_banner_says_that_messaging_still_works() {
    // Человек видит незнакомую плашку в приложении, которым пользуется каждый день.
    // Если не сказать сразу, что связь в порядке, он начнёт чинить — переустановкой,
    // то есть потерей переписки.
    assertTrue(HearthNodeText.BANNER_BODY.contains("работают как обычно"))
    assertTrue(HearthNodeText.BANNER_CONNECT.isNotBlank())
    assertTrue(HearthNodeText.BANNER_LATER.isNotBlank())
  }

  @Test
  fun the_plan_still_asks_a_restored_phone_to_join_the_node() {
    // Само решение не изменилось — изменилось то, как оно показывается: раньше это
    // была подмена всего интерфейса, теперь плашка.
    assertEquals(
      setOf(HearthBringUpStep.Onboarding, HearthBringUpStep.DisableOperators),
      hearthBringUpPlan(enrolled = false, dbHasUser = true, dbHasOwnServers = true),
    )
  }
}
