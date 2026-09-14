package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * «Чат запущен» показывается только тогда, когда это правда.
 *
 * Тест написан по живой жалобе: человек удалил приложение, поставил заново, и чат не
 * работал — при том что в настройках стояло «чат запущен». Помогало только вручную
 * выключить и включить обратно.
 *
 * Причина — третье состояние. `chatRunning` это `Boolean?`, и `null` означает «ядро
 * ещё ни разу не запускали». Сравнение `== false`, которым это место было написано в
 * upstream, отправляет `null` в ветку «работает»: не равно `false` — значит не
 * остановлен. Человеку показывали галочку у мёртвого ядра.
 *
 * Здесь проверяются все три значения поимённо. Если ребейз на новый тег upstream
 * вернёт `== false`, тест назовёт ровно то, что сломалось.
 */
class HearthChatStateTest {

  @Test
  fun null_is_not_running() {
    // Самый важный случай: свежая установка, ядро ещё не стартовало.
    assertFalse(HearthChatState.isRunning(null), "null — это «не знаем», а не «работает»")
    assertTrue(HearthChatState.isStopped(null), "неизвестность показываем как «остановлен»")
  }

  @Test
  fun started_is_running() {
    assertTrue(HearthChatState.isRunning(true))
    assertFalse(HearthChatState.isStopped(true))
  }

  @Test
  fun stopped_by_hand_is_not_running() {
    assertFalse(HearthChatState.isRunning(false))
    assertTrue(HearthChatState.isStopped(false))
  }

  @Test
  fun running_and_stopped_never_agree() {
    for (flag in listOf(null, true, false)) {
      assertTrue(
        HearthChatState.isRunning(flag) != HearthChatState.isStopped(flag),
        "состояние $flag описано противоречиво"
      )
    }
  }
}
