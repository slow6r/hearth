package chat.hearth

import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Приведение к своему узлу: что считается выполненным и что надо повторить.
 *
 * Флаг «отработало» ставился ПЕРВОЙ строкой, до единого шага. Значит любая осечка
 * (ядро отказало, сеть моргнула, профиль не готов) записывалась в журнал — и повтора
 * не было до конца жизни процесса. Операторы SimpleX могли остаться включёнными,
 * то есть воспроизводился ровно тот сценарий, ради которого файл и написан.
 *
 * Настоящие шаги тянут ChatController, которого на JVM нет, поэтому цепочка принимает
 * шаги параметром — и здесь подставляются свои.
 */
class HearthStartupTest {

  @BeforeTest
  fun clean() = HearthStartup.reset()

  @AfterTest
  fun tidy() = HearthStartup.reset()

  private fun step(name: String, outcome: HearthStepOutcome, counter: MutableList<String>) =
    HearthStartupStep(name) {
      counter.add(name)
      outcome
    }

  @Test
  fun a_fully_successful_run_is_not_repeated() = runBlocking {
    val ran = mutableListOf<String>()
    val steps = listOf(
      step("первый", HearthStepOutcome.Done, ran),
      step("второй", HearthStepOutcome.Done, ran),
    )

    hearthAfterChatStarted(steps)
    assertEquals(listOf("первый", "второй"), ran)
    assertFalse(HearthStartup.shouldRun())

    hearthAfterChatStarted(steps)
    assertEquals(listOf("первый", "второй"), ran, "цепочка прошла второй раз без нужды")
  }

  @Test
  fun a_failed_step_leaves_the_chain_due_again() = runBlocking {
    val ran = mutableListOf<String>()
    val steps = listOf(
      step("сломанный", HearthStepOutcome.Failed, ran),
      step("целый", HearthStepOutcome.Done, ran),
    )

    hearthAfterChatStarted(steps)

    // Соседей осечка НЕ отменяет: защита, выключающаяся целиком от одной ошибки, хуже
    // её отсутствия — человек уверен, что она работает.
    assertEquals(listOf("сломанный", "целый"), ran)
    assertTrue(HearthStartup.shouldRun(), "неудача помечена как выполненное приведение")
  }

  @Test
  fun a_step_that_is_not_applicable_yet_is_not_success() = runBlocking {
    // Устройство ещё не заведено. Считать это успехом значило бы навсегда оставить без
    // приведения телефон, на котором bundle применят через час.
    val ran = mutableListOf<String>()
    hearthAfterChatStarted(listOf(step("свои серверы", HearthStepOutcome.NotApplicable, ran)))

    assertTrue(HearthStartup.shouldRun())
  }

  @Test
  fun a_thrown_step_does_not_wedge_the_chain() = runBlocking {
    val ran = mutableListOf<String>()
    val steps = listOf(
      HearthStartupStep("бросает") { throw IllegalStateException("chatNotStarted") },
      step("следующий", HearthStepOutcome.Done, ran),
    )

    hearthAfterChatStarted(steps)

    assertEquals(listOf("следующий"), ran)
    // Главное: цепочка не осталась «занятой» навсегда — иначе её не повторит никто.
    assertTrue(HearthStartup.shouldRun())
  }

  @Test
  fun a_second_entry_while_running_does_not_start_a_second_chain() = runBlocking {
    val ran = mutableListOf<String>()
    val reentrant = listOf(
      HearthStartupStep("внешний") {
        // Так выглядит конкурентный startChat: пока цепочка идёт, зовут ещё раз.
        hearthAfterChatStarted(listOf(step("внутренний", HearthStepOutcome.Done, ran)))
        ran.add("внешний")
        HearthStepOutcome.Done
      }
    )

    hearthAfterChatStarted(reentrant)

    assertEquals(listOf("внешний"), ran)
  }

  @Test
  fun stopping_the_chat_makes_the_chain_due_again() = runBlocking {
    hearthAfterChatStarted(listOf(HearthStartupStep("шаг") { HearthStepOutcome.Done }))
    assertFalse(HearthStartup.shouldRun())

    HearthStartup.reset()
    assertTrue(HearthStartup.shouldRun())
  }

  // --- восстановление из архива (UPD-9) ---------------------------------------------

  @Test
  fun a_clean_install_only_gets_the_onboarding() {
    // Выключить операторов здесь означало бы оставить телефон вовсе без серверов:
    // своих ещё нет, чужие выключены — вместо экрана настройки человек видит ошибку.
    assertEquals(
      setOf(HearthBringUpStep.Onboarding),
      hearthBringUpPlan(enrolled = false, dbHasUser = false, dbHasOwnServers = false),
    )
  }

  @Test
  fun a_restored_archive_is_asked_for_the_node_and_loses_its_operators() {
    // База с профилем и чужими серверами при пустых hearth-настройках — это ровно
    // восстановление архива. Раньше здесь не делалось НИЧЕГО.
    val plan = hearthBringUpPlan(enrolled = false, dbHasUser = true, dbHasOwnServers = true)

    assertEquals(
      setOf(HearthBringUpStep.Onboarding, HearthBringUpStep.DisableOperators),
      plan,
    )
  }

  @Test
  fun a_restored_archive_without_own_servers_keeps_its_operators() {
    // Своих серверов в базе нет — выключать операторов некуда. Сначала узел.
    assertEquals(
      setOf(HearthBringUpStep.Onboarding),
      hearthBringUpPlan(enrolled = false, dbHasUser = true, dbHasOwnServers = false),
    )
  }

  @Test
  fun an_enrolled_phone_gets_everything() {
    assertEquals(
      setOf(
        HearthBringUpStep.DisableOperators,
        HearthBringUpStep.MigrateRelayPort,
        HearthBringUpStep.CleanUpForeignLinks,
      ),
      hearthBringUpPlan(enrolled = true, dbHasUser = true, dbHasOwnServers = true),
    )
  }

  @Test
  fun an_enrolled_phone_with_an_empty_database_starts_from_the_onboarding() {
    // Базу удалили, преф остался. Трогать в базе нечего — там ещё нет профиля.
    assertEquals(
      setOf(HearthBringUpStep.Onboarding),
      hearthBringUpPlan(enrolled = true, dbHasUser = false, dbHasOwnServers = false),
    )
  }

  // --- ограничение повторов (UPD-8) --------------------------------------------------

  @Test
  fun the_first_run_is_never_delayed() {
    // Обычный запуск приложения: задержки на этом пути быть не должно.
    assertTrue(hearthStartupDue(attempts = 0, lastRunMs = 0, nowMs = 0))
    assertTrue(hearthStartupDue(attempts = 0, lastRunMs = 12_345, nowMs = 12_345))
  }

  @Test
  fun a_second_run_waits_out_the_gap() {
    // Точка повтора — выход приложения на передний план, а он случается десятки раз в
    // день. Шаг «порт релея» при этом ходит в сеть, то есть заставляет ждать ровно
    // там, где человек ждёт список чатов.
    val start = 1_000_000L
    assertFalse(hearthStartupDue(attempts = 1, lastRunMs = start, nowMs = start))
    assertFalse(hearthStartupDue(attempts = 1, lastRunMs = start, nowMs = start + HearthStartup.MIN_GAP_MS - 1))
    assertTrue(hearthStartupDue(attempts = 1, lastRunMs = start, nowMs = start + HearthStartup.MIN_GAP_MS))
  }

  @Test
  fun the_attempts_run_out() {
    // Не вышло за полтора часа — дело не в моргнувшей сети. Дёргать ядро и узел
    // дальше незачем: счёт начнёт заново следующий запуск приложения.
    val start = 1_000_000L
    val late = start + HearthStartup.MIN_GAP_MS * 100
    assertTrue(hearthStartupDue(attempts = HearthStartup.MAX_ATTEMPTS - 1, lastRunMs = start, nowMs = late))
    assertFalse(hearthStartupDue(attempts = HearthStartup.MAX_ATTEMPTS, lastRunMs = start, nowMs = late))
  }

  @Test
  fun clocks_moved_backwards_do_not_wedge_the_chain() {
    // Одно неверное значение времени не должно запирать приведение до перезапуска
    // приложения: часы на этих телефонах переводят руками, и не по одному разу.
    assertTrue(hearthStartupDue(attempts = 1, lastRunMs = 5_000_000, nowMs = 1_000))
  }

  @Test
  fun the_throttle_really_blocks_the_chain() {
    val ran = mutableListOf<String>()
    val steps = listOf(step("незаконченный", HearthStepOutcome.Failed, ran))
    val start = 1_000_000L

    runBlocking { hearthAfterChatStarted(steps, nowMs = start) }
    assertEquals(1, ran.size)

    // Тот же выход на передний план через минуту: цепочка не прошла, но и повторять
    // рано.
    runBlocking { hearthAfterChatStarted(steps, nowMs = start + 60_000) }
    assertEquals(1, ran.size, "цепочка повторилась раньше срока")

    runBlocking { hearthAfterChatStarted(steps, nowMs = start + HearthStartup.MIN_GAP_MS) }
    assertEquals(2, ran.size, "цепочка не повторилась, когда срок вышел")
  }

  @Test
  fun applying_a_bundle_lifts_the_throttle_at_once() {
    // Человек только что ввёл код доступа: причина пробовать новая, и ждать четверть
    // часа было бы издевательством. HearthImportView зовёт reset() именно за этим.
    val ran = mutableListOf<String>()
    val steps = listOf(step("шаг", HearthStepOutcome.Failed, ran))
    val start = 1_000_000L

    runBlocking { hearthAfterChatStarted(steps, nowMs = start) }
    HearthStartup.reset()
    runBlocking { hearthAfterChatStarted(steps, nowMs = start + 1) }

    assertEquals(2, ran.size)
  }
}
