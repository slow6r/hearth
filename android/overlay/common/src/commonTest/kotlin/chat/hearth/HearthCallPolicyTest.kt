package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Прикладной AES: звонок без него больше не проходит молча.
 *
 * Сегодня (флаг выключен) это предупреждение, завтра (флаг включён) — отказ. Тест
 * проверяет ОБА режима параметром, а не только тот, что включён: иначе переключение
 * флага в релизе было бы непроверенным изменением поведения.
 */
class HearthCallPolicyTest {

  @Test
  fun the_flag_ships_off_until_every_phone_is_updated() {
    // Включённый запрет ломает звонки со сборками h17…h21, которые сейчас стоят у
    // семьи. Включать его можно только вместе с раскаткой — см. HearthCallPolicy.
    assertEquals(false, HearthCallPolicy.REQUIRE_APP_AES)
  }

  @Test
  fun both_layers_present_means_an_ordinary_call() {
    assertEquals(
      HearthCallDecision.Allow,
      hearthCallDecision(localEncryption = true, sharedKey = "k", askConfirmation = false, mandatory = true),
    )
    assertEquals(
      HearthCallDecision.Allow,
      hearthCallDecision(localEncryption = true, sharedKey = "k", askConfirmation = false, mandatory = false),
    )
  }

  @Test
  fun a_missing_shared_key_is_refused_when_the_layer_is_mandatory() {
    val decision = hearthCallDecision(localEncryption = true, sharedKey = null, mandatory = true)
    assertTrue(decision is HearthCallDecision.Refuse, "звонок без общего ключа обязан быть отклонён")
    assertTrue(decision.reason?.isNotBlank() == true, "человеку надо сказать, почему звонок не идёт")
  }

  @Test
  fun a_missing_shared_key_is_only_a_warning_while_the_flag_is_off() {
    // Ровно то, что выкатывается сейчас: звонок идёт, но человек об этом знает.
    val decision = hearthCallDecision(localEncryption = true, sharedKey = null, mandatory = false)
    assertTrue(decision is HearthCallDecision.Warn)
    assertTrue(decision.reason?.isNotBlank() == true)
  }

  @Test
  fun a_downgrade_with_a_key_is_caught_too() {
    // askConfirmation = true при непустом ключе: мы просили шифрованный звонок,
    // собеседник не смог. Раньше этот флаг не читался вообще.
    val decision =
      hearthCallDecision(localEncryption = true, sharedKey = "k", askConfirmation = true, mandatory = true)
    assertTrue(decision is HearthCallDecision.Refuse)
  }

  @Test
  fun an_old_webview_on_our_own_side_is_caught_before_the_call_starts() {
    // WebView без insertable streams: шифровать не умеет НАША сторона, и узнаём мы
    // это из ответа Capabilities — до того, как отправлено приглашение.
    val decision = hearthCallDecision(localEncryption = false, sharedKey = "k", mandatory = true)
    assertTrue(decision is HearthCallDecision.Refuse)
    assertTrue(decision.reason?.contains("WebView") == true)
  }

  @Test
  fun the_reason_differs_by_cause() {
    // Одно сообщение на все случаи бесполезно: «у собеседника старая версия» и «у вас
    // старый WebView» чинятся разными людьми.
    val theirs = hearthCallDecision(localEncryption = true, sharedKey = null, mandatory = true)
    val ours = hearthCallDecision(localEncryption = false, sharedKey = null, mandatory = true)
    assertTrue(theirs is HearthCallDecision.Refuse)
    assertTrue(ours is HearthCallDecision.Refuse)
    assertTrue(theirs.reason != ours.reason)
  }

  @Test
  fun our_own_side_is_judged_before_the_peer_has_answered() {
    // Точка «WebView сообщил свои возможности»: общего ключа ещё нет и быть не может,
    // поэтому его отсутствие не должно превращаться в жалобу на собеседника.
    assertEquals(HearthCallDecision.Allow, hearthLocalCallDecision(localEncryption = true, mandatory = true))
    val old = hearthLocalCallDecision(localEncryption = false, mandatory = false)
    assertTrue(old is HearthCallDecision.Warn)
    assertTrue(old.reason?.contains("WebView") == true, "причина должна указывать на НАШУ сторону")
  }

  @Test
  fun with_the_flag_off_no_branch_ever_ends_the_call() {
    // То, ради чего флаг сегодня выключен: при REQUIRE_APP_AES = false ни одна
    // комбинация не даёт Refuse. Если ветка появится, звонки со сборками h17…h21
    // оборвутся — а этого в выкатываемом релизе быть не должно.
    val flags = listOf(true, false)
    val keys = listOf("k", null)
    for (local in flags) {
      for (key in keys) {
        for (ask in flags) {
          val decision = hearthCallDecision(local, key, ask, mandatory = false)
          assertFalse(
            decision is HearthCallDecision.Refuse,
            "local=$local key=$key ask=$ask завершает звонок при выключенном флаге",
          )
        }
      }
    }
    // И то же для точки «свои возможности», где ключа ещё нет.
    for (local in flags) {
      assertFalse(hearthLocalCallDecision(local, mandatory = false) is HearthCallDecision.Refuse)
    }
  }

  // --- память предупреждений --------------------------------------------------------

  @Test
  fun the_same_peer_is_complained_about_once_per_session() {
    // Пока в семье стоят сборки h17…h21, sharedKey у них пуст ВСЕГДА. По ключу «звонок»
    // окно всплывало на каждый звонок с этими телефонами — и его переставали читать.
    HearthCallNotice.forget()
    assertTrue(HearthCallNotice.shouldTell("@2", "причина"))
    assertFalse(HearthCallNotice.shouldTell("@2", "причина"))
    // Следующий звонок с тем же собеседником — это не новость.
    assertFalse(HearthCallNotice.shouldTell("@2", "причина"))
    HearthCallNotice.forget()
  }

  @Test
  fun a_different_reason_about_the_same_peer_is_news() {
    HearthCallNotice.forget()
    assertTrue(HearthCallNotice.shouldTell("@2", "причина"))
    assertTrue(HearthCallNotice.shouldTell("@2", "другая причина"))
    // И чередование причин больше ничего не воскрешает: хранится набор, а не
    // последняя пара, как было.
    assertFalse(HearthCallNotice.shouldTell("@2", "причина"))
    assertFalse(HearthCallNotice.shouldTell("@2", "другая причина"))
    HearthCallNotice.forget()
  }

  @Test
  fun a_different_peer_is_a_separate_story() {
    // Изъян принадлежит собеседнику: про телефон брата и про телефон бабушки надо
    // сказать по разу, а не один раз на двоих.
    HearthCallNotice.forget()
    assertTrue(HearthCallNotice.shouldTell("@2", "причина"))
    assertTrue(HearthCallNotice.shouldTell("@3", "причина"))
    assertFalse(HearthCallNotice.shouldTell("@3", "причина"))
    HearthCallNotice.forget()
  }

  @Test
  fun an_unknown_peer_is_still_told_about_only_once() {
    // Собеседник неизвестен — ключом остаётся причина. Повторять её на каждый звонок
    // значит перестать быть услышанным, а это и есть вся польза предупреждения.
    HearthCallNotice.forget()
    assertTrue(HearthCallNotice.shouldTell(null, "причина"))
    assertFalse(HearthCallNotice.shouldTell(null, "причина"))
    HearthCallNotice.forget()
  }

  @Test
  fun forgetting_starts_the_session_over() {
    // Кто зовёт forget() в продуктовом коде: views/database/DatabaseView.kt — при
    // остановке чата (звонков больше нет) и сразу после восстановления базы из архива.
    // Второй случай и есть причина, по которой сброс обязателен: ключ памяти —
    // Contact.id, а в восстановленной базе тот же «@2» принадлежит уже другому
    // человеку, и предупреждение о НЁМ было бы съедено как уже сказанное.
    HearthCallNotice.forget()
    assertTrue(HearthCallNotice.shouldTell("@2", "причина"))
    assertFalse(HearthCallNotice.shouldTell("@2", "причина"))
    HearthCallNotice.forget()
    assertTrue(
      HearthCallNotice.shouldTell("@2", "причина"),
      "после сброса про того же собеседника обязаны сказать снова",
    )
    HearthCallNotice.forget()
  }

  @Test
  fun the_refusal_text_says_the_call_will_not_happen() {
    // Раньше при отказе человек видел то же окно «защищён слабее обычного», после
    // которого звонок просто обрывался, — и чинил это переустановкой приложения.
    assertTrue(HearthCallText.REFUSED_TITLE.isNotBlank())
    assertTrue(HearthCallText.REFUSED_BODY.contains("не состоится"))
    assertTrue(HearthCallText.REFUSED_TITLE != HearthCallText.ALERT_TITLE)
  }
}
