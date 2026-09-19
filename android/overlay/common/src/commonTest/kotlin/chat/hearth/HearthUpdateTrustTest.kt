package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Доверие к манифесту обновления — таблица случаев.
 *
 * Проверяет то, ради чего появилась подпись: что делает клиент, когда узел раздачи
 * захвачен. Подменить сборку такой узел не может (её нечем подписать), поэтому
 * остаются три приёма — снять подпись, откатить метаданные и замолчать, вечно отдавая
 * один и тот же старый подписанный манифест. Все три обязаны быть отказом.
 */
class HearthUpdateTrustTest {

  // 2026-09-12 в днях эпохи — тот же день, что у «свежих» отметок ниже.
  private val today = hearthEpochDaysOf("2026-09-12T00:00:00Z")!!

  private fun refusal(verdict: HearthUpdateTrust.Verdict): String {
    assertTrue(verdict is HearthUpdateTrust.Verdict.Refuse, "ожидался отказ, получено: $verdict")
    return (verdict as HearthUpdateTrust.Verdict.Refuse).reason
  }

  @Test
  fun a_signed_fresh_manifest_is_allowed() {
    val verdict = HearthUpdateTrust.decide(
      hasPinnedKey = true,
      signaturePresent = true,
      signatureValid = true,
      issued = "2026-09-12T08:00:00Z",
      lastSeenIssued = "2026-09-11T08:00:00Z",
      nowEpochDays = today,
    )
    assertEquals(HearthUpdateTrust.Verdict.Allow(), verdict)
  }

  @Test
  fun a_missing_signature_is_refused() {
    // Иначе защиту выключает тот, от кого она защищает: достаточно удалить .sig.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = false,
        signatureValid = false,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("не подписан"), reason)
  }

  @Test
  fun a_broken_signature_is_refused() {
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = false,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("не сошлась"), reason)
  }

  @Test
  fun a_manifest_without_a_timestamp_is_refused() {
    // Без отметки времени откат метаданных не поймать.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = null,
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("отметки времени"), reason)
  }

  @Test
  fun an_unparsable_timestamp_is_refused() {
    // Неразобранная отметка — это отсутствие проверки свежести, а не мелочь.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "позавчера",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("не разобрана"), reason)
  }

  @Test
  fun rolled_back_metadata_is_refused() {
    // Подпись верна — манифест действительно наш, просто старый. Так выглядит
    // попытка удержать телефон на версии с известной дырой.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-01T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("старее"), reason)
  }

  @Test
  fun a_rollback_hidden_by_an_offset_is_still_a_rollback() {
    // Строковое сравнение здесь ошибалось: «2026-09-11T23:00:00+03:00» — это
    // 20:00 UTC 11-го, то есть СТАРЕЕ полуночи 12-го, хотя лексикографически больше.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T23:00:00+03:00",
        lastSeenIssued = "2026-09-12T00:00:00Z",
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("старее"), reason)
  }

  @Test
  fun the_same_timestamp_inside_the_window_is_allowed() {
    // Повторная проверка обновлений не должна упираться в собственный след, пока окно
    // не вышло: узел мог просто не выпускать новых версий эту неделю.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow(),
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
        nowEpochDays = today,
        firstSeenEpochDays = today - 1,
      )
    )
  }

  @Test
  fun the_same_timestamp_past_the_window_is_refused() {
    // Заморозка. Здесь считается только ПРОШЕДШИЙ локальный интервал, поэтому
    // переведённые часы правило не обходят.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
        nowEpochDays = today,
        firstSeenEpochDays = today - HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS,
      )
    )
    assertTrue(reason.contains("один и тот же манифест"), reason)
  }

  @Test
  fun a_manifest_older_than_the_limit_is_refused() {
    // Девять месяцев без переподписи. Потолок стоит далеко (полгода) именно затем,
    // чтобы сюда попадала брошенная раздача, а не спокойный год без новых релизов.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2025-12-01T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("старше"), reason)
    // Текст обязан называть дату телефона: доверенных часов нет, и человек должен
    // знать, куда смотреть, а не остаться без обновлений без объяснения.
    assertTrue(reason.contains("дата"), reason)
  }

  @Test
  fun a_manifest_from_the_future_is_refused() {
    // Иначе узел ставит дату вперёд и обходит правило возраста навсегда.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-10-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("будущим"), reason)
  }

  @Test
  fun a_day_ahead_is_still_allowed() {
    // Часовые пояса и выпуск релиза в другом полушарии дают законный разбег.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow(),
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-13T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
  }

  @Test
  fun a_build_without_a_pinned_key_refuses() {
    // Раньше здесь стоял Allow: нет ключа — не проверяем. Значит достаточно было
    // вырезать ресурс, чтобы манифест снова принимался от кого угодно.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = false,
        signatureValid = false,
        issued = null,
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("нет ключа"), reason)
  }

  @Test
  fun a_valid_signature_does_not_rescue_a_keyless_build() {
    // Подпись «сошлась» без вшитого ключа означает только то, что её проверял узел.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("нет ключа"), reason)
  }

  @Test
  fun a_build_without_a_key_is_told_what_to_do() {
    // Отказ правильный: проверять подпись нечем. Но он не пройдёт сам ни завтра, ни
    // через месяц, и «в сборке нет ключа» без продолжения — тупик, из которого человек
    // не выберется. Текст обязан называть действие целиком.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = false,
        signatureValid = false,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("нет ключа"), reason)
    assertTrue(reason.contains("Переустановите"), reason)
    assertTrue(reason.contains("владельца узла"), reason)
    // И снимать панику: обновлений нет, но связь цела.
    assertTrue(reason.contains("Переписка"), reason)
  }

  @Test
  fun a_build_that_declares_itself_unsigned_may_update() {
    // Сборка без проверки подписи всё ещё возможна — но только как ЯВНО заявленная
    // отдельным ресурсом, который релизный гейт не пропускает.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow(),
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = false,
        signatureValid = false,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        unsignedUpdatesAllowed = true,
      )
    )
  }

  @Test
  fun a_declared_unsigned_build_still_checks_freshness() {
    // Заморозка одинаково опасна в любой сборке: она от ключа не зависит.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = false,
        signatureValid = false,
        issued = "2025-12-01T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        unsignedUpdatesAllowed = true,
      )
    )
    assertTrue(reason.contains("старше"), reason)
  }

  @Test
  fun silence_becomes_visible_within_a_week() {
    // Захваченный узел не может подсунуть своё, но может молчать. Молчание — тоже
    // событие, и человек должен о нём узнать. Семь дней — горизонт ТЗ §1.4; это
    // счётчик молчания, а не отказ, поэтому ранняя граница здесь ничего не стоит.
    assertTrue(
      HearthUpdateTrust.isStale(
        lastSuccessEpochDays = 100,
        todayEpochDays = 107,
        failedAttemptDays = 4,
      )
    )
    assertTrue(
      !HearthUpdateTrust.isStale(
        lastSuccessEpochDays = 100,
        todayEpochDays = 106,
        failedAttemptDays = 4,
      )
    )
    // Проверки не было ни разу — так выглядит свежеустановленное приложение.
    assertTrue(
      !HearthUpdateTrust.isStale(
        lastSuccessEpochDays = null,
        todayEpochDays = 500,
        failedAttemptDays = 99,
      )
    )
  }

  @Test
  fun a_phone_that_was_not_trying_does_not_accuse_the_node() {
    // Замечание критика: считались календарные дни, поэтому телефон, сам неделю не
    // выходивший в сеть (уехали, выключили, кончился интернет), обвинял узел — и
    // человека посылали к владельцу узла зря, а тот ничего не находил.
    assertTrue(
      !HearthUpdateTrust.isStale(
        lastSuccessEpochDays = 100,
        todayEpochDays = 130,
        failedAttemptDays = 0,
      )
    )
    // Одна-две неудачи — ещё не молчание: столько даёт один перезагружающийся роутер.
    assertTrue(
      !HearthUpdateTrust.isStale(
        lastSuccessEpochDays = 100,
        todayEpochDays = 130,
        failedAttemptDays = 2,
      )
    )
    // А вот три РАЗНЫХ дня без единого ответа — это уже не совпадение.
    assertTrue(
      HearthUpdateTrust.isStale(
        lastSuccessEpochDays = 100,
        todayEpochDays = 130,
        failedAttemptDays = 3,
      )
    )
  }

  // --- срок годности манифеста (UPD-2) ------------------------------------------------
  //
  // Две ветки, и обе настоящие: манифест С полем expires (оператор назначил срок при
  // подписи) и БЕЗ него (манифесты прежних версий). Первая редакция правила знала только
  // вторую ветку и отказывала через 14 дней — то есть требовала от узла переподписывать
  // манифест, чего узел не умеет: ключ лежит на рабочей станции. Две недели без человека
  // у станции оставляли всю семью без обновлений.

  private fun allowance(verdict: HearthUpdateTrust.Verdict): String? {
    assertTrue(verdict is HearthUpdateTrust.Verdict.Allow, "ожидалось согласие, получено: $verdict")
    return (verdict as HearthUpdateTrust.Verdict.Allow).notice
  }

  @Test
  fun a_declared_expiry_beats_the_age_fallback() {
    // Манифесту два с половиной месяца — запас по возрасту его бы отверг. Но оператор
    // назначил срок до декабря, а поле лежит ВНУТРИ подписанного документа: узел его не
    // подделает. Верим оператору, а не запасу.
    val notice = allowance(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-07-01T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        expires = "2026-12-01T00:00:00Z",
      )
    )
    assertNull(notice, "срок назначен и не вышел — говорить не о чем")
  }

  @Test
  fun a_manifest_past_its_declared_expiry_is_refused_with_an_instruction() {
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-10T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        expires = "2026-09-11T00:00:00Z",
      )
    )
    assertTrue(reason.contains("срок годности"), reason)
    // Отказ обязан говорить, ЧТО ДЕЛАТЬ, и обязан снимать панику: переписка цела.
    assertTrue(reason.contains("владельцем узла"), reason)
    assertTrue(reason.contains("дата"), reason)
    assertTrue(reason.contains("Переписка"), reason)
  }

  @Test
  fun an_unparsable_expiry_is_refused_too() {
    // «Поля нет» и «поле есть, и оно не то» — разные вещи. Второе спускать нельзя:
    // иначе проверка выключается тем же способом, каким её выключали бы нарочно.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-12T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        expires = "когда-нибудь",
      )
    )
    assertTrue(reason.contains("срок годности манифеста не разобран"), reason)
  }

  @Test
  fun the_day_the_expiry_falls_on_is_still_inside_it() {
    // Граница не должна отсекать день, который оператор назначил последним: человек,
    // обновляющийся в этот день, имеет на это право. Но день этот — последний, и
    // предупреждение о конце срока к нему уже относится.
    val notice = allowance(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-10T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        expires = "2026-09-12T00:00:00Z",
      )
    )
    assertTrue(notice != null && notice.contains("срок"), "получено: $notice")
  }

  @Test
  fun without_an_expiry_a_quiet_node_is_reported_not_refused() {
    // Ровно то, ради чего правило переписали: узел молчит вторую неделю, человек об
    // этом узнаёт, а обновления продолжают ставиться.
    val notice = allowance(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-02T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(notice != null && notice.contains("молчит"), "получено: $notice")
    assertTrue(notice.contains("ставятся"), notice)
  }

  @Test
  fun without_an_expiry_a_week_of_silence_is_not_even_worth_mentioning() {
    // До горизонта ТЗ §1.4 молчание — обычное дело: новых версий может просто не быть.
    assertNull(
      allowance(
        HearthUpdateTrust.decide(
          hasPinnedKey = true,
          signaturePresent = true,
          signatureValid = true,
          issued = "2026-09-05T08:00:00Z",
          lastSeenIssued = null,
          nowEpochDays = today,
        )
      )
    )
  }

  @Test
  fun the_age_allowance_is_exactly_the_number_the_runbooks_promise() {
    // Почему полгода, а не месяц — в комментарии у самой константы. Здесь
    // закреплено число. Оно живёт в четырёх местах — здесь, в hearthd
    // (model/update.rs) и в двух ранбуках — и уже однажды разъехалось:
    // docs/runbook-release.md обещал запас в 30 дней, а клиент отказывал на 180.
    // Оператор при таком расхождении готовится не к тому и чинит не то.
    assertEquals(180L, HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS)
    // И порядок границ на месте: молчание видно задолго до отказа, иначе отказ
    // стал бы первой новостью о проблеме.
    assertTrue(
      HearthUpdateTrust.QUIET_NODE_AFTER_DAYS < HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS,
      "предупреждение обязано приходить раньше отказа",
    )
  }

  @Test
  fun without_an_expiry_the_refusal_moves_out_to_half_a_year() {
    // Замечание критика: месяц — это не запас, а календарь. Узел раздаёт статический
    // manifest.json и переподписать его не может: ключ на рабочей станции. Значит,
    // возраст манифеста меряет частоту релизов, и спокойный месяц (а то и пять) без
    // нового релиза оставлял бы всю семью без канала обновлений ни за что.
    assertTrue(
      HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS >= 180,
      "потолок возраста опять стал календарём: ${HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS}",
    )
    // Пять с половиной месяцев без релиза — человеку говорят, обновления ставятся.
    val notice = allowance(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-04-01T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(notice != null && notice.contains("молчит"), "получено: $notice")
    assertTrue(notice.contains("ставятся"), notice)
    // Девять месяцев — уже похоже на брошенную раздачу, и это отказ с объяснением.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2025-12-01T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
      )
    )
    assertTrue(reason.contains("старше 180 дней"), reason)
  }

  @Test
  fun a_live_declared_expiry_switches_off_the_freeze_rule_too() {
    // Замечание критика: шапка файла обещала, что при живом `expires` возрастом манифест
    // не судят, а правило заморозки всё равно срабатывало. Оператор, назначивший срок на
    // полгода, получал отказ у ВСЕЙ семьи на тридцатый день неизменного манифеста —
    // притом что неизменный манифест и есть ровно то, о чём он договорился, подписав срок.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow(),
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
        nowEpochDays = today,
        firstSeenEpochDays = today - HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS * 2,
        expires = "2099-01-01T00:00:00Z",
      )
    )
  }

  @Test
  fun a_frozen_node_without_an_expiry_is_still_refused() {
    // Отмена заморозки держится ИМЕННО на живом сроке. Нет срока — правило работает, и
    // это единственная проверка, которую не обойти переводом часов.
    val reason = refusal(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
        nowEpochDays = today,
        firstSeenEpochDays = today - HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS,
      )
    )
    assertTrue(reason.contains("один и тот же манифест"), reason)
  }

  @Test
  fun an_expiry_running_out_is_announced_before_it_does() {
    // Переподписать манифест может только человек у рабочей станции, поэтому узнать о
    // сроке в день его истечения — значит узнать поздно: отказ уже у всех телефонов.
    // Предупреждаем за неделю, обновления при этом продолжают ставиться.
    val notice = allowance(
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-10T08:00:00Z",
        lastSeenIssued = null,
        nowEpochDays = today,
        expires = "2026-09-15T00:00:00Z",
      )
    )
    assertTrue(notice != null && notice.contains("срок"), "получено: $notice")
    assertTrue(notice.contains("ставятся"), notice)
  }
}
