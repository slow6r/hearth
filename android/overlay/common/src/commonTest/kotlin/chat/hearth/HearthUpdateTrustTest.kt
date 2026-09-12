package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Доверие к манифесту обновления — таблица случаев.
 *
 * Проверяет то, ради чего появилась подпись: что делает клиент, когда узел раздачи
 * захвачен. Подменить сборку такой узел не может (её нечем подписать), поэтому
 * остаются два приёма — снять подпись и откатить метаданные. Оба обязаны быть отказом.
 */
class HearthUpdateTrustTest {

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
    )
    assertEquals(HearthUpdateTrust.Verdict.Allow, verdict)
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
      )
    )
    assertTrue(reason.contains("отметки времени"), reason)
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
      )
    )
    assertTrue(reason.contains("старее"), reason)
  }

  @Test
  fun the_same_timestamp_is_allowed() {
    // Повторная проверка обновлений не должна упираться в собственный след.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow,
      HearthUpdateTrust.decide(
        hasPinnedKey = true,
        signaturePresent = true,
        signatureValid = true,
        issued = "2026-09-11T08:00:00Z",
        lastSeenIssued = "2026-09-11T08:00:00Z",
      )
    )
  }

  @Test
  fun a_build_without_a_pinned_key_does_not_pretend_to_check() {
    // Сборка «по QR» ключа не имеет. Делать вид, что проверка прошла, хуже, чем
    // честно её не делать.
    assertEquals(
      HearthUpdateTrust.Verdict.Allow,
      HearthUpdateTrust.decide(
        hasPinnedKey = false,
        signaturePresent = false,
        signatureValid = false,
        issued = null,
        lastSeenIssued = null,
      )
    )
  }

  @Test
  fun silence_becomes_visible_after_a_month() {
    // Захваченный узел не может подсунуть своё, но может молчать. Молчание — тоже
    // событие, и человек должен о нём узнать.
    assertTrue(HearthUpdateTrust.isStale(lastSuccessEpochDays = 100, todayEpochDays = 130))
    assertTrue(!HearthUpdateTrust.isStale(lastSuccessEpochDays = 100, todayEpochDays = 129))
    assertTrue(!HearthUpdateTrust.isStale(lastSuccessEpochDays = null, todayEpochDays = 500))
  }
}
