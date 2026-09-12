package chat.hearth

/**
 * Доверие к манифесту обновления.
 *
 * # Зачем
 *
 * Раньше подлинность манифеста держалась на серверном TLS — то есть на самом узле.
 * Захват узла раздачи означал власть над тем, что клиент считает свежей версией и
 * какой файл качает. Прямую подмену сборки Android отверг бы (чужая подпись не
 * установится), но заморозку — нет: узел мог просто не отдавать обновления и держать
 * людей на версии с известной дырой.
 *
 * Теперь манифест подписан ключом, которого на узле нет. Здесь — решение о доверии:
 * чистая логика, отделённая от криптографии и от сети, чтобы её можно было прогнать
 * по таблице случаев на JVM.
 *
 * # Почему отсутствие подписи — отказ
 *
 * Сборка, в которую вшит открытый ключ, обязана требовать подпись. Иначе достаточно
 * убрать `.sig` с узла, чтобы вернуться к старому — и вся защита выключается тем,
 * кого она должна останавливать.
 */
object HearthUpdateTrust {

  sealed interface Verdict {
    data object Allow : Verdict
    data class Refuse(val reason: String) : Verdict
  }

  /**
   * @param hasPinnedKey вшит ли в сборку открытый ключ. Сборки «по QR» его не имеют.
   * @param signaturePresent лежит ли рядом с манифестом `.sig`.
   * @param signatureValid сошлась ли подпись (проверяется платформой).
   * @param issued отметка времени в манифесте, RFC 3339.
   * @param lastSeenIssued самая свежая отметка, которую этот телефон уже видел.
   */
  fun decide(
    hasPinnedKey: Boolean,
    signaturePresent: Boolean,
    signatureValid: Boolean,
    issued: String?,
    lastSeenIssued: String?,
  ): Verdict {
    if (!hasPinnedKey) {
      // Сборка без вшитого ключа: проверять нечем. Это честнее, чем делать вид.
      return Verdict.Allow
    }
    if (!signaturePresent) {
      return Verdict.Refuse("манифест обновления не подписан")
    }
    if (!signatureValid) {
      return Verdict.Refuse("подпись манифеста не сошлась")
    }
    if (issued.isNullOrBlank()) {
      return Verdict.Refuse("в манифесте нет отметки времени")
    }
    if (lastSeenIssued != null && issued < lastSeenIssued) {
      // Откат метаданных: узел показывает манифест старее уже виденного. Так
      // выглядит попытка удержать телефон на прежней версии.
      return Verdict.Refuse("манифест старее уже полученного")
    }
    return Verdict.Allow
  }

  /**
   * Давно ли приходили обновления.
   *
   * Захваченный узел не может подсунуть своё, но может молчать. Молчание — тоже
   * событие, и человек должен о нём узнать, а не считать, что новостей нет.
   */
  fun isStale(lastSuccessEpochDays: Long?, todayEpochDays: Long, limitDays: Long = 30): Boolean {
    if (lastSuccessEpochDays == null) return false
    return todayEpochDays - lastSuccessEpochDays >= limitDays
  }
}
