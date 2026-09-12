package chat.hearth

/**
 * Правила допуска обновления к установке.
 *
 * # Зачем отдельно от платформы
 *
 * Факты о файле добывает Android (`PackageManager`), а решение принимается здесь —
 * чистой функцией, которую можно прогнать на JVM по таблице случаев. Иначе
 * единственным способом проверить «а что будет, если узел подсунет чужой пакет»
 * была бы ручная установка чужого пакета на живой телефон.
 *
 * # Что защищает
 *
 * Захват узла раздачи не должен позволять выдать клиенту произвольное обновление.
 * Android и сам отвергнет пакет, подписанный не тем ключом, — но отвергнет он его
 * ПОСЛЕ того, как человек увидит системный диалог установки и нажмёт «Установить».
 * Человек, которому приложение само предложило обновиться, нажмёт. Поэтому решение
 * принимается до диалога, и до него же отбрасываются случаи, которые Android
 * пропустил бы молча: другой пакет с тем же именем, версия не та, что обещал узел,
 * откат на старую версию с известной дырой.
 */
object HearthApkRules {

  /** Чем закончился осмотр скачанного файла. */
  sealed interface Verdict {
    /** Можно предлагать установку. */
    data object Allow : Verdict

    /** Нельзя. Причина показывается человеку и пишется в журнал. */
    data class Refuse(val reason: String) : Verdict
  }

  /** Факты о файле и об установленном приложении — всё, что нужно для решения. */
  data class Facts(
    /** Имя пакета внутри скачанного файла; `null`, если файл не разобрался. */
    val packageName: String?,
    /** Имя пакета установленного приложения. */
    val ownPackageName: String,
    /** versionCode внутри файла. */
    val versionCode: Long,
    /** versionCode установленного приложения. */
    val installedVersionCode: Long,
    /** versionCode, который обещал узел в манифесте. 0 — узел не назвал. */
    val expectedVersionCode: Long,
    /** sha256 сертификатов подписи файла (в нижнем регистре). */
    val signatures: Set<String>,
    /** sha256 сертификатов подписи установленного приложения. */
    val installedSignatures: Set<String>,
  )

  fun decide(facts: Facts): Verdict {
    if (facts.packageName == null) {
      return Verdict.Refuse("файл не разбирается как приложение Android")
    }
    if (facts.packageName != facts.ownPackageName) {
      return Verdict.Refuse("это другое приложение: ${facts.packageName}")
    }
    if (facts.signatures.isEmpty()) {
      return Verdict.Refuse("у файла нет подписи")
    }
    if (facts.installedSignatures.isEmpty()) {
      // Своей подписи не видно — сравнивать не с чем. Это не повод разрешать.
      return Verdict.Refuse("не удалось прочитать подпись установленного приложения")
    }
    if (facts.signatures != facts.installedSignatures) {
      return Verdict.Refuse("обновление подписано другим ключом")
    }
    if (facts.versionCode <= facts.installedVersionCode) {
      // Откат на старую версию — способ вернуть уже закрытую дыру. Узел, который
      // предлагает такое, либо сломан, либо захвачен.
      return Verdict.Refuse(
        "версия не новее установленной (${facts.versionCode} ≤ ${facts.installedVersionCode})"
      )
    }
    if (facts.expectedVersionCode > 0 && facts.versionCode != facts.expectedVersionCode) {
      // Файл не тот, что описан в манифесте: хеш сошёлся, а содержимое другое —
      // значит манифест и файл разошлись, и доверять ни тому, ни другому нельзя.
      return Verdict.Refuse(
        "версия не та, что обещал узел (${facts.versionCode} вместо ${facts.expectedVersionCode})"
      )
    }
    return Verdict.Allow
  }
}
