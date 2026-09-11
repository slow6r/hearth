package chat.hearth

/**
 * Код доступа — то, что человек получает лично и вводит руками (ADR 0012).
 *
 * Зеркало серверного `hearthd/src/model/code.rs`. Раскладка одна и та же, и это
 * важнее, чем кажется: если клиент и узел разойдутся в том, что считать «тем же
 * кодом», человек с правильной бумажкой получит отказ и позвонит не туда.
 *
 * Алфавит Крокфорда: 32 знака, без `I`, `L`, `O`, `U`. Ни одного, который путают на
 * слух и на бумаге; `U` выкинут ещё и затем, чтобы код не сложился в непристойность.
 *
 * Ввод прощает человека — регистр любой, дефисы и пробелы не важны, а `O`, `I` и `L`
 * читаются как `0` и `1`. Это делается здесь, а не только на узле: подсказать
 * «проверьте код» до отправки дешевле, чем сходить в сеть и вернуться с отказом.
 */
object HearthAccessCode {
  private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

  /** Знаков в коде. 12 × 5 бит = 60 бит. */
  const val LENGTH = 12

  private const val GROUP = 4

  /** Привести введённое к тому виду, в каком код хранится на узле. */
  fun normalize(input: String): String = buildString {
    for (raw in input) {
      val c = raw.uppercaseChar()
      when {
        // Человек видит «ноль» и печатает «О», видит «единицу» и печатает «I».
        c == 'O' -> append('0')
        c == 'I' || c == 'L' -> append('1')
        ALPHABET.contains(c) -> append(c)
        // Всё прочее — дефисы, пробелы, перевод строки из буфера обмена — выкидываем.
      }
    }
  }

  /** Похоже ли это на полный код: правильная длина и только знаки алфавита. */
  fun isValid(canonical: String): Boolean =
    canonical.length == LENGTH && canonical.all { ALPHABET.contains(it) }

  /** Разбить на группы для показа: `H7K4-P9QX-M3TV`. */
  fun formatGroups(canonical: String): String =
    canonical.chunked(GROUP).joinToString("-")

  /**
   * Показать ровно то, что человек набрал, но группами — чтобы сверять с бумажкой.
   *
   * Обрезаем по длине кода: лишние знаки не молчат, а просто не появляются в поле,
   * и человек видит это сразу.
   */
  fun formatAsTyped(input: String): String = formatGroups(normalize(input).take(LENGTH))
}
