package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Адрес узла, вшитый в сборку (ADR 0011, ADR 0012).
 *
 * # Что здесь лежит и чего здесь нет
 *
 * Только адрес узла. Ни паролей релеев, ни токена приглашения — ничего, что стоило бы
 * прятать: адрес видно в любом соединении с релеем.
 *
 * Так было не всегда. Сначала в сборку клали токен приглашения, и первый запуск шёл
 * сам — человек ставил APK и сразу пользовался, как в SimpleX. Платой был файл,
 * который сам по себе впускал в контур: кто его достал, тот и завёлся.
 *
 * Теперь входной секрет приносит человек — код доступа, выданный лично. Это меняет
 * свойства раздачи целиком:
 *
 *  * APK можно передавать как угодно: без кода он ничего не открывает;
 *  * отзывают не сборку, а код, и поимённо: `hearthctl invite revoke <id>`;
 *  * видно, кто чем воспользовался: у каждого кода свой id и своё устройство.
 *
 * Цена — один экран при первом запуске. Это ровно тот шаг, которого нет в SimpleX, и
 * он существует по той же причине, что и раньше: серверы у нас свои, и телефон надо
 * на них навести.
 */
@Serializable
data class HearthBakedNode(
  /** Хост узла — тот же, что в адресе релея. */
  val host: String,
  /** Порт device API. */
  val port: Int = DEFAULT_PORT,
) {
  companion object {
    const val DEFAULT_PORT = 7444

    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    private val HOST = Regex("^[A-Za-z0-9.-]{1,253}$")

    fun parse(payload: String): Result<HearthBakedNode> = runCatching {
      val node = json.decodeFromString(serializer(), payload)
      node.validate().getOrThrow()
      node
    }
  }

  fun validate(): Result<Unit> = runCatching {
    // Хост, а не URL: подставлять из файла произвольный адрес нельзя даже когда файл
    // свой — однажды он окажется не своим.
    require(HOST.matches(host)) { "недопустимый адрес узла" }
    require(port in 1..65535) { "недопустимый порт: $port" }
  }
}

/** Чем закончилась попытка завестись по коду доступа. */
sealed interface HearthClaimResult {
  /** Узел завёл устройство и отдал bundle. Дальше — обычный онбординг upstream. */
  data class Applied(val device: String) : HearthClaimResult
  /** Адреса узла в сборке нет — это сборка «по QR», а не ошибка. */
  data object NoNode : HearthClaimResult
  /** Узел не ответил или отказал. Причину показываем человеку дословно. */
  data class Failed(val reason: String) : HearthClaimResult
}

/**
 * Транспорт до узла для заведения по коду.
 *
 * Отдельный от [HearthUpdateTransport] намеренно: тот предъявляет токен УЖЕ
 * заведённого устройства, а здесь устройства ещё нет — предъявляется код доступа.
 */
interface HearthClaimTransport {
  /** `POST /claim` с кодом в заголовке. Возвращает JSON bundle'а, как его отдаёт узел. */
  suspend fun claim(node: HearthBakedNode, code: String, deviceName: String): Result<String>
}

/**
 * Первый запуск: завести себя по коду и применить bundle.
 *
 * Чистая оркестрация без платформенных типов — тестируется на JVM.
 */
class HearthCodeEnroller(
  private val transport: HearthClaimTransport,
  /**
   * Что делать с полученным bundle. По умолчанию — проверить и отложить до появления
   * профиля ([hearthAcceptBundle]): применить его прямо здесь нельзя, ядру нужен
   * пользователь, а его на этом экране ещё нет.
   */
  private val accept: suspend (String) -> HearthImportResult = ::hearthAcceptBundle,
) {
  suspend fun enrol(node: HearthBakedNode?, code: String, deviceName: String): HearthClaimResult {
    if (node == null) return HearthClaimResult.NoNode

    val canonical = HearthAccessCode.normalize(code)
    // Неполный код заворачиваем здесь: сходить в сеть и вернуться с «неизвестный код»
    // — это те же слова, но через три секунды и с потраченной попыткой у узла.
    if (!HearthAccessCode.isValid(canonical)) {
      return HearthClaimResult.Failed(HearthOnboardingText.CODE_INCOMPLETE)
    }

    val payload = transport.claim(node, canonical, deviceName).getOrElse { e ->
      return HearthClaimResult.Failed(e.message ?: "узел недоступен")
    }
    // Bundle с узла проходит ровно ту же проверку, что и отсканированный. Источник
    // доверенный, но проверка стоит один вызов, а ловит подменённый ответ и
    // рассинхрон версий формата.
    return when (val result = accept(payload)) {
      is HearthImportResult.Applied -> HearthClaimResult.Applied(result.device)
      is HearthImportResult.Rejected -> HearthClaimResult.Failed(result.reason)
    }
  }
}

/** Адрес узла из сборки, или `null` — если это сборка «по QR». */
expect fun hearthBakedNode(): HearthBakedNode?

/** Завести себя на вшитом узле по коду доступа, который ввёл человек. */
expect suspend fun hearthClaimWithCode(code: String): HearthClaimResult
