package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Приглашение, вшитое в сборку (ADR 0011).
 *
 * # Зачем
 *
 * Это единственное место, где мы отличались от SimpleX. Там серверы публичные и вшиты
 * в приложение, поэтому человек ставит его и сразу пользуется. У нас серверы свои, и
 * без приглашения каждый телефон требовал бы QR — то есть кого-то рядом.
 *
 * С приглашением первый запуск идёт сам: приложение просит у узла bundle, получает
 * СВОЮ запись в реестре и свой токен, экран сканера не показывается вовсе.
 *
 * # Чего здесь НЕТ
 *
 * Паролей релеев. В сборке лежит только адрес узла и одноразовый токен, ограниченный
 * сроком и числом использований. Поэтому исчерпанная сборка — обычный файл, из
 * которого нечего достать, тогда как вшитый bundle был бы вечным ключом.
 *
 * Пока приглашение живо, файл APK впускает в контур — это размен, названный в ADR
 * 0010, и его ограничивают срок, счётчик и отзыв на узле.
 */
@Serializable
data class HearthBakedInvite(
  /** Хост узла — тот же, что в адресе релея. */
  val host: String,
  val port: Int = DEFAULT_PORT,
  /** Токен приглашения, 64 hex-символа. */
  val token: String,
) {
  companion object {
    const val DEFAULT_PORT = 7444

    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    private val TOKEN = Regex("^[0-9a-f]{64}$")
    private val HOST = Regex("^[A-Za-z0-9.-]{1,253}$")

    fun parse(payload: String): Result<HearthBakedInvite> = runCatching {
      val invite = json.decodeFromString(serializer(), payload)
      invite.validate().getOrThrow()
      invite
    }
  }

  fun validate(): Result<Unit> = runCatching {
    // Хост, а не URL: подставлять из файла произвольный адрес нельзя даже когда файл
    // свой — однажды он окажется не своим.
    require(HOST.matches(host)) { "недопустимый адрес узла" }
    require(port in 1..65535) { "недопустимый порт: $port" }
    require(TOKEN.matches(token)) { "токен приглашения должен быть 64 hex-символами" }
  }
}

/** Чем закончилась попытка завести себя по приглашению. */
sealed interface HearthClaimResult {
  /** Узел завёл устройство и отдал bundle. Дальше — обычный онбординг upstream. */
  data class Applied(val device: String) : HearthClaimResult
  /** Приглашения в сборке нет — это не ошибка, а обычная сборка «по QR». */
  data object NoInvite : HearthClaimResult
  /** Узел не ответил или отказал. Человеку показываем сканер и причину. */
  data class Failed(val reason: String) : HearthClaimResult
}

/**
 * Транспорт до узла для заведения по приглашению.
 *
 * Отдельный от [HearthUpdateTransport] намеренно: тот предъявляет токен УЖЕ
 * заведённого устройства, а здесь устройства ещё нет — предъявляется приглашение.
 */
interface HearthClaimTransport {
  /** `POST /claim`. Возвращает JSON bundle'а, как его отдаёт узел. */
  suspend fun claim(invite: HearthBakedInvite, deviceName: String): Result<String>
}

/**
 * Первый запуск: завести себя и применить bundle.
 *
 * Чистая оркестрация без платформенных типов — тестируется на JVM.
 */
class HearthSelfEnroller(
  private val transport: HearthClaimTransport,
  private val importer: HearthOnboardingImporter,
) {
  suspend fun setUp(invite: HearthBakedInvite?, deviceName: String): HearthClaimResult {
    if (invite == null) return HearthClaimResult.NoInvite

    val payload = transport.claim(invite, deviceName).getOrElse { e ->
      return HearthClaimResult.Failed(e.message ?: "узел недоступен")
    }
    // Bundle с узла проходит ровно ту же валидацию, что и отсканированный. Источник
    // доверенный, но проверка стоит один вызов, а ловит подменённый ответ и
    // рассинхрон версий формата.
    return when (val result = importer.import(payload)) {
      is HearthImportResult.Applied -> HearthClaimResult.Applied(result.device)
      is HearthImportResult.Rejected -> HearthClaimResult.Failed(result.reason)
    }
  }
}

/**
 * Попробовать завести себя по вшитому приглашению.
 *
 * Реализация платформенная: приглашение лежит в ресурсах Android-сборки, а на desktop
 * его нет и быть не может — там настройка идёт по QR, как и раньше.
 */
expect suspend fun hearthAutoSetUp(): HearthClaimResult
