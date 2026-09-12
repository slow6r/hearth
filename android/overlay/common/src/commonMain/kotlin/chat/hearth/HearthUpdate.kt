package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Обновление приложения со СВОЕГО узла.
 *
 * # Почему это не противоречит patches/0010-no-updates.md
 *
 * 0010 выключает проверку обновлений upstream, и причина там названа точно:
 * «проверка обновлений — исходящее соединение К ТРЕТЬЕЙ СТОРОНЕ, то есть ровно то,
 * чего в контуре быть не должно, плюс она раскрывает факт использования сборки».
 *
 * Узел семьи третьей стороной не является. Телефон и так держит с ним постоянное
 * соединение — это режим доставки сообщений. Поэтому запрос обновления не добавляет
 * наблюдателю ни одного нового факта: он и так видит, что устройство говорит с узлом.
 *
 * Что этот модуль всё-таки стоит, и это надо знать:
 *
 *  - приложению нужно разрешение `REQUEST_INSTALL_PACKAGES` — право ставить
 *    произвольные APK. patches/0005 разрешения наоборот вычищает, так что это размен,
 *    а не мелочь;
 *  - на узле появляется публично доступный HTTP-эндпоинт, которого раньше не было
 *    (ADR 0007 сводил публичную поверхность к релеям и TURN).
 *
 * Взамен выполняется требование ТЗ §1.4: security-релиз должен попасть в контур за
 * ≤ 7 дней. Раздача «приходите домой и обновляйтесь по LAN» этого не даёт тому, кто
 * уехал, а именно он и остаётся с дырой.
 *
 * # Чего Android не позволит
 *
 * Установить APK без нажатия человека нельзя — системный диалог обязателен для всех,
 * кроме device-owner и системных приложений. Скачивание идёт в фоне и переживает
 * сворачивание; установка всегда требует одного касания.
 */
@Serializable
data class HearthUpdateManifest(
  /** Версия формата самого манифеста, а не приложения. */
  val v: Int,
  val versionName: String,
  val versionCode: Int,
  /** sha256 файла APK в нижнем регистре hex. */
  val sha256: String,
  /** Путь к APK относительно того же эндпоинта. Абсолютные URL запрещены — см. validate. */
  val file: String,
  val notes: String = "",
  /**
   * Когда манифест выпущен, RFC 3339.
   *
   * Нужна не для красоты: по ней ловится откат метаданных — узел, показывающий
   * манифест старее уже виденного, пытается удержать телефон на прежней версии.
   */
  val issued: String = "",
) {
  companion object {
    const val SUPPORTED_VERSION = 1

    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    fun parse(payload: String): Result<HearthUpdateManifest> = runCatching {
      val manifest = json.decodeFromString(serializer(), payload)
      manifest.validate().getOrThrow()
      manifest
    }
  }

  fun validate(): Result<Unit> = runCatching {
    require(v == SUPPORTED_VERSION) { "неизвестная версия манифеста обновления: $v" }
    require(versionCode > 0) { "versionCode должен быть положительным" }
    require(versionName.isNotBlank()) { "пустой versionName" }
    require(SHA256.matches(sha256)) { "sha256 должен быть 64 hex-символами" }

    // Имя файла, а не URL. Манифест приходит с узла, но подставлять из него
    // произвольный адрес нельзя: подменённый манифест увёл бы загрузку на чужой
    // сервер. Адрес узла клиент знает сам — из bundle, а не из этого документа.
    require(file.isNotBlank()) { "пустое имя файла" }
    require(!file.contains("://")) { "в манифесте должно быть имя файла, а не URL" }
    require(!file.contains("..") && !file.startsWith("/")) { "недопустимое имя файла: $file" }
    require(file.endsWith(".apk")) { "ожидается .apk" }
  }

  /**
   * Новее ли это того, что установлено.
   *
   * Сравнение по `versionCode`, а не по строке версии: строку человек пишет руками, а
   * versionCode монотонен по требованию Android. Строго больше — равное не предлагаем.
   */
  fun isNewerThan(installedVersionCode: Int): Boolean = versionCode > installedVersionCode
}

private val SHA256 = Regex("^[0-9a-f]{64}$")

/** Чем закончилась проверка обновления. */
sealed interface HearthUpdateCheck {
  data object UpToDate : HearthUpdateCheck
  data class Available(val manifest: HearthUpdateManifest) : HearthUpdateCheck
  data class Failed(val reason: String) : HearthUpdateCheck
}

/** Чем закончилась загрузка. */
sealed interface HearthDownloadResult {
  /** Файл скачан и его sha256 совпал с манифестом. Ставить — отдельное действие человека. */
  data class Ready(val path: String) : HearthDownloadResult
  data class Failed(val reason: String) : HearthDownloadResult
}

/**
 * Транспорт до узла. Реализация платформенная: на Android это HttpURLConnection,
 * никаких новых зависимостей (ТЗ §8.3 запрещает добавлять SDK).
 */
interface HearthUpdateTransport {
  /** GET манифеста. Токен устройства уходит заголовком, не в URL: URL попадает в логи. */
  suspend fun fetchManifest(): Result<String>

  /**
   * GET подписи манифеста (`manifest.json.sig`, base64 DER).
   *
   * `null` — подписи на узле нет. Для сборки со вшитым ключом это отказ, а не
   * повод продолжить: иначе достаточно удалить файл, чтобы выключить проверку.
   */
  suspend fun fetchManifestSignature(): Result<String?>

  /**
   * Скачать файл, сообщая прогресс. Реализация обязана быть докачиваемой и жить в
   * foreground-сервисе: пользователь свернёт приложение, и загрузка не должна умирать.
   */
  suspend fun download(file: String, expectedSha256: String, onProgress: (Long, Long) -> Unit): HearthDownloadResult

  /**
   * Попросить узел завести НОВОЕ устройство и вернуть для него bundle.
   *
   * Это и есть самостоятельное заведение телефонов. Оно не раздаёт чужой секрет:
   * узел заводит отдельную запись со СВОИМ токеном, поэтому потерянный телефон
   * отзывается поштучно. Секретность от этого не меняется — пароль релея и так лежит
   * на каждом настроенном устройстве, внутри адреса `smp://`. Меняется учёт.
   */
  suspend fun enroll(name: String): Result<String>
}

/**
 * Проверка обновления. Чистая оркестрация, без платформенных типов — тестируется на JVM.
 */
class HearthUpdateChecker(
  private val transport: HearthUpdateTransport,
  private val installedVersionCode: Int,
  /** Открытый ключ подписи манифестов из сборки; `null` — сборка без него. */
  private val pinnedKey: String? = null,
  /** Проверка подписи. Платформенная: на Android — штатный SHA256withECDSA. */
  private val verify: (ByteArray, String, String) -> Boolean = { _, _, _ -> false },
  /** Самая свежая отметка времени, которую этот телефон уже видел. */
  private val lastSeenIssued: String? = null,
  /** Куда запомнить отметку принятого манифеста. */
  private val rememberIssued: (String) -> Unit = {},
) {
  suspend fun check(): HearthUpdateCheck {
    val payload = transport.fetchManifest().getOrElse { e ->
      return HearthUpdateCheck.Failed(e.message ?: "узел недоступен")
    }
    // Подпись запрашивается всегда, когда в сборке есть ключ: её отсутствие — такой
    // же отказ, как несовпадение.
    val signature = if (pinnedKey != null) {
      transport.fetchManifestSignature().getOrElse { e ->
        return HearthUpdateCheck.Failed(e.message ?: "подпись манифеста не получена")
      }
    } else {
      null
    }

    val manifest = HearthUpdateManifest.parse(payload).getOrElse { e ->
      return HearthUpdateCheck.Failed(e.message ?: "манифест не разобран")
    }

    val verdict = HearthUpdateTrust.decide(
      hasPinnedKey = pinnedKey != null,
      signaturePresent = signature != null,
      signatureValid = signature != null && pinnedKey != null &&
        verify(payload.encodeToByteArray(), signature, pinnedKey),
      issued = manifest.issued.ifBlank { null },
      lastSeenIssued = lastSeenIssued,
    )
    if (verdict is HearthUpdateTrust.Verdict.Refuse) {
      return HearthUpdateCheck.Failed(verdict.reason)
    }
    if (manifest.issued.isNotBlank()) rememberIssued(manifest.issued)

    return if (manifest.isNewerThan(installedVersionCode)) {
      HearthUpdateCheck.Available(manifest)
    } else {
      HearthUpdateCheck.UpToDate
    }
  }
}
