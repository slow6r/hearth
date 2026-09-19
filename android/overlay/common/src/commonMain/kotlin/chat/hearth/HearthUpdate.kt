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
  /**
   * До какого момента этому манифесту верить, RFC 3339. Пусто — поля нет.
   *
   * Назначает оператор в момент подписи на рабочей станции: ключ лежит там, и только
   * там известно, когда в следующий раз дойдут руки. Поле ВНУТРИ подписанного
   * документа, поэтому узел его не подделает и не продлит.
   *
   * Почему это лучше запаса по возрасту: запас — это требование к узлу, которое узел
   * выполнить не может (переподписать манифест он не умеет). Срок — это обещание
   * оператора, которое он даёт, зная свои обстоятельства. Клиент, живущий по обещанию,
   * не отрезает семью от обновлений на ровном месте.
   */
  val expires: String = "",
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

/**
 * Чем закончилась проверка обновления.
 *
 * У успешных исходов есть `notice` — то, что надо сказать человеку, хотя проверка и
 * прошла. Сегодня там бывает ровно одно: «узел давно не публиковал нового». Раньше
 * этот случай был отказом, то есть звучал как «обновлений вам больше не будет», хотя
 * на деле означал «сходите спросите».
 */
sealed interface HearthUpdateCheck {
  data class UpToDate(val notice: String? = null) : HearthUpdateCheck
  data class Available(
    val manifest: HearthUpdateManifest,
    val notice: String? = null,
  ) : HearthUpdateCheck

  /**
   * Проверка не прошла.
   *
   * @param actionable узел ОТВЕТИЛ, и ответ не приняли: нет ключа в сборке, подпись не
   *   сошлась, вышел срок, манифест не разобран. Такой отказ сам не пройдёт — ни через
   *   час, ни через месяц, — и человеку надо что-то сделать. Поэтому он обязан дойти до
   *   экрана «Узел», а не остаться в логе, где его не увидит никто.
   *
   *   `false` — до узла просто не дошли (нет сети, узел не отвечает). Это не новость:
   *   одна неудача — обычное дело, а новостью становится МОЛЧАНИЕ, и о нём говорит
   *   отдельное правило ([HearthUpdateTrust.isStale]).
   */
  data class Failed(val reason: String, val actionable: Boolean = false) : HearthUpdateCheck
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
  /**
   * Объявлено ли ресурсом сборки, что она сознательно собрана БЕЗ ключа.
   *
   * По умолчанию `false`: отсутствие ключа — отказ. Разрешение жить без проверки
   * подписи должно быть дописано в сборку явно, а не получиться само из того, что
   * ресурс с ключом кто-то вырезал.
   */
  private val unsignedUpdatesAllowed: Boolean = false,
  /**
   * Сегодня по часам телефона, в днях эпохи.
   *
   * Параметром, а не обращением к часам внутри: правила свежести тем и хороши, что
   * гоняются таблицей на JVM, а часы в таблицу не подставишь.
   */
  private val nowEpochDays: Long = hearthNowEpochDays(),
  /** День, когда телефон впервые увидел [lastSeenIssued]. */
  private val firstSeenEpochDays: Long? = null,
  /** Куда запомнить день первого появления НОВОЙ отметки. */
  private val rememberFirstSeenDay: (Long) -> Unit = {},
  /** Куда запомнить день удавшейся проверки: по нему видно молчание узла. */
  private val rememberCheckedDay: (Long) -> Unit = {},
) {
  suspend fun check(): HearthUpdateCheck {
    val payload = transport.fetchManifest().getOrElse { e ->
      return HearthUpdateCheck.Failed(e.message ?: "узел недоступен")
    }
    // Подпись запрашивается ВСЕГДА, а не только когда в сборке есть ключ. Раньше при
    // `pinnedKey == null` запроса не было вовсе: решение принималось до того, как
    // появлялись факты, и «сборка по QR» была неотличима от вырезанного ресурса.
    val signature = transport.fetchManifestSignature().getOrElse { e ->
      return HearthUpdateCheck.Failed(e.message ?: "подпись манифеста не получена")
    }

    val manifest = HearthUpdateManifest.parse(payload).getOrElse { e ->
      // Узел ответил, но ответ не разбирается: это не сетевая осечка, сама она не
      // пройдёт, и человек должен об этом узнать.
      return HearthUpdateCheck.Failed(e.message ?: "манифест не разобран", actionable = true)
    }

    val verdict = HearthUpdateTrust.decide(
      hasPinnedKey = pinnedKey != null,
      signaturePresent = signature != null,
      signatureValid = signature != null && pinnedKey != null &&
        verify(payload.encodeToByteArray(), signature, pinnedKey),
      issued = manifest.issued.ifBlank { null },
      lastSeenIssued = lastSeenIssued,
      nowEpochDays = nowEpochDays,
      firstSeenEpochDays = firstSeenEpochDays,
      unsignedUpdatesAllowed = unsignedUpdatesAllowed,
      // Срок годности берём из САМОГО манифеста: он внутри подписанного документа, а
      // значит меняется только вместе с подписью. Пусто — поля нет, и тогда свежесть
      // судит запас по возрасту (см. HearthUpdateTrust).
      expires = manifest.expires.ifBlank { null },
    )
    if (verdict is HearthUpdateTrust.Verdict.Refuse) {
      // Отказ политики: узел на связи, а обновления не ставятся. Текст вердикта уже
      // написан для человека и говорит, что делать, — его и показываем.
      return HearthUpdateCheck.Failed(verdict.reason, actionable = true)
    }
    val notice = (verdict as? HearthUpdateTrust.Verdict.Allow)?.notice
    if (manifest.issued.isNotBlank() && manifest.issued != lastSeenIssued) {
      // День первого появления пишется только вместе с НОВОЙ отметкой. Обновляй его
      // на каждой проверке — и правило «узел две недели отдаёт одно и то же» никогда
      // бы не сработало: срок отодвигался бы сам собой.
      rememberIssued(manifest.issued)
      rememberFirstSeenDay(nowEpochDays)
    }
    // Узел ответил и ответ приняли. Пишем день и при UpToDate: «новостей нет» — это
    // тоже ответ, а молчание — нет, и отличать их надо именно здесь.
    rememberCheckedDay(nowEpochDays)

    return if (manifest.isNewerThan(installedVersionCode)) {
      HearthUpdateCheck.Available(manifest, notice)
    } else {
      HearthUpdateCheck.UpToDate(notice)
    }
  }
}
