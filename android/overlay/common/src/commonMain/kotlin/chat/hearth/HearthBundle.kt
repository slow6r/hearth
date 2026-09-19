package chat.hearth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Client bundle — the QR a family member scans during onboarding, produced by
 * `hearthd` (`GET /devices/{id}/bundle.png`).
 *
 * Parsing it is the only new data format this fork introduces. Both string formats
 * inside it are upstream's, verified against simplexmq / simplex-chat v7.0.1:
 *
 *  - relays: `smp://<fingerprint>:<password>@host:port`
 *  - ICE:    `scheme:[user:credential@]host:port[?query]`, the exact form
 *            `parseRTCIceServer` in `views/call/WebRTC.kt` accepts.
 *
 * The validation here mirrors `hearthd`'s. The node already checked all of it; checking
 * again on the device means a tampered or stale QR cannot quietly point a phone at a
 * foreign relay.
 */
@Serializable
data class HearthBundle(
  val v: Int,
  val smp: List<String>,
  val xftp: List<String> = emptyList(),
  /** ICE entries as strings, ready to hand to `parseRTCIceServers`. */
  val ice: List<String> = emptyList(),
  val net: HearthNetPrefs,
  val issued: String,
  val device: String,
  /**
   * Device API узла: откуда брать обновления и свежие TURN-креды.
   *
   * `null` — узел без device API. Такое устройство живёт как раньше, но его звонки
   * сломаются при следующей ротации TURN-секрета, и bundle придётся выдать заново.
   */
  val node: HearthNodeApi? = null,
) {
  companion object {
    const val SUPPORTED_VERSION = 1

    /**
     * Сколько живёт QR узла.
     *
     * У bundle была дата выпуска и не было срока годности: сфотографированный год
     * назад QR оставался рабочим, хотя в нём пароли релеев. Тридцать дней — столько,
     * чтобы выданный лично код успели применить даже в отпуске, и не столько, чтобы
     * старый снимок в галерее оставался ключом от контура.
     *
     * # Почему срок остался, а изменился только текст
     *
     * В HEAD этой строгости не было, и соблазн убрать её обратно понятен: код передают
     * из рук в руки и применяют не в тот же вечер. Но убрать — значит вернуть бессрочный
     * пропуск в контур, и цена ошибки тут не «придётся попросить новый код», а «чужой
     * человек со старой фотографией заходит на релеи семьи».
     *
     * Поэтому смягчили не срок, а отказ. Он и был настоящей бедой: [staleMessage]
     * раньше звучал как внутренняя ошибка, и человек, увидев его на первом же экране
     * нового телефона, решал, что приложение сломано. Теперь текст говорит ровно то,
     * что случилось, и что делать, — и прямо сообщает, что приложение исправно.
     */
    const val MAX_AGE_DAYS: Long = 30

    /**
     * Текст про устаревший код — на языке человека, а не разбора.
     *
     * @param issued отметка выпуска из QR. В текст идёт только дата: время и часовой
     *   пояс здесь ничего не объясняют, а строку делают похожей на аварийный дамп.
     */
    fun staleMessage(issued: String, maxAgeDays: Long = MAX_AGE_DAYS): String {
      val day = issued.substringBefore('T').ifBlank { issued }
      return "Этот код подключения выдан $day, а такие коды действуют $maxAgeDays дней. " +
        "С приложением всё в порядке — код просто устарел. Попросите владельца узла " +
        "показать новый QR-код или прислать новый код доступа. Если дата на телефоне " +
        "неверна, поправьте сначала её: код может быть ещё годным."
    }

    /** Допуск на неточные часы и часовые пояса: двое суток вперёд — не подделка. */
    const val FUTURE_TOLERANCE_SECONDS: Long = 2 * HEARTH_SECONDS_PER_DAY

    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    /**
     * Parse and validate a scanned QR payload.
     *
     * @param nowEpochSeconds текущий момент; `null` — возраст не проверять. Проверяет
     *   его тот, кто ПРИНИМАЕТ QR от человека ([hearthAcceptBundle]): именно там
     *   протухший QR должен быть отвергнут на месте. Разбор уже принятого и отложенного
     *   bundle возрастом не судит — иначе телефон, пролежавший в ящике, не смог бы
     *   применить то, что человек уже завёл.
     */
    fun parse(payload: String, nowEpochSeconds: Long? = null): Result<HearthBundle> = runCatching {
      val bundle = json.decodeFromString(serializer(), payload)
      bundle.validate(nowEpochSeconds).getOrThrow()
      bundle
    }
  }

  /**
   * Reject anything that would take this device outside the family contour.
   *
   * Each rule maps to a requirement, so an upstream rebase that quietly changes a
   * default is caught here rather than in production.
   */
  fun validate(
    nowEpochSeconds: Long? = null,
    maxAgeDays: Long = MAX_AGE_DAYS,
  ): Result<Unit> = runCatching {
    require(v == SUPPORTED_VERSION) { "unsupported bundle version $v" }
    require(smp.isNotEmpty()) { "bundle has no SMP servers" }
    require(device.isNotBlank()) { "bundle has no device id" }
    if (nowEpochSeconds != null) requireFresh(nowEpochSeconds, maxAgeDays)

    val host = hearthHostOf(smp.first()) ?: throw IllegalArgumentException("SMP address has no host")
    smp.forEach { requireServerUri(it, "smp", host) }
    xftp.forEach { requireServerUri(it, "xftp", host) }

    // Calls: our own STUN/TURN only. A public STUN would hand the caller's address to
    // a third party.
    require(ice.isNotEmpty()) { "bundle has no ICE servers" }
    ice.forEach { requireIceEntry(it, host) }

    require(net.privateRouting == "always") { "privateRouting must be `always`" }
    require(!net.presetsEnabled) { "public operator presets must stay disabled" }
    require(net.ntfMode == "instant") { "notification mode must be `instant`" }
  }

  /** The host every address in this bundle points at. */
  fun host(): String? = smp.firstOrNull()?.let { hearthHostOf(it) }

  /**
   * Не устарел ли QR.
   *
   * Отдельно про часы: доверенного времени на телефоне нет, и свежеустановленное
   * приложение вполне может стоять на телефоне с неверной датой. Поэтому каждый из
   * трёх отказов прямо называет дату телефона как возможную причину — иначе человек
   * будет бесконечно пересканировать заведомо годный QR.
   *
   * Тексты здесь — единственное, что человек увидит: выше по стеку сообщение уходит
   * прямо в [HearthImportResult.Rejected] и оттуда на экран. Поэтому они написаны
   * словами, а не как причина в логе.
   */
  private fun requireFresh(nowEpochSeconds: Long, maxAgeDays: Long) {
    val issuedAt = hearthEpochSecondsOf(issued)
    require(issuedAt != null) {
      "В этом коде не удалось прочитать дату выпуска ($issued). Попросите владельца " +
        "узла показать новый QR-код — этот, скорее всего, повреждён."
    }
    require(issuedAt - nowEpochSeconds <= FUTURE_TOLERANCE_SECONDS) {
      "Этот код выпущен позже сегодняшнего дня по часам телефона ($issued). Скорее " +
        "всего, на телефоне сбита дата — проверьте дату, время и часовой пояс и " +
        "отсканируйте код снова."
    }
    require(nowEpochSeconds - issuedAt <= maxAgeDays * HEARTH_SECONDS_PER_DAY) {
      staleMessage(issued, maxAgeDays)
    }
  }
}

/**
 * Адрес device API и токен ЭТОГО устройства.
 *
 * Хост берётся отсюда — из bundle, который человек отсканировал лично, — и больше
 * ниоткуда. В частности, не из документов, которые сам этот API потом отдаёт:
 * подменённый манифест обновления иначе увёл бы загрузку на чужой сервер.
 */
@Serializable
data class HearthNodeApi(
  val host: String,
  val port: Int,
  /** Секрет устройства. Уходит заголовком, не в URL: URL оседает в логах. */
  val token: String,
)

@Serializable
data class HearthNetPrefs(
  @SerialName("privateRouting") val privateRouting: String,
  @SerialName("presetsEnabled") val presetsEnabled: Boolean,
  @SerialName("ntfMode") val ntfMode: String,
)

/**
 * `smp://<fingerprint>:<password>@<host>:<port>`.
 *
 * Every address in one bundle must point at the same host: a bundle that mixes hosts
 * means either a mistake or an attempt to slip one foreign server into the set.
 */
private fun requireServerUri(uri: String, scheme: String, expectedHost: String) {
  require(uri.startsWith("$scheme://")) { "expected a $scheme:// address, got $uri" }
  val auth = uri.removePrefix("$scheme://")
  val at = auth.lastIndexOf('@')
  require(at > 0) { "$scheme address has no fingerprint: $uri" }
  val credentials = auth.substring(0, at)
  // Upstream requires a password to create queues; without one the relay is open.
  require(credentials.contains(':')) { "$scheme address carries no relay password: $uri" }

  val hostPort = auth.substring(at + 1)
  val host = hostPort.substringBeforeLast(':', "")
  require(host.isNotEmpty()) { "$scheme address has no host: $uri" }
  require(host.equals(expectedHost, ignoreCase = true)) {
    "$scheme address points at $host, not at $expectedHost"
  }
  val port = hostPort.substringAfterLast(':', "").toIntOrNull()
  require(port != null && port in 1..65535) { "bad port in $uri" }
}

/**
 * `scheme:[user:credential@]host[:port][?query]`.
 *
 * The strictness here is not pedantry. `parseRTCIceServers` returns null for the WHOLE
 * list if any single entry fails to parse, and the client then falls back to its
 * built-in **public** STUN/TURN. A malformed entry would therefore not break calls
 * loudly — it would quietly route them through a third party.
 *
 * # Почему порт необязателен
 *
 * Раньше он требовался явно, и запись вида `stun:relay.myhearth.ru` без порта
 * отвергалась — хотя `parseRTCIceServer` в upstream её принимает. Нынешний hearthd
 * таких строк не выдаёт, но старый или собранный руками bundle выдаёт, и такой bundle
 * переставал применяться ЦЕЛИКОМ: одна запись отравляла весь список, а значит и
 * звонки. Охранял этот отказ ровно ничего — хост сверяется отдельной строкой ниже, а
 * номер порта на то, чьему серверу достанется медиа, не влияет. Поэтому порт теперь
 * подставляется по умолчанию ([hearthDefaultIcePort]), а не требуется.
 *
 * Сама запись при этом приводится к виду с портом перед звонком
 * ([hearthNormalizeIceEntry]): upstream на строке без порта собирает `stun:host:-1`
 * (`URI.getPort()` возвращает -1), то есть формально разбирает, а фактически делает
 * сервер недостижимым — худший из возможных исходов, потому что он невидим.
 */
internal fun requireIceEntry(entry: String, expectedHost: String) {
  val scheme = entry.substringBefore(':', "")
  require(scheme in setOf("stun", "stuns", "turn", "turns")) {
    "unsupported ICE scheme: $entry"
  }
  val rest = entry.substringAfter(':').substringBefore('?')
  val hostPort = if (rest.contains('@')) rest.substringAfterLast('@') else rest
  val colon = hostPort.lastIndexOf(':')
  val host = if (colon < 0) hostPort else hostPort.substring(0, colon)
  require(host.isNotEmpty()) { "ICE entry has no host: $entry" }
  require(host.equals(expectedHost, ignoreCase = true)) {
    "ICE entry points at $host, not at $expectedHost — a public STUN/TURN would leak " +
      "the caller's address"
  }
  // Порта нет — берём умолчание схемы, а не отказываем: см. шапку.
  val port = if (colon < 0) hearthDefaultIcePort(scheme) else hostPort.substring(colon + 1).toIntOrNull()
  require(port != null && port in 1..65535) { "bad port in ICE entry: $entry" }

  if (scheme.startsWith("turn")) {
    val userInfo = if (rest.contains('@')) rest.substringBeforeLast('@') else ""
    require(userInfo.contains(':')) { "TURN entry without credentials: $entry" }
    // A '/' would start a URI path and make the client discard the entry — and with
    // it the whole list. hearthd guarantees this, so seeing one means the QR is not
    // the one hearthd minted.
    require(!userInfo.contains('/')) { "TURN credentials contain '/': $entry" }
  }
}

/**
 * Порт по умолчанию для схемы ICE.
 *
 * 3478 для открытых `stun`/`turn`, 5349 для `stuns`/`turns` — RFC 5389 и RFC 5928.
 * Те же числа стоят в coturn по умолчанию, то есть подставляется ровно то, куда и
 * сходил бы человек, написавший адрес без порта.
 */
internal fun hearthDefaultIcePort(scheme: String): Int =
  if (scheme == "stuns" || scheme == "turns") 5349 else 3478

/**
 * Привести запись ICE к виду, который upstream разбирает без потерь.
 *
 * Единственное, что здесь делается, — дописывается порт по умолчанию, если его нет.
 * Без этого `parseRTCIceServer` собирает адрес `stun:host:-1`: формально запись
 * разобралась, фактически сервер недостижим.
 *
 * Строка, которую не удалось разобрать, возвращается как есть: задача здесь — не
 * судить (это делает [requireIceEntry]), а не сломать то, что уже проверено.
 */
internal fun hearthNormalizeIceEntry(entry: String): String {
  val text = entry.trim()
  val scheme = text.substringBefore(':', "")
  if (scheme !in setOf("stun", "stuns", "turn", "turns")) return text
  val afterScheme = text.substringAfter(':')
  val query = afterScheme.substringAfter('?', "")
  val rest = afterScheme.substringBefore('?')
  val at = rest.lastIndexOf('@')
  val userInfo = if (at >= 0) rest.substring(0, at + 1) else ""
  val hostPort = if (at >= 0) rest.substring(at + 1) else rest
  if (hostPort.isEmpty() || hostPort.contains(':')) return text
  val suffix = if (query.isEmpty()) "" else "?$query"
  return "$scheme:$userInfo$hostPort:${hearthDefaultIcePort(scheme)}$suffix"
}

// Разбор хоста переехал в HearthOwnHost.kt: то же правило нужно и для ссылок-
// приглашений, а два разных разбора однажды разъезжаются — и разъехались.
