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

    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    /** Parse and validate a scanned QR payload. */
    fun parse(payload: String): Result<HearthBundle> = runCatching {
      val bundle = json.decodeFromString(serializer(), payload)
      bundle.validate().getOrThrow()
      bundle
    }
  }

  /**
   * Reject anything that would take this device outside the family contour.
   *
   * Each rule maps to a requirement, so an upstream rebase that quietly changes a
   * default is caught here rather than in production.
   */
  fun validate(): Result<Unit> = runCatching {
    require(v == SUPPORTED_VERSION) { "unsupported bundle version $v" }
    require(smp.isNotEmpty()) { "bundle has no SMP servers" }
    require(device.isNotBlank()) { "bundle has no device id" }

    val host = hostOf(smp.first()) ?: throw IllegalArgumentException("SMP address has no host")
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
  fun host(): String? = smp.firstOrNull()?.let { hostOf(it) }
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
 * `scheme:[user:credential@]host:port[?query]`.
 *
 * The strictness here is not pedantry. `parseRTCIceServers` returns null for the WHOLE
 * list if any single entry fails to parse, and the client then falls back to its
 * built-in **public** STUN/TURN. A malformed entry would therefore not break calls
 * loudly — it would quietly route them through a third party.
 */
private fun requireIceEntry(entry: String, expectedHost: String) {
  val scheme = entry.substringBefore(':', "")
  require(scheme in setOf("stun", "stuns", "turn", "turns")) {
    "unsupported ICE scheme: $entry"
  }
  val rest = entry.substringAfter(':').substringBefore('?')
  val hostPort = if (rest.contains('@')) rest.substringAfterLast('@') else rest
  val host = hostPort.substringBeforeLast(':', "")
  require(host.isNotEmpty()) { "ICE entry has no host: $entry" }
  require(host.equals(expectedHost, ignoreCase = true)) {
    "ICE entry points at $host, not at $expectedHost — a public STUN/TURN would leak " +
      "the caller's address"
  }
  val port = hostPort.substringAfterLast(':', "").toIntOrNull()
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

private fun hostOf(uri: String): String? {
  val auth = uri.substringAfter("://", "")
  if (auth.isEmpty()) return null
  val hostPort = auth.substringAfterLast('@', auth)
  return hostPort.substringBeforeLast(':', "").ifEmpty { null }
}
