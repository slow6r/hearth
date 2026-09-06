package chat.hearth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Client bundle — ТЗ Приложение B.
 *
 * The QR a family member scans during onboarding contains exactly this document,
 * produced by `hearthd` (`GET /devices/{id}/bundle.png`). Parsing it is the ONLY new
 * data format this fork introduces; everything else — `smp://` addresses, the handshake,
 * the message formats — belongs to upstream and is untouched (ТЗ §8.3).
 *
 * The validation here deliberately mirrors `hearthd`'s `Bundle::validate`. The node
 * already checked all of this; checking it again on the device means a tampered or
 * stale QR cannot silently point a phone at a foreign relay.
 */
@Serializable
data class HearthBundle(
  val v: Int,
  val smp: List<String>,
  val xftp: List<String> = emptyList(),
  val ice: List<HearthIceServer> = emptyList(),
  val net: HearthNetPrefs,
  val issued: String,
  val device: String,
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
   * Every rule maps to a ТЗ requirement, so a future upstream rebase that quietly
   * changes a default is caught here rather than in production.
   */
  fun validate(): Result<Unit> = runCatching {
    require(v == SUPPORTED_VERSION) { "unsupported bundle version $v" }
    require(smp.isNotEmpty()) { "bundle has no SMP servers" }
    require(device.isNotBlank()) { "bundle has no device id" }

    smp.forEach { requireServerUri(it, "smp") }
    xftp.forEach { requireServerUri(it, "xftp") }

    // ТЗ §8.2 п.3 / §6.4: our coturn only. A public STUN would leak the real address.
    require(ice.isNotEmpty()) { "bundle has no ICE servers" }
    ice.flatMap { it.urls }.forEach { requireIceUrl(it) }

    // ТЗ §8.2 п.5, §1.2, §8.2 п.4.
    require(net.privateRouting == "always") { "privateRouting must be `always`" }
    require(!net.presetsEnabled) { "public operator presets must stay disabled" }
    require(net.ntfMode == "instant") { "notification mode must be `instant`" }
  }

  /** Host part of every server address, for display during onboarding. */
  fun hosts(): List<String> = (smp + xftp).mapNotNull { hostOf(it) }.distinct()
}

@Serializable
data class HearthIceServer(
  val urls: List<String>,
  val username: String? = null,
  val credential: String? = null,
)

@Serializable
data class HearthNetPrefs(
  @SerialName("privateRouting") val privateRouting: String,
  @SerialName("presetsEnabled") val presetsEnabled: Boolean,
  @SerialName("ntfMode") val ntfMode: String,
)

/**
 * `smp://<fingerprint>:<password>@<ip>:<port>`.
 *
 * The host MUST be an IP literal: the contour has no DNS (ТЗ §5.2), so a name here
 * would mean either a misconfiguration or an attempt to redirect the client.
 */
private fun requireServerUri(uri: String, scheme: String) {
  require(uri.startsWith("$scheme://")) { "expected a $scheme:// address, got $uri" }
  val auth = uri.removePrefix("$scheme://")
  val at = auth.lastIndexOf('@')
  require(at > 0) { "$scheme address has no fingerprint: $uri" }
  val credentials = auth.substring(0, at)
  require(credentials.contains(':')) {
    // ТЗ §6.2: creating a queue requires a password; an address without one would
    // silently fail at the relay.
    "$scheme address carries no relay password: $uri"
  }
  val hostPort = auth.substring(at + 1)
  val host = hostPort.substringBeforeLast(':', "")
  require(host.isNotEmpty() && isIpLiteral(host)) {
    "$scheme host must be an IP literal (the contour has no DNS): $uri"
  }
  val port = hostPort.substringAfterLast(':', "").toIntOrNull()
  require(port != null && port in 1..65535) { "bad port in $uri" }
}

private fun requireIceUrl(url: String) {
  val rest = when {
    url.startsWith("stun:") -> url.removePrefix("stun:")
    url.startsWith("turn:") -> url.removePrefix("turn:")
    url.startsWith("turns:") -> url.removePrefix("turns:")
    else -> throw IllegalArgumentException("unsupported ICE url: $url")
  }
  val host = rest.substringBefore('?').substringBeforeLast(':', rest.substringBefore('?'))
  require(isIpLiteral(host)) { "ICE url must point at the home node by IP: $url" }
}

private fun hostOf(uri: String): String? {
  val auth = uri.substringAfter("://", "")
  if (auth.isEmpty()) return null
  val hostPort = auth.substringAfterLast('@', auth)
  return hostPort.substringBeforeLast(':', "").ifEmpty { null }
}

/** IPv4 literal check. IPv6 is not used inside the contour (ТЗ §5.1). */
internal fun isIpLiteral(host: String): Boolean {
  val parts = host.split('.')
  if (parts.size != 4) return false
  return parts.all { part ->
    part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
      (part.toIntOrNull() ?: -1) in 0..255
  }
}
