package chat.hearth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Заведение настольной сборки по коду доступа (ADR 0012).
 *
 * # Почему здесь свой транспорт, а не общий с Android
 *
 * Транспорт-то одинаковый — `HttpURLConnection` из JVM. Разное доверие.
 *
 * На Android сертификат узла принимается через Network Security Config: CA лежит в
 * ресурсах, и платформа подставляет его сама, поэтому в коде нет ни `SSLContext`, ни
 * своего `TrustManager`. На JVM такого механизма нет: узел подписан собственным CA
 * (`CN = hearth admin CA`), и обычное соединение упало бы на проверке цепочки.
 *
 * Поэтому здесь доверие собирается руками — и ТОЛЬКО к нашему CA. Системные корни
 * намеренно не добавляются: узел подписан своим CA, и принимать что-то ещё означало бы
 * принимать любой сертификат из сотни корней, которым мы не обязаны верить.
 *
 * Общего набора исходников для JVM в проекте нет (только androidMain и desktopMain),
 * поэтому разделить получилось бы лишь ценой нового source set в сборке upstream — а
 * это ровно та правка, из-за которой ребейзы перестают быть механическими.
 */
object HearthDesktopNodeSource {
  private const val NODE_RESOURCE = "/hearth_node.json"
  private const val CA_RESOURCE = "/hearth_ca.pem"
  private const val LIMIT_BYTES = 8 * 1024

  /** Адрес узла из сборки, или `null` — если это сборка «по QR». */
  fun baked(): HearthBakedNode? {
    val payload = readResource(NODE_RESOURCE) ?: return null
    return HearthBakedNode.parse(payload).getOrNull()
  }

  /** Как назвать эту машину в реестре устройств. */
  fun deviceName(): String {
    val user = System.getProperty("user.name").orEmpty().trim()
    val os = System.getProperty("os.name").orEmpty().trim().ifBlank { "ПК" }
    return (if (user.isBlank()) os else "$os · $user").take(48)
  }

  /**
   * Доверие ровно к одному CA — тому, что вшит в сборку.
   *
   * `null`, если CA в сборке нет: тогда заводиться по коду невозможно, и человеку
   * честнее сказать это словами, чем молча не доверять узлу.
   */
  fun sslContext(): SSLContext? {
    val pem = readResource(CA_RESOURCE) ?: return null
    return runCatching {
      val certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(pem.byteInputStream(Charsets.UTF_8))
      val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null)
        setCertificateEntry("hearth-ca", certificate)
      }
      val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(store) }
      SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
    }.getOrNull()
  }

  private fun readResource(name: String): String? =
    javaClass.getResourceAsStream(name)?.use { readBounded(it, LIMIT_BYTES) }

  private fun readBounded(input: InputStream, limit: Int): String {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(4 * 1024)
    while (out.size() < limit) {
      val n = input.read(buf)
      if (n < 0) break
      out.write(buf, 0, n)
    }
    return out.toString(Charsets.UTF_8.name())
  }
}

/** `POST /claim` с доверием только к вшитому CA. */
class HearthDesktopClaimTransport : HearthClaimTransport {

  override suspend fun claim(
    node: HearthBakedNode,
    code: String,
    deviceName: String,
  ): Result<String> = withContext(Dispatchers.IO) {
    runCatching {
      val ssl = HearthDesktopNodeSource.sslContext()
        ?: throw IllegalStateException("в сборке нет сертификата узла — нужна сборка от администратора")
      val url = URL("https://${node.host}:${node.port}/claim")
      val conn = (url.openConnection() as HttpsURLConnection).apply {
        sslSocketFactory = ssl.socketFactory
        requestMethod = "POST"
        doOutput = true
        // Код заголовком, а не в URL: URL оседает в логах прокси и в истории.
        setRequestProperty("X-Hearth-Invite-Token", code)
        setRequestProperty("Content-Type", "application/json")
        connectTimeout = 15_000
        readTimeout = 30_000
        instanceFollowRedirects = false
      }
      try {
        val body = kotlinx.serialization.json.Json.encodeToString(
          kotlinx.serialization.json.JsonObject.serializer(),
          kotlinx.serialization.json.JsonObject(
            mapOf("name" to kotlinx.serialization.json.JsonPrimitive(deviceName))
          ),
        )
        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        when (val responseCode = conn.responseCode) {
          200 -> conn.inputStream.use { readBounded(it) }
          401 -> throw IllegalStateException(HearthOnboardingText.CODE_REFUSED)
          429 -> throw IllegalStateException(HearthOnboardingText.CODE_THROTTLED)
          409 -> throw IllegalStateException("на узле кончились места для устройств")
          else -> throw IllegalStateException("узел ответил $responseCode")
        }
      } finally {
        conn.disconnect()
      }
    }
  }

  private fun readBounded(input: InputStream): String {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(8 * 1024)
    while (out.size() < BUNDLE_LIMIT_BYTES) {
      val n = input.read(buf)
      if (n < 0) break
      out.write(buf, 0, n)
    }
    if (out.size() >= BUNDLE_LIMIT_BYTES) throw IllegalStateException("ответ узла слишком длинный")
    return out.toString(Charsets.UTF_8.name())
  }

  private companion object {
    const val BUNDLE_LIMIT_BYTES = 64 * 1024
  }
}

actual fun hearthBakedNode(): HearthBakedNode? = HearthDesktopNodeSource.baked()

actual suspend fun hearthClaimWithCode(code: String): HearthClaimResult =
  HearthCodeEnroller(HearthDesktopClaimTransport())
    .enrol(hearthBakedNode(), code, HearthDesktopNodeSource.deviceName())
