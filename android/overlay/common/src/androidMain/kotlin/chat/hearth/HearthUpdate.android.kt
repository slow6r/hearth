package chat.hearth

import android.content.Context
import chat.simplex.common.model.ChatController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Транспорт обновлений поверх `HttpURLConnection`.
 *
 * Никакого HTTP-клиента в зависимостях: ТЗ §8.3 запрещает добавлять SDK, а
 * `HttpURLConnection` есть в самой платформе. Того, что он умеет, здесь достаточно.
 */
class HearthAndroidUpdateTransport(
  private val context: Context,
  /** Хост узла — тот же, что в адресе релея. Берётся из bundle, а не из манифеста. */
  private val nodeHost: String,
  private val port: Int = DEFAULT_PORT,
  /** Токен устройства из bundle. Без него эндпоинт не отдаёт ничего. */
  private val token: String,
) : HearthUpdateTransport {

  override suspend fun fetchManifest(): Result<String> = withContext(Dispatchers.IO) {
    runCatching {
      open("$BASE/manifest.json").use { conn ->
        val code = conn.responseCode
        if (code != 200) throw IllegalStateException("узел ответил $code")
        // Манифест — маленький документ. Ограничение стоит, чтобы подменённый или
        // сломанный эндпоинт не заставил телефон читать поток без конца.
        conn.inputStream.readBoundedText(MANIFEST_LIMIT_BYTES)
      }
    }
  }

  override suspend fun download(
    file: String,
    expectedSha256: String,
    onProgress: (Long, Long) -> Unit,
  ): HearthDownloadResult = withContext(Dispatchers.IO) {
    val target = File(context.cacheDir, "hearth-update.apk")
    runCatching {
      // Докачка: если файл уже частично лежит, просим остаток через Range. Обновление
      // весит сотни мегабайт, а телефон в дороге теряет сеть постоянно.
      val already = if (target.exists()) target.length() else 0L
      open("$BASE/$file").use { conn ->
        if (already > 0) conn.setRequestProperty("Range", "bytes=$already-")
        val code = conn.responseCode
        val resuming = code == 206
        if (code != 200 && code != 206) throw IllegalStateException("узел ответил $code")
        if (already > 0 && !resuming) target.delete()

        val total = conn.contentLengthLong.let { if (it > 0) it + (if (resuming) already else 0) else -1L }
        var done = if (resuming) already else 0L

        conn.inputStream.use { input ->
          java.io.FileOutputStream(target, resuming).use { out ->
            val buf = ByteArray(64 * 1024)
            while (true) {
              val n = input.read(buf)
              if (n < 0) break
              out.write(buf, 0, n)
              done += n
              onProgress(done, total)
            }
            out.fd.sync()
          }
        }
      }

      // Проверка целостности. Подмену APK по дороге поймал бы и сам Android при
      // установке — обновление обязано быть подписано тем же ключом, иначе установка
      // отклоняется. Но битую докачку он не поймает, а хеш поймает.
      val actual = target.sha256Hex()
      if (!actual.equals(expectedSha256, ignoreCase = true)) {
        target.delete()
        throw IllegalStateException("sha256 не совпал: ожидали $expectedSha256, получили $actual")
      }
      HearthDownloadResult.Ready(target.absolutePath) as HearthDownloadResult
    }.getOrElse { e ->
      HearthDownloadResult.Failed(e.message ?: "загрузка не удалась")
    }
  }

  private fun open(path: String): HttpURLConnection =
    (URL("https://$nodeHost:$port$path").openConnection() as HttpURLConnection).apply {
      // Токен заголовком, а не в URL: URL оседает в логах прокси и в истории.
      setRequestProperty("X-Hearth-Device-Token", token)
      connectTimeout = 15_000
      readTimeout = 60_000
      instanceFollowRedirects = false
    }

  companion object {
    const val DEFAULT_PORT = 7444
    private const val BASE = "/updates"
    private const val MANIFEST_LIMIT_BYTES = 64 * 1024

    /** Транспорт, настроенный по тому, что записал импорт bundle. */
    fun fromPrefs(context: Context): HearthAndroidUpdateTransport? {
      val host = ChatController.appPrefs.hearthUpdateHost.get() ?: return null
      val token = ChatController.appPrefs.hearthUpdateToken.get() ?: return null
      return HearthAndroidUpdateTransport(context, host, DEFAULT_PORT, token)
    }
  }
}

private fun java.io.InputStream.readBoundedText(limit: Int): String {
  val out = java.io.ByteArrayOutputStream()
  val buf = ByteArray(8 * 1024)
  while (out.size() < limit) {
    val n = read(buf)
    if (n < 0) break
    out.write(buf, 0, n)
  }
  if (out.size() >= limit) throw IllegalStateException("манифест длиннее $limit байт")
  return out.toString(Charsets.UTF_8.name())
}

private fun File.sha256Hex(): String {
  val digest = MessageDigest.getInstance("SHA-256")
  inputStream().use { input ->
    val buf = ByteArray(64 * 1024)
    while (true) {
      val n = input.read(buf)
      if (n < 0) break
      digest.update(buf, 0, n)
    }
  }
  return digest.digest().joinToString("") { "%02x".format(it) }
}
