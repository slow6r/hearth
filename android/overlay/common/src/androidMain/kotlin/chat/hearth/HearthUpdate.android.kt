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
      // `use` здесь не годится: HttpURLConnection не Closeable, у него disconnect().
      val conn = open("$BASE/manifest.json")
      try {
        val code = conn.responseCode
        if (code != 200) throw IllegalStateException("узел ответил $code")
        // Манифест — маленький документ. Ограничение стоит, чтобы подменённый или
        // сломанный эндпоинт не заставил телефон читать поток без конца.
        conn.inputStream.use { it.readBoundedText(MANIFEST_LIMIT_BYTES) }
      } finally {
        conn.disconnect()
      }
    }
  }

  override suspend fun fetchManifestSignature(): Result<String?> = withContext(Dispatchers.IO) {
    runCatching {
      val conn = open("$BASE/manifest.json.sig")
      try {
        when (val code = conn.responseCode) {
          200 -> conn.inputStream.use { it.readBoundedText(MANIFEST_LIMIT_BYTES) }.trim()
          // Подписи на узле нет. Решение об этом принимает HearthUpdateTrust: для
          // сборки со вшитым ключом это отказ, а не повод продолжить.
          404 -> null
          else -> throw IllegalStateException("узел ответил $code")
        }
      } finally {
        conn.disconnect()
      }
    }
  }

  override suspend fun download(
    file: String,
    expectedSha256: String,
    onProgress: (Long, Long) -> Unit,
  ): HearthDownloadResult = withContext(Dispatchers.IO) {
    // filesDir, а не cacheDir: систему никто не просил чистить кэш посреди загрузки
    // 248-мегабайтного файла, но она вправе. Плюс FileProvider уже покрывает filesDir
    // (`file_paths.xml`, `my_files`), значит намерение установки заработает без правок.
    val dir = File(context.filesDir, "hearth-update").apply { mkdirs() }
    val target = File(dir, "hearth-update.apk")
    runCatching {
      // Докачка: если файл уже частично лежит, просим остаток через Range. Обновление
      // весит сотни мегабайт, а телефон в дороге теряет сеть постоянно.
      val already = if (target.exists()) target.length() else 0L
      val conn = open("$BASE/$file")
      try {
        if (already > 0) conn.setRequestProperty("Range", "bytes=$already-")
        val code = conn.responseCode
        val resuming = code == 206
        // 416 означает «этот кусок уже за концом файла» — почти всегда потому, что
        // недокачанный остаток от ПРЕДЫДУЩЕЙ, более старой версии длиннее новой.
        // Начинаем с нуля, а не сдаёмся.
        if (code == 416) {
          target.delete()
          throw IllegalStateException("остаток от прошлой версии не подошёл, начните заново")
        }
        if (code != 200 && code != 206) throw IllegalStateException("узел ответил $code")
        if (already > 0 && !resuming) target.delete()

        val total = conn.contentLengthLong.let {
          if (it > 0) it + (if (resuming) already else 0) else -1L
        }
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
            // Принудительный сброс на диск: иначе внезапная перезагрузка телефона
            // оставит файл, который выглядит целым, а хеш не сойдётся.
            out.fd.sync()
          }
        }
      } finally {
        conn.disconnect()
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

  override suspend fun enroll(name: String): Result<String> = withContext(Dispatchers.IO) {
    runCatching {
      val conn = open("/enroll")
      try {
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        // Имя экранируем через сериализатор, а не склейкой строк: имя вводит человек,
        // и кавычка в нём не должна ломать документ.
        val body = kotlinx.serialization.json.Json.encodeToString(
          kotlinx.serialization.json.JsonObject.serializer(),
          kotlinx.serialization.json.JsonObject(
            mapOf("name" to kotlinx.serialization.json.JsonPrimitive(name))
          ),
        )
        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        val code = conn.responseCode
        if (code == 409) throw IllegalStateException("узел отказал: лимит устройств или такое имя уже есть")
        if (code != 200) throw IllegalStateException("узел ответил $code")
        conn.inputStream.use { it.readBoundedText(BUNDLE_LIMIT_BYTES) }
      } finally {
        conn.disconnect()
      }
    }
  }

  /**
   * Свежие креды TURN.
   *
   * Не часть [HearthUpdateTransport]: обновлениям это не нужно, а звонкам нужно на
   * каждом запуске. Живёт здесь только потому, что адрес узла и токен уже настроены.
   */
  suspend fun turnCredentials(): Result<String> = withContext(Dispatchers.IO) {
    runCatching {
      val conn = open("/turn-credentials")
      try {
        val code = conn.responseCode
        if (code == 404) throw IllegalStateException("на узле выключен TURN")
        if (code != 200) throw IllegalStateException("узел ответил $code")
        conn.inputStream.use { it.readBoundedText(MANIFEST_LIMIT_BYTES) }
      } finally {
        conn.disconnect()
      }
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
    private const val BUNDLE_LIMIT_BYTES = 64 * 1024

    /** Транспорт, настроенный по тому, что записал импорт bundle. */
    fun fromPrefs(context: Context): HearthAndroidUpdateTransport? {
      val host = ChatController.appPrefs.hearthUpdateHost.get()?.ifBlank { null } ?: return null
      val token = ChatController.appPrefs.hearthUpdateToken.get()?.ifBlank { null } ?: return null
      // Порт тоже из bundle: узел может быть проброшен снаружи не на 7444.
      val port = ChatController.appPrefs.hearthUpdatePort.get()?.toIntOrNull() ?: DEFAULT_PORT
      return HearthAndroidUpdateTransport(context, host, port, token)
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
