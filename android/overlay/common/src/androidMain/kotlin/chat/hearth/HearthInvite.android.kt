package chat.hearth

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Чтение вшитого приглашения и заведение по нему.
 *
 * Ресурс ищется ПО ИМЕНИ, а не через сгенерированный `R`. Причина простая: приглашение
 * кладётся в сборку скриптом раздачи и в репозитории его нет, поэтому ссылка на
 * `R.raw.hearth_invite` ломала бы компиляцию обычной сборки «по QR». Минификация в
 * релизе выключена (`isMinifyEnabled = false`), так что ресурс, на который нет ссылки
 * из кода, никто не вырежет.
 */
object HearthInviteSource {
  private const val RESOURCE_NAME = "hearth_invite"
  private const val LIMIT_BYTES = 4 * 1024

  /** Приглашение из сборки, или `null` — если это обычная сборка «по QR». */
  fun baked(context: Context): HearthBakedInvite? {
    val id = context.resources.getIdentifier(RESOURCE_NAME, "raw", context.packageName)
    if (id == 0) return null
    val payload = runCatching {
      context.resources.openRawResource(id).use { input ->
        val bytes = ByteArray(LIMIT_BYTES)
        val read = input.read(bytes)
        if (read <= 0) return null
        String(bytes, 0, read, Charsets.UTF_8)
      }
    }.getOrNull() ?: return null
    // Битое приглашение — это обычная сборка «по QR», а не отказ работать: человек
    // должен получить сканер, а не пустой экран.
    return HearthBakedInvite.parse(payload).getOrNull()
  }

  /**
   * Как назвать устройство в реестре.
   *
   * Модель телефона, а не имя человека: на этом экране человек ничего не вводит — в
   * этом весь смысл. Различать одинаковые модели узел умеет сам, дописывая номер.
   */
  fun deviceName(): String {
    val manufacturer = Build.MANUFACTURER.orEmpty().trim()
    val model = Build.MODEL.orEmpty().trim()
    val name = when {
      model.startsWith(manufacturer, ignoreCase = true) -> model
      manufacturer.isEmpty() -> model
      else -> "$manufacturer $model"
    }
    return name.ifBlank { "Android" }.take(48)
  }
}

/** `POST /claim` поверх `HttpURLConnection` — без новых зависимостей (ТЗ §8.3). */
class HearthAndroidClaimTransport : HearthClaimTransport {

  override suspend fun claim(
    invite: HearthBakedInvite,
    deviceName: String,
  ): Result<String> = withContext(Dispatchers.IO) {
    runCatching {
      val url = URL("https://${invite.host}:${invite.port}/claim")
      // `use` не годится: HttpURLConnection не Closeable, у него disconnect().
      val conn = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        // Токен заголовком, а не в URL: URL оседает в логах прокси и в истории.
        setRequestProperty("X-Hearth-Invite-Token", invite.token)
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
        when (val code = conn.responseCode) {
          200 -> conn.inputStream.use { readBounded(it) }
          401 -> throw IllegalStateException(
            "приглашение в этой сборке больше не действует — попросите новую или настройте по QR"
          )
          409 -> throw IllegalStateException("на узле кончились места для устройств")
          else -> throw IllegalStateException("узел ответил $code")
        }
      } finally {
        conn.disconnect()
      }
    }
  }

  private fun readBounded(input: java.io.InputStream): String {
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

actual suspend fun hearthAutoSetUp(): HearthClaimResult {
  val context = chat.simplex.common.platform.androidAppContext
  val invite = HearthInviteSource.baked(context)
  val enroller = HearthSelfEnroller(HearthAndroidClaimTransport())
  return enroller.setUp(invite, HearthInviteSource.deviceName())
}
