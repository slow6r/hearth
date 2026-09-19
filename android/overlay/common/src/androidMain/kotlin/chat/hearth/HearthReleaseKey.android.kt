package chat.hearth

import android.content.Context
import android.util.Base64
import chat.simplex.common.platform.Log
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Открытый ключ подписи манифестов и проверка этой подписи.
 *
 * Ключ вшивается в сборку скриптом раздачи (`bake-node.sh`) и секретом не является —
 * секретна закрытая половина, и она на узел не попадает никогда. Именно поэтому
 * захваченный узел не может выдать своё обновление: подписать манифест ему нечем.
 *
 * ECDSA P-256, а не Ed25519: `SHA256withECDSA` есть во всех версиях Android, а
 * Ed25519 появился только в API 33. Новых зависимостей не требуется ни там, ни там.
 *
 * # Почему «нет ключа» и «ключ не прочитался» — разные события
 *
 * Раньше [pinned] отвечала `null` на оба случая: и когда ресурса нет, и когда чтение
 * упало. А [HearthUpdateTrust] на `null` отвечал «проверять нечем — пропускаем».
 * Значит любая осечка чтения ресурса выключала проверку подписи целиком, молча.
 * Теперь отсутствие ключа — отказ в любом случае, а сборку без проверки надо
 * объявлять отдельным ресурсом ([unsignedUpdatesAllowed]), который релизный гейт
 * `verify-apk.sh` в релизе не пропускает.
 */
object HearthReleaseKey {
  private const val RESOURCE_NAME = "hearth_release_key"

  /**
   * Ресурс-объявление «эта сборка сознательно живёт без проверки подписи».
   *
   * Пустой файл, содержимое неважно — важен сам факт. Вырезать ресурс может кто
   * угодно, а дописать — значит оставить в сборке след, который видно снаружи.
   */
  private const val UNSIGNED_FLAG_RESOURCE = "hearth_allow_unsigned_updates"

  private const val LIMIT_BYTES = 4 * 1024

  /** Открытый ключ из сборки (base64 SPKI), или `null` — ключа в сборке нет. */
  fun pinned(context: Context): String? {
    val id = resourceId(context, RESOURCE_NAME)
    if (id == 0) return null
    return runCatching {
      context.resources.openRawResource(id).use { input ->
        // Читаем ДО конца, а не один `read()`: один вызов возвращает сколько придётся,
        // и длинный ключ обрезался бы посередине — подпись потом «просто не сходится»,
        // и искать причину будут в узле.
        val bytes = input.readBounded(LIMIT_BYTES)
        String(bytes, Charsets.UTF_8).trim()
      }
    }.getOrElse { e ->
      // Ресурс есть, но прочитать не удалось. Это не «сборка без ключа»: тихо вернуть
      // null здесь означало бы выключить проверку подписи поломкой чтения.
      Log.e("hearth", "ключ проверки обновлений не прочитан: ${e.message}")
      null
    }?.ifBlank { null }
  }

  /**
   * Разрешено ли этой сборке обновляться без проверки подписи.
   *
   * `true` только когда ключа в сборке НЕТ ВОВСЕ и рядом лежит объявление. Если ресурс
   * с ключом присутствует, но не прочитался, ответ `false`: сборка заявляла, что умеет
   * проверять, значит обязана проверить или отказаться.
   */
  fun unsignedUpdatesAllowed(context: Context): Boolean {
    if (resourceId(context, RESOURCE_NAME) != 0) return false
    return resourceId(context, UNSIGNED_FLAG_RESOURCE) != 0
  }

  private fun resourceId(context: Context, name: String): Int =
    runCatching { context.resources.getIdentifier(name, "raw", context.packageName) }
      .getOrDefault(0)

  /**
   * Сошлась ли подпись.
   *
   * Любая осечка — разбора ключа, разбора подписи, самой проверки — это `false`.
   * Исключение здесь означало бы «проверить не удалось», а такое состояние обязано
   * читаться как отказ, а не как успех.
   */
  fun verify(body: ByteArray, signatureBase64: String, publicKeyBase64: String): Boolean =
    runCatching {
      val spki = Base64.decode(publicKeyBase64, Base64.DEFAULT)
      val der = Base64.decode(signatureBase64, Base64.DEFAULT)
      val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
      Signature.getInstance("SHA256withECDSA").run {
        initVerify(key)
        update(body)
        verify(der)
      }
    }.getOrDefault(false)
}

/** Прочитать поток целиком, но не дальше потолка: ресурс в сборке маленький. */
private fun java.io.InputStream.readBounded(limit: Int): ByteArray {
  val out = java.io.ByteArrayOutputStream()
  val buf = ByteArray(1024)
  while (true) {
    val n = read(buf)
    if (n < 0) break
    if (out.size() + n > limit) throw IllegalStateException("ресурс ключа длиннее $limit байт")
    out.write(buf, 0, n)
  }
  return out.toByteArray()
}
