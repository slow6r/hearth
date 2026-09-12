package chat.hearth

import android.content.Context
import android.util.Base64
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
 */
object HearthReleaseKey {
  private const val RESOURCE_NAME = "hearth_release_key"
  private const val LIMIT_BYTES = 4 * 1024

  /** Открытый ключ из сборки (base64 SPKI), или `null` — сборка без него. */
  fun pinned(context: Context): String? {
    val id = context.resources.getIdentifier(RESOURCE_NAME, "raw", context.packageName)
    if (id == 0) return null
    return runCatching {
      context.resources.openRawResource(id).use { input ->
        val bytes = ByteArray(LIMIT_BYTES)
        val read = input.read(bytes)
        if (read <= 0) return null
        String(bytes, 0, read, Charsets.UTF_8).trim()
      }
    }.getOrNull()?.ifBlank { null }
  }

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
