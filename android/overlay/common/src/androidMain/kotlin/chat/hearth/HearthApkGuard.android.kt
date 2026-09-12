package chat.hearth

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Осмотр скачанного APK перед тем, как предложить его установщику.
 *
 * Здесь только добыча фактов; решение принимает [HearthApkRules], и оно покрыто
 * тестами на JVM. Разделение не ради красоты: проверить «что будет, если узел
 * подсунет чужой пакет» иначе можно было бы только установкой чужого пакета.
 */
object HearthApkGuard {

  fun inspect(context: Context, apk: File, expectedVersionCode: Long): HearthApkRules.Verdict {
    if (!apk.isFile || apk.length() == 0L) {
      return HearthApkRules.Verdict.Refuse("файл обновления не найден")
    }
    val pm = context.packageManager
    val flags = PackageManager.GET_SIGNING_CERTIFICATES
    val downloaded = runCatching { pm.getPackageArchiveInfo(apk.absolutePath, flags) }.getOrNull()
    val installed = runCatching { pm.getPackageInfo(context.packageName, flags) }.getOrNull()

    return HearthApkRules.decide(
      HearthApkRules.Facts(
        packageName = downloaded?.packageName,
        ownPackageName = context.packageName,
        versionCode = downloaded?.let(::versionCodeOf) ?: 0L,
        installedVersionCode = installed?.let(::versionCodeOf) ?: 0L,
        expectedVersionCode = expectedVersionCode,
        signatures = downloaded?.let(::signaturesOf).orEmpty(),
        installedSignatures = installed?.let(::signaturesOf).orEmpty(),
      )
    )
  }

  private fun versionCodeOf(info: PackageInfo): Long =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      info.longVersionCode
    } else {
      @Suppress("DEPRECATION")
      info.versionCode.toLong()
    }

  /**
   * Отпечатки сертификатов подписи.
   *
   * Берём именно `apkContentsSigners`: это тот набор, которым файл подписан сейчас.
   * Цепочку ротации (`signingCertificateHistory`) сознательно не принимаем — у нас
   * один офлайновый ключ, и «подпись другим ключом из истории» означала бы, что
   * ключ менялся; такое обновление ставится руками, а не молча по воздуху.
   */
  private fun signaturesOf(info: PackageInfo): Set<String> {
    val signing = info.signingInfo ?: return emptySet()
    val certs = if (signing.hasMultipleSigners()) {
      signing.apkContentsSigners
    } else {
      signing.apkContentsSigners
    }
    return certs.orEmpty().map { sha256Hex(it.toByteArray()) }.toSet()
  }

  private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
