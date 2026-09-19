package chat.hearth

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import java.io.File
import java.security.MessageDigest

/**
 * Осмотр скачанного APK перед тем, как предложить его установщику.
 *
 * Здесь только добыча фактов; решение принимает [HearthApkRules], и оно покрыто
 * тестами на JVM. Разделение не ради красоты: проверить «что будет, если узел
 * подсунет чужой пакет» иначе можно было бы только установкой чужого пакета.
 *
 * # Про Android 8 (minSdk 26)
 *
 * `PackageManager.GET_SIGNING_CERTIFICATES` и поле `PackageInfo.signingInfo` появились
 * ОБА в API 28. Здесь стоял один флаг на все версии, и поле читалось напрямую — на
 * Android 8.0/8.1 это `NoSuchFieldError` ровно в момент осмотра уже скачанного файла,
 * то есть падение приложения там, где человек ждёт установки. Теперь выбор ветки идёт
 * по версии системы ([HearthApkSigningApi]), а старая ветка через `GET_SIGNATURES`
 * даёт ТОТ ЖЕ вердикт: нормализация одна и та же (sha256 от байтов сертификата),
 * поэтому [HearthApkRules] не отличает, откуда набор пришёл.
 *
 * Обе версионные ветки вынесены в отдельные функции намеренно: так поле API 28
 * упоминается только в методе, который на Android 8 никогда не вызывается, и
 * проверяющий классы верификатор до него не доходит.
 */
object HearthApkGuard {

  fun inspect(context: Context, apk: File, expectedVersionCode: Long): HearthApkRules.Verdict {
    if (!apk.isFile || apk.length() == 0L) {
      return HearthApkRules.Verdict.Refuse("файл обновления не найден")
    }
    val pm = context.packageManager
    val flags = signatureFlags()
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

  /** Какие подписи вообще просить у системы. На 26-27 нового флага не существует. */
  @Suppress("DEPRECATION")
  private fun signatureFlags(): Int =
    HearthApkSigningApi.pick(
      Build.VERSION.SDK_INT,
      PackageManager.GET_SIGNING_CERTIFICATES,
      PackageManager.GET_SIGNATURES,
    )

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
   * Пустой набор — это не «всё хорошо»: [HearthApkRules] отвечает на него отказом.
   * Поэтому любая несовместимость, которую мы не предусмотрели, становится громким
   * отказом с понятным текстом, а не падением на пути установки.
   */
  private fun signaturesOf(info: PackageInfo): Set<String> = runCatching {
    if (HearthApkSigningApi.usesSigningInfo(Build.VERSION.SDK_INT)) {
      signersFromSigningInfo(info)
    } else {
      legacySigners(info)
    }
  }.getOrElse { emptySet() }

  /**
   * Android 9+.
   *
   * Берём именно `apkContentsSigners`: это тот набор, которым файл подписан сейчас.
   * Цепочку ротации (`signingCertificateHistory`) сознательно не принимаем — у нас
   * один офлайновый ключ, и «подпись другим ключом из истории» означала бы, что
   * ключ менялся; такое обновление ставится руками, а не молча по воздуху.
   */
  @RequiresApi(Build.VERSION_CODES.P)
  private fun signersFromSigningInfo(info: PackageInfo): Set<String> {
    val signing = info.signingInfo ?: return emptySet()
    return signing.apkContentsSigners.orEmpty().map { sha256Hex(it.toByteArray()) }.toSet()
  }

  /**
   * Android 8.0/8.1.
   *
   * `PackageInfo.signatures` объявлено устаревшим в API 28, но до него это
   * единственный источник, и вердикт он даёт тот же — набор тех же сертификатов,
   * нормализованный тем же sha256.
   */
  @SuppressLint("PackageManagerGetSignatures")
  @Suppress("DEPRECATION")
  private fun legacySigners(info: PackageInfo): Set<String> =
    info.signatures.orEmpty().map { sha256Hex(it.toByteArray()) }.toSet()

  private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
