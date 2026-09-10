package chat.hearth

/**
 * Onboarding step 0 — "Отсканируй QR настройки узла" (ТЗ §8.2 п.7).
 *
 * This is the whole of the fork's added UI surface. It runs BEFORE upstream's own
 * profile onboarding, applies the bundle, and then hands control back to upstream
 * unchanged. Keeping it a separate screen (rather than editing upstream's onboarding
 * flow) is what keeps the rebase mechanical (ТЗ §8.1, §8.5).
 *
 * INTEGRATION POINTS (see ../../../../../patches/0003-onboarding-import.md):
 *   - QR scanning: reuse upstream's existing scanner composable; do not add a camera
 *     library — a second scanner would be a new dependency and a new permission story.
 *   - [HearthBundleApplier] is implemented in the Android source set against the
 *     upstream chat controller API of the pinned tag.
 */

/** Result of importing a bundle. */
sealed interface HearthImportResult {
  data class Applied(val servers: HearthServers, val device: String) : HearthImportResult
  data class Rejected(val reason: String) : HearthImportResult
}

/**
 * Applies an imported bundle to the SimpleX core.
 *
 * Implemented per-platform against upstream's controller API, because that API is the
 * one thing that moves between tags. Everything above this interface is stable.
 */
interface HearthBundleApplier {
  /** Replace the configured SMP/XFTP servers with exactly these. */
  suspend fun setServers(servers: HearthServers)

  /** Apply ТЗ §8.2 network defaults: private routing, no presets, instant delivery. */
  suspend fun applyNetworkDefaults(prefs: HearthNetPrefs)

  /** Persist which device id this install was enrolled as, for support and revocation. */
  suspend fun rememberDevice(deviceId: String, issued: String)

  /**
   * Запомнить device API узла: обновления и свежие TURN-креды.
   *
   * `null` — узел без device API. Тогда устройство работает как раньше, но его звонки
   * сломаются при следующей ротации TURN-секрета (см. ADR 0010).
   */
  suspend fun rememberNode(node: HearthNodeApi?)
}

/**
 * Import a scanned payload.
 *
 * Pure orchestration: parse, validate, apply, report. No UI, no platform types, so it
 * is unit-testable on the JVM (see HearthBundleTest).
 */
class HearthOnboardingImporter(private val applier: HearthBundleApplier) {

  suspend fun import(payload: String): HearthImportResult {
    val bundle = HearthBundle.parse(payload).getOrElse { error ->
      return HearthImportResult.Rejected(error.message ?: "bundle is not valid")
    }

    val servers = HearthPresets.serversFrom(bundle)
    return runCatching {
      applier.setServers(servers)
      applier.applyNetworkDefaults(bundle.net)
      applier.rememberDevice(bundle.device, bundle.issued)
      applier.rememberNode(bundle.node)
      HearthImportResult.Applied(servers, bundle.device) as HearthImportResult
    }.getOrElse { error ->
      HearthImportResult.Rejected(error.message ?: "could not apply the bundle")
    }
  }
}

/**
 * Copy shown on the first screen. Kept here so translators and reviewers can see the
 * whole of the fork's user-facing text in one file.
 */
object HearthOnboardingText {
  const val TITLE = "Настройка домашнего узла"
  const val BODY =
    "Отсканируйте QR-код, который показал администратор узла.\n\n" +
      "Код содержит пароли релеев — показывайте его лично, " +
      "не пересылайте и не сохраняйте в галерею."
  const val AUTO_BODY =
    "Подключаемся к домашнему узлу. Это занимает несколько секунд " +
      "и делается один раз."
  const val SCAN_BUTTON = "Сканировать QR"
  const val NETWORK_HINT =
    "Дополнительной настройки сети не нужно: узел доступен из интернета. " +
      "Если сообщения не идут — проверьте, что узел включён."
  const val APPLIED = "Узел настроен. Дальше — обычная настройка профиля."
}
