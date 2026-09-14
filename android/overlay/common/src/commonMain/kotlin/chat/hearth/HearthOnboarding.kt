package chat.hearth

import chat.simplex.common.model.ChatController

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
  const val TITLE = "Настройка узла"

  // --- Код доступа (ADR 0012) ---

  const val CODE_TITLE = "Код доступа"

  /**
   * Сборка без вшитого адреса узла.
   *
   * Раньше в этом случае показывался сканер QR. Его больше нет: настройка по QR
   * отменена в пользу кода доступа, и человеку честнее сказать, что сборка неполная,
   * чем включать камеру на экране, который он видит один раз и не понимает.
   */
  const val INCOMPLETE_BUILD =
    "Эта сборка неполная: в ней нет адреса узла. Возьмите установочный файл у того, " +
      "кто вас пригласил, — вместе с кодом доступа."
  const val CODE_BODY =
    "Введите код, который вам дали лично. Двенадцать знаков, вводится один раз — " +
      "дальше приложение настроится само."
  const val CODE_HINT = "Регистр и дефисы не важны."
  const val CODE_BUTTON = "Продолжить"
  const val CODE_WORKING = "Подключаемся к узлу…"

  /** Набрано меньше двенадцати знаков — ловим до похода в сеть. */
  const val CODE_INCOMPLETE = "В коде двенадцать знаков — проверьте, всё ли набрано."

  /**
   * Узел отказал. Формулировка намеренно одна на все случаи: узел не различает
   * «такого кода нет», «он уже использован» и «он отозван» — по ответу нельзя
   * узнать, существовал ли код. Человеку полезнее знать, что делать, чем почему.
   */
  const val CODE_REFUSED = "Код не подошёл — возможно, он уже использован. Попросите новый."

  /** Ограничитель перебора на узле (deviceapi::throttle). */
  const val CODE_THROTTLED = "Слишком много попыток. Попробуйте через час."
  const val BODY =
    "Отсканируйте QR-код, который показал администратор узла.\n\n" +
      "Код содержит пароли релеев — показывайте его лично, " +
      "не пересылайте и не сохраняйте в галерею."
  const val AUTO_BODY =
    "Подключаемся к узлу. Это занимает несколько секунд " +
      "и делается один раз."
  const val SCAN_BUTTON = "Сканировать QR"
  const val NETWORK_HINT =
    "Дополнительной настройки сети не нужно: узел доступен из интернета. " +
      "Если сообщения не идут — проверьте, что узел включён."
  const val APPLIED = "Узел настроен. Дальше — обычная настройка профиля."
}

/**
 * Принять bundle: проверить и отложить до появления профиля.
 *
 * # Почему не применить сразу
 *
 * Экран узла идёт ПЕРВЫМ, раньше стокового онбординга — так и задумано: телефон должен
 * знать свой узел до того, как что-либо создаст. Но записать серверы в ядро в этот
 * момент нельзя: `apiSetUserServers` требует `userId`, а пользователя ещё нет —
 * `currentUserId()` бросает «no current user». То есть применение неизбежно позже
 * приёма.
 *
 * Так что здесь bundle проверяется (подменённый или протухший QR должен быть отвергнут
 * на месте, пока человек стоит перед кодом) и откладывается. Применяет его
 * [hearthApplyPendingBundle] в первый момент, когда профиль появился.
 */
suspend fun hearthAcceptBundle(payload: String): HearthImportResult {
  val bundle = HearthBundle.parse(payload).getOrElse { error ->
    return HearthImportResult.Rejected(error.message ?: "bundle is not valid")
  }
  return runCatching {
    ChatController.appPrefs.hearthPendingBundle.set(payload)
    HearthImportResult.Applied(HearthPresets.serversFrom(bundle), bundle.device) as HearthImportResult
  }.getOrElse { error ->
    HearthImportResult.Rejected(error.message ?: "не удалось сохранить настройки узла")
  }
}

/**
 * Применить отложенный bundle. Вызывается сразу после того, как профиль создан и ядро
 * запущено, — и ещё раз при каждом старте, если применить не удалось.
 *
 * `true`, если применять было нечего или применилось. `false` — bundle есть, но лёг
 * неудачно: тогда человека возвращают на экран узла, а значение остаётся ждать.
 */
suspend fun hearthApplyPendingBundle(): Boolean {
  val payload = ChatController.appPrefs.hearthPendingBundle.get()?.ifBlank { null } ?: return true
  return when (HearthOnboardingImporter(HearthCoreApplier()).import(payload)) {
    is HearthImportResult.Applied -> {
      // Стираем сразу: в bundle пароли релеев, и держать его в настройках дольше
      // необходимого незачем — адреса уже записаны в серверы ядра.
      ChatController.appPrefs.hearthPendingBundle.set(null)
      true
    }
    is HearthImportResult.Rejected -> false
  }
}
