package chat.hearth

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import chat.simplex.common.views.helpers.AlertManager

/**
 * Фоновая работа на Huawei и Honor.
 *
 * # В чём дело
 *
 * Сообщения к нам приходят только через фоновую службу: пуш-серверов Google в сборке
 * нет намеренно. На Huawei (EMUI) и Honor (Magic UI) у системы есть свой «менеджер
 * запуска приложений», который останавливает службу в фоне — молча и независимо от
 * стандартной оптимизации батареи Android. Стандартная проверка
 * `isIgnoringBatteryOptimizations()` при этом отвечает «всё разрешено», поэтому
 * upstream-уведомление о батарее человека не предупреждает.
 *
 * Итог для семьи, где одиннадцать телефонов из тринадцати — Huawei: «уведомления
 * приходят, только когда заходишь в приложение». Единственное лечение — руками в
 * настройках: Батарея → Запуск приложений → Очаг → «Управлять вручную» и включить все
 * три переключателя (автозапуск, вторичный запуск, работа в фоне). Так делает каждый
 * мессенджер на Huawei; программно это не обходится.
 *
 * # Что делает этот файл
 *
 * Один раз за запуск процесса показывает объяснение с кнопкой, которая открывает нужный
 * экран напрямую. Экран у разных версий EMUI называется по-разному, поэтому перебираются
 * известные имена; если ни одно не открылось — обычные сведения о приложении. Отдельный
 * пункт в настройках узла позволяет открыть тот же экран в любой момент.
 */
object HearthHuawei {

  private const val PREFS = "hearth"
  private const val KEY_OPENED = "huawei_launch_settings_opened"

  @Volatile
  private var shownThisProcess = false

  val isHuawei: Boolean
    get() = listOf(Build.MANUFACTURER, Build.BRAND).any {
      it.equals("HUAWEI", ignoreCase = true) || it.equals("HONOR", ignoreCase = true)
    }

  // Порядок — от новых версий EMUI к старым.
  private val LAUNCH_SCREENS = listOf(
    "com.huawei.systemmanager" to "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity",
    "com.huawei.systemmanager" to "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
    "com.huawei.systemmanager" to "com.huawei.systemmanager.optimize.process.ProtectActivity",
  )

  const val STEPS =
    "Найдите Очаг в списке, выключите «Управлять автоматически» и включите все три " +
      "переключателя: автозапуск, вторичный запуск, работа в фоне."

  const val FOOTER =
    "На Huawei и Honor система останавливает приложение в фоне, и сообщения приходят " +
      "только при открытии. " + STEPS

  /** Открыть экран управления запуском; вернуть, открылся ли именно он, а не запасной. */
  fun openLaunchSettings(context: Context): Boolean {
    for ((pkg, cls) in LAUNCH_SCREENS) {
      try {
        context.startActivity(
          Intent().setComponent(ComponentName(pkg, cls)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_OPENED, true).apply()
        return true
      } catch (_: Exception) {
        // этой версии экрана нет — пробуем следующую
      }
    }
    return try {
      context.startActivity(
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}"))
          .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      )
      false
    } catch (_: Exception) {
      false
    }
  }

  /**
   * Показать объяснение: раз за запуск процесса, пока человек хоть раз не открыл
   * нужный экран. «Позже» откладывает до следующего запуска — не навсегда: цена
   * молчания здесь — неприходящие сообщения.
   */
  fun showNoticeIfNeeded(context: Context) {
    if (!isHuawei || shownThisProcess) return
    val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    if (prefs.getBoolean(KEY_OPENED, false)) return
    // Поверх чужого диалога не лезем — покажем при следующем выходе на экран.
    if (AlertManager.shared.hasAlertsShown()) return
    shownThisProcess = true
    AlertManager.shared.showAlertDialog(
      title = "Сообщения в фоне на Huawei",
      text = "Чтобы сообщения приходили, когда Очаг закрыт, телефону надо разрешить ему " +
        "работать в фоне. Иначе система останавливает приложение, и уведомления " +
        "появляются только при открытии.\n\n" + STEPS,
      confirmText = "Открыть настройки",
      onConfirm = { openLaunchSettings(context) },
      dismissText = "Позже",
    )
  }
}
