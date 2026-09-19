package chat.hearth

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

/**
 * Фоновая загрузка обновления.
 *
 * # Почему сервис, а не просто корутина
 *
 * Требование было прямым: «загрузка продолжается, даже если приложение свернуть».
 * Обычная корутина в Activity умирает вместе с ней, а работа в фоне без видимого
 * уведомления Android убивает сам — начиная с Android 8 это не разрешено.
 * Foreground-сервис с уведомлением о прогрессе — единственный способ, который система
 * не прерывает.
 *
 * # Чего сервис НЕ делает и не может
 *
 * Не устанавливает APK молча. Android показывает системный диалог «Установить?»
 * обязательно, и в этот момент приложение перезапускается. Обойти это может только
 * device-owner или системное приложение, то есть телефон под корпоративным
 * управлением. Поэтому сценарий такой: скачалось в фоне → уведомление «готово» →
 * человек нажимает один раз.
 *
 * Подмену APK по дороге ловит сам Android: обновление обязано быть подписано тем же
 * ключом, иначе установка отклоняется. Хеш из манифеста проверяется здесь ради другого —
 * битой докачки, которую подпись не заметит, пока не станет поздно.
 */
class HearthUpdateService : Service() {

  private val scope = CoroutineScope(Dispatchers.IO + Job())
  private var job: Job? = null

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent?.action == ACTION_CANCEL) {
      job?.cancel()
      stopSelf()
      return START_NOT_STICKY
    }

    val file = intent?.getStringExtra(EXTRA_FILE)
    val sha256 = intent?.getStringExtra(EXTRA_SHA256)
    val version = intent?.getStringExtra(EXTRA_VERSION) ?: "?"
    val versionCode = intent?.getIntExtra(EXTRA_VERSION_CODE, 0)?.toLong() ?: 0L
    if (file == null || sha256 == null) {
      stopSelf()
      return START_NOT_STICKY
    }

    createChannel()
    startForeground(NOTIFICATION_ID, progressNotification(version, 0, -1))

    // Один запуск за раз: две параллельные загрузки одного файла подрались бы за него.
    if (job?.isActive == true) return START_NOT_STICKY

    job = scope.launch {
      val transport = HearthAndroidUpdateTransport.fromPrefs(applicationContext)
      if (transport == null) {
        notify(doneNotification(NO_NODE, null))
        stopSelf()
        return@launch
      }

      var lastShown = -1
      val result = transport.download(file, sha256) { done, total ->
        // Уведомление перерисовывается только когда меняется целый процент: иначе
        // на быстрой сети шторка обновляется сотни раз в секунду и телефон тормозит.
        val pct = if (total > 0) ((done * 100) / total).toInt() else -1
        if (pct != lastShown) {
          lastShown = pct
          notify(progressNotification(version, pct, total))
        }
      }

      when (result) {
        is HearthDownloadResult.Ready -> {
          // Осмотр ДО того, как человеку предложат установку. Android и сам отвергнет
          // чужую подпись — но уже после системного диалога, на который человек,
          // которому приложение само предложило обновиться, нажмёт «Установить».
          // Здесь же отбрасываются случаи, которые система пропустила бы молча:
          // другой пакет, версия не та, что обещал узел, откат на старую.
          val apk = java.io.File(result.path)
          // runCatching вокруг осмотра: он лезет в PackageManager, а тот на разных
          // версиях Android умеет бросать то, чего мы не предусмотрели. Раньше бросок
          // уходил из scope.launch без перехвата и ронял приложение ровно тогда, когда
          // APK уже скачан. Несовместимость обязана быть громким отказом, а не падением.
          val verdict = runCatching {
            HearthApkGuard.inspect(applicationContext, apk, versionCode)
          }.getOrElse { e ->
            HearthApkRules.Verdict.Refuse("проверить файл не удалось: ${e.message ?: e::class.simpleName}")
          }
          when (verdict) {
            is HearthApkRules.Verdict.Allow ->
              notify(doneNotification(readyText(version), result.path))

            is HearthApkRules.Verdict.Refuse -> {
              // Файл удаляем: он не должен остаться лежать и однажды быть установлен
              // руками из «Загрузок».
              apk.delete()
              notify(doneNotification(refusedText(verdict.reason), null))
            }
          }
        }

        is HearthDownloadResult.Failed -> notify(doneNotification(failedText(result.reason), null))
      }
      stopForeground(STOP_FOREGROUND_DETACH)
      stopSelf()
    }
    return START_REDELIVER_INTENT
  }

  override fun onDestroy() {
    scope.cancel()
    super.onDestroy()
  }

  // --- уведомления ---------------------------------------------------------------

  private fun createChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val mgr = getSystemService(NotificationManager::class.java)
    if (mgr.getNotificationChannel(CHANNEL) != null) return
    mgr.createNotificationChannel(
      NotificationChannel(CHANNEL, "Обновление Очага", NotificationManager.IMPORTANCE_LOW).apply {
        description = "Загрузка новой версии приложения с домашнего узла"
        setShowBadge(false)
      }
    )
  }

  private fun base(): NotificationCompat.Builder =
    NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(android.R.drawable.stat_sys_download)
      .setOnlyAlertOnce(true)
      .setOngoing(false)

  private fun progressNotification(version: String, pct: Int, total: Long): Notification {
    val cancel = PendingIntent.getService(
      this,
      0,
      Intent(this, HearthUpdateService::class.java).setAction(ACTION_CANCEL),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    return base()
      .setContentTitle("Загрузка Очага $version")
      .setContentText(
        if (total > 0) "${pct}% из ${total / 1024 / 1024} МБ" else "соединяемся с узлом…"
      )
      .setProgress(100, pct.coerceAtLeast(0), pct < 0)
      .setOngoing(true)
      .addAction(0, "Отменить", cancel)
      .build()
  }

  private fun doneNotification(text: String, path: String?): Notification {
    val b = base()
      .setSmallIcon(android.R.drawable.stat_sys_download_done)
      .setContentTitle("Очаг")
      .setContentText(text)
      .setStyle(NotificationCompat.BigTextStyle().bigText(text))
      .setAutoCancel(true)
    if (path != null) {
      b.setContentIntent(
        PendingIntent.getActivity(
          this,
          1,
          installIntent(this, File(path)),
          PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
      )
    }
    return b.build()
  }

  private fun notify(n: Notification) {
    getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, n)
  }

  private fun readyText(version: String) =
    "Версия $version скачана. Нажмите, чтобы установить — Android покажет свой диалог, " +
      "приложение при этом перезапустится."

  /** Обновление отвергнуто проверкой — это не сетевая ошибка, и текст другой. */
  private fun refusedText(reason: String): String =
    "Обновление отклонено: $reason. Файл удалён. Возьмите сборку у администратора."

  private fun failedText(reason: String) = "Обновление не скачалось: $reason"

  companion object {
    private const val CHANNEL = "hearth_update"
    private const val NOTIFICATION_ID = 4201
    private const val ACTION_CANCEL = "chat.hearth.CANCEL_UPDATE"
    private const val EXTRA_FILE = "file"
    private const val EXTRA_SHA256 = "sha256"
    private const val EXTRA_VERSION = "version"
    private const val EXTRA_VERSION_CODE = "versionCode"
    private const val NO_NODE =
      "Узел не настроен: сначала отсканируйте QR настроек узла."

    /** Запустить загрузку. Сервис сам покажет прогресс и переживёт сворачивание. */
    fun start(context: Context, manifest: HearthUpdateManifest) {
      val intent = Intent(context, HearthUpdateService::class.java)
        .putExtra(EXTRA_FILE, manifest.file)
        .putExtra(EXTRA_SHA256, manifest.sha256)
        .putExtra(EXTRA_VERSION, manifest.versionName)
        .putExtra(EXTRA_VERSION_CODE, manifest.versionCode)
      androidx.core.content.ContextCompat.startForegroundService(context, intent)
    }

    /**
     * Намерение установки.
     *
     * Через FileProvider: с Android 7 передавать `file://` другому приложению нельзя,
     * система бросает FileUriExposedException. Authority — тот же, что объявлен в
     * манифесте (`${provider_authorities}`).
     */
    fun installIntent(context: Context, apk: File): Intent {
      val uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.provider",
        apk,
      )
      return Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, "application/vnd.android.package-archive")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
  }
}
