package chat.hearth

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import chat.simplex.common.model.ChatController
import chat.simplex.common.platform.Log

/**
 * Проверка обновлений: как собрать проверяющего и как сходить к узлу в фоне.
 *
 * # Зачем понадобился отдельный файл
 *
 * Проверка была ровно одна — по нажатию «Проверить обновление» на экране «Узел». Это
 * значит, что телефон, месяцами не видевший обновлений, выглядел нормально: отметки об
 * удачной проверке не сохранялось, [HearthUpdateTrust.isStale] не вызывалась ни разу, и
 * требование ТЗ §1.4 «security-релиз в контуре за ≤ 7 дней» зависело от того, зайдёт ли
 * человек в настройки. Захваченный узел не может подсунуть своё, но может молчать — и
 * молчание было невидимо.
 *
 * Теперь удавшаяся проверка оставляет день в настройках, [checkQuietly] ходит к узлу
 * сама из фонового блока запуска и один раз за окно молчания говорит об этом человеку.
 *
 * Молчание при этом различается двух родов, и оба доходят до человека, но по-разному:
 * «узел не отвечает на проверку» — [silenceNotice] и уведомление в шторку; «узел
 * отвечает, но давно не публиковал нового» — строка [HearthPrefs.updateNotice] на
 * экране «Узел». Второе раньше было ОТКАЗОМ, то есть звучало как «обновлений вам больше
 * не будет», хотя означало «сходите спросите».
 *
 * # Чего [checkQuietly] НЕ делает
 *
 * Не качает APK. Сотни мегабайт по мобильной сети без спроса — это не забота, а счёт
 * за трафик. Нашлась новая версия — человек увидит её на экране «Узел» и нажмёт сам.
 */
object HearthUpdates {

  /** Проверяющий, настроенный по тому, что записано на этом устройстве. */
  fun checker(
    context: Context,
    transport: HearthUpdateTransport,
    installedVersionCode: Int,
  ): HearthUpdateChecker = HearthUpdateChecker(
    transport = transport,
    installedVersionCode = installedVersionCode,
    pinnedKey = HearthReleaseKey.pinned(context),
    verify = HearthReleaseKey::verify,
    lastSeenIssued = ChatController.appPrefs.hearthLastManifestIssued.get()?.ifBlank { null },
    rememberIssued = { ChatController.appPrefs.hearthLastManifestIssued.set(it) },
    // Сборка без ключа проверяет обновления только если сама это объявила ресурсом.
    unsignedUpdatesAllowed = HearthReleaseKey.unsignedUpdatesAllowed(context),
    nowEpochDays = hearthNowEpochDays(),
    firstSeenEpochDays = HearthPrefs.manifestFirstSeenDay,
    rememberFirstSeenDay = { HearthPrefs.manifestFirstSeenDay = it },
    // Удавшаяся проверка не только ставит день, но и обнуляет счёт неудачных дней:
    // молчание меряется непрерывной полосой, а не суммой обрывов за всю жизнь телефона.
    rememberCheckedDay = { HearthPrefs.noteCheckSucceeded(it) },
  )

  /**
   * versionCode установленной сборки.
   *
   * Именно code, а не versionName: строку человек пишет руками и может ошибиться, а
   * code монотонен по требованию Android — на нём и строится сравнение «новее ли».
   */
  fun installedVersionCode(context: Context): Int = runCatching {
    val info = context.packageManager.getPackageInfo(context.packageName, 0)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      info.longVersionCode.toInt()
    } else {
      @Suppress("DEPRECATION")
      info.versionCode
    }
  }.getOrDefault(0)

  /**
   * Давно ли узел последний раз отвечал на проверку обновлений.
   *
   * Считается по ПОПЫТКАМ, а не по календарю: телефон, который сам неделю не выходил в
   * сеть, к узлу не обращался ни разу, и обвинять узел в этом нельзя — человек сходит к
   * владельцу узла зря. См. [HearthUpdateTrust.isStale].
   */
  fun nodeIsSilent(todayEpochDays: Long = hearthNowEpochDays()): Boolean =
    HearthUpdateTrust.isStale(
      lastSuccessEpochDays = HearthPrefs.lastUpdateCheckDay,
      todayEpochDays = todayEpochDays,
      failedAttemptDays = HearthPrefs.failedUpdateCheckDays,
    )

  /** Строка для экрана «Узел». `null` — говорить не о чем. */
  fun silenceNotice(todayEpochDays: Long = hearthNowEpochDays()): String? {
    val last = HearthPrefs.lastUpdateCheckDay ?: return null
    if (!nodeIsSilent(todayEpochDays)) return null
    // В тексте обе величины: сколько дней прошло И сколько раз мы на самом деле
    // стучались. Вторая и отличает «узел молчит» от «телефон неделю лежал выключенным».
    return "Узел не отвечает: последний раз он отозвался ${todayEpochDays - last} дней " +
      "назад, с тех пор мы пробовали связаться с ним в ${HearthPrefs.failedUpdateCheckDays} " +
      "разных дней и ответа не было ни разу. Так выглядит и потерянная связь с узлом, и " +
      "остановленная раздача обновлений — свяжитесь с владельцем узла. Переписка и звонки " +
      "продолжают работать."
  }

  /**
   * Запомнить исход проверки.
   *
   * Одно место на оба входа — фоновый заход и кнопку на экране «Узел». Два разных набора
   * присваиваний однажды разъехались бы, и разъехались бы молча: счётчик молчания рос бы
   * только от одного из них.
   */
  fun remember(result: HearthUpdateCheck, todayEpochDays: Long = hearthNowEpochDays()) {
    when (result) {
      // Здоровый ответ стирает старую строку: предупреждение, пережившее починку,
      // перестают читать — и тогда оно не работает вовсе.
      is HearthUpdateCheck.Available -> HearthPrefs.updateNotice = result.notice
      is HearthUpdateCheck.UpToDate -> HearthPrefs.updateNotice = result.notice
      is HearthUpdateCheck.Failed ->
        if (result.actionable) {
          // Узел ответил, и ответ не приняли. Само это не пройдёт, значит в логе этому
          // не место: строка уходит на экран «Узел» — туда, куда человека посылают,
          // когда что-то не так.
          HearthPrefs.updateNotice = result.reason
        } else {
          // До узла не дошли. Строку НЕ трогаем: новых сведений нет, а прошлые остаются
          // верными. Зато считаем попытку — по ним и меряется молчание узла.
          HearthPrefs.noteCheckFailed(todayEpochDays)
        }
    }
  }

  /**
   * Сходить к узлу молча.
   *
   * Вызывать из фонового блока запуска — рядом с обновлением ICE-кредов, — а не с пути,
   * где человек ждёт списка чатов: это сетевой вызов, и на плохой связи он ждёт минуту.
   *
   * Сам этот блок живёт в `Core.kt`, то есть в дереве форка. Вызов стоит там одной
   * строкой с пометкой `hearth (UPD-5)` — рядом с `hearthRefreshIceServers`. Строка
   * ровно одна, и потерять её при ребейзе легко: без неё день проверки запишет только
   * ручное «Проверить обновление» на экране «Узел», и молчание узла станет видно
   * позже, чем должно. Отсюда и пометка — чтобы пропажу было видно в диффе.
   *
   * Неудача человеку не показывается: узел мог быть недоступен ровно в этот момент, а
   * повод для тревоги — не одна неудача, а МОЛЧАНИЕ, и о нём говорит [silenceNotice].
   */
  suspend fun checkQuietly(context: Context) {
    val transport = HearthAndroidUpdateTransport.fromPrefs(context)
    if (transport == null) {
      // Устройство ещё не заведено: проверять нечего и тревожить не о чем.
      return
    }
    val result = checker(context, transport, installedVersionCode(context)).check()
    remember(result)
    when (result) {
      is HearthUpdateCheck.Available -> {
        Log.w("hearth", "на узле есть версия ${result.manifest.versionName}")
        // Экран «Узел» человек может не открыть ни разу за год — ровно по этой причине
        // туда же, в шторку, уходят отказ и молчание. Доступная версия до недавнего
        // времени была единственным исходом, остававшимся только в настройках: человек
        // узнавал о сломанном обновлении, но не о готовом.
        offerUpdate(context, result.manifest)
      }
      is HearthUpdateCheck.UpToDate ->
        Log.d("hearth", "обновлений нет, узел отвечает")
      is HearthUpdateCheck.Failed -> {
        Log.w("hearth", "проверка обновления не удалась: ${result.reason}")
        // Отказ, который сам не пройдёт (нет ключа в сборке, не сошлась подпись, вышел
        // срок), человек обязан увидеть. Экран «Узел» он может не открыть ни разу за год,
        // поэтому то же самое уходит и в шторку.
        if (result.actionable) warnAboutRefusal(context, result.reason)
      }
    }
    warnIfSilent(context)
  }

  /**
   * Одноразовое уведомление о молчании.
   *
   * Экран «Узел» человек может не открыть ни разу за год, поэтому предупреждение
   * дублируется в шторку — но не чаще раза за окно молчания.
   */
  private fun warnIfSilent(context: Context) {
    val today = hearthNowEpochDays()
    val notice = silenceNotice(today) ?: return
    val shown = HearthPrefs.staleNoticeDay
    if (shown != null && today - shown < HearthUpdateTrust.STALE_AFTER_DAYS) return
    if (show(context, "Очаг: узел молчит", notice)) HearthPrefs.staleNoticeDay = today
  }

  /**
   * Отказ проверки, который сам не пройдёт.
   *
   * Отдельно от [warnIfSilent] и с отдельным счётчиком: молчание узла проходит само,
   * когда узел оживёт, а «в сборке нет ключа» или «вышел срок манифеста» не пройдёт
   * никогда, пока человек чего-нибудь не сделает. Один счётчик на два повода означал бы,
   * что одно предупреждение глушит другое — и глушит молча.
   *
   * Не чаще раза за окно молчания: предупреждение, которое видно каждый день, перестают
   * читать, и тогда оно не работает вовсе.
   */
  private fun warnAboutRefusal(context: Context, reason: String) {
    val today = hearthNowEpochDays()
    val shown = HearthPrefs.updateProblemNoticeDay
    if (shown != null && today - shown < HearthUpdateTrust.STALE_AFTER_DAYS) return
    val text = "Обновления с узла не ставятся: $reason"
    if (show(context, "Очаг: обновления не проверяются", text)) {
      HearthPrefs.updateProblemNoticeDay = today
    }
  }

  /**
   * Показать уведомление в шторке. `false` — не вышло (и это не повод падать).
   *
   * Разрешения на уведомления может не быть, менеджера может не оказаться, прошивка
   * Huawei может отказать — но проверка обновлений не должна из-за этого срываться.
   */
  /**
   * Сказать в шторку, что на узле готова новая версия.
   *
   * Правило «говорить ли» — [HearthUpdateOffer.shouldAnnounce], и оно намеренно живёт в
   * commonMain: это единственная часть, которую можно проверить тестом без устройства.
   * Здесь остаётся то, что без Android не проверяется, — показ и запись отметки.
   *
   * Отметка ставится ТОЛЬКО если уведомление действительно показано. Иначе телефон, где
   * уведомления запрещены, записал бы «сказано» и замолчал на неделю, ничего не сказав.
   */
  private fun offerUpdate(context: Context, manifest: HearthUpdateManifest) {
    val today = hearthNowEpochDays()
    val announce = HearthUpdateOffer.shouldAnnounce(
      versionCode = manifest.versionCode,
      announcedVersionCode = HearthPrefs.updateOfferedVersionCode,
      announcedDay = HearthPrefs.updateOfferedDay,
      todayEpochDays = today,
    )
    if (!announce) return
    val shown = show(
      context,
      HearthUpdateOffer.TITLE,
      HearthUpdateOffer.text(manifest.versionName),
      openApp(context),
    )
    if (shown) {
      HearthPrefs.updateOfferedVersionCode = manifest.versionCode.toLong()
      HearthPrefs.updateOfferedDay = today
    }
  }

  /**
   * Куда ведёт нажатие на уведомление.
   *
   * Уведомление «есть новая версия», по которому некуда нажать, отправляет человека
   * искать экран самостоятельно — а мы в тексте этот экран и называем.
   *
   * Точка входа берётся у системы по имени пакета, а не `Intent(context, MainActivity::class)`:
   * `MainActivity` лежит в модуле приложения, а этот файл — в общем модуле, и модуль
   * приложения зависит от него, а не наоборот. Ссылка на класс просто не собралась бы.
   */
  private fun openApp(context: Context): PendingIntent? = runCatching {
    val intent = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
    PendingIntent.getActivity(
      context,
      0,
      intent,
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
  }.getOrNull()

  private fun show(
    context: Context,
    title: String,
    text: String,
    contentIntent: PendingIntent? = null,
  ): Boolean = runCatching {
    val mgr = context.getSystemService(NotificationManager::class.java) ?: return false
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && mgr.getNotificationChannel(CHANNEL) == null) {
      mgr.createNotificationChannel(
        NotificationChannel(CHANNEL, "Обновление Очага", NotificationManager.IMPORTANCE_LOW).apply {
          description = "Загрузка новой версии приложения с домашнего узла"
          setShowBadge(false)
        }
      )
    }
    mgr.notify(
      NOTIFICATION_ID,
      NotificationCompat.Builder(context, CHANNEL)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle(title)
        .setContentText(text)
        .setStyle(NotificationCompat.BigTextStyle().bigText(text))
        .setOnlyAlertOnce(true)
        .setAutoCancel(true)
        .apply { if (contentIntent != null) setContentIntent(contentIntent) }
        .build(),
    )
    true
  }.getOrElse {
    Log.w("hearth", "предупреждение об обновлениях не показано: ${it.message}")
    false
  }

  // Тот же канал, что у загрузки: человеку это одна и та же тема, а лишний канал в
  // системных настройках — лишний переключатель, который однажды выключат не глядя.
  private const val CHANNEL = "hearth_update"
  private const val NOTIFICATION_ID = 4202
}

/**
 * Точка вызова из общего кода запуска (`platform/Core.kt`).
 *
 * Контекст берётся у приложения, а не передаётся параметром: у фонового блока
 * запуска его нет, а протаскивать `Context` через общий код означало бы править
 * дерево форка в нескольких местах вместо одного.
 */
actual suspend fun hearthCheckUpdatesQuietly() {
  HearthUpdates.checkQuietly(chat.simplex.common.platform.androidAppContext)
}
