package chat.hearth

import chat.simplex.common.platform.settings

/**
 * Настройки Очага, которых нет в `AppPreferences` форка.
 *
 * # Почему отдельно, а не строкой рядом с `hearthLastManifestIssued`
 *
 * `AppPreferences` живёт в чужом файле (`SimpleXAPI.kt`), а правила этого репозитория
 * запрещают править дерево форка: всё наше лежит в overlay и потому переживает
 * ребейз без конфликтов. Хранилище при этом то же самое — тот же `settings`, те же
 * ключи в том же файле настроек, — так что ничего не раздваивается.
 *
 * Здесь отметки времени и хост своего узла. Секретов нет и быть не должно: они живут
 * в адресах серверов и в токене устройства.
 */
object HearthPrefs {

  /**
   * Когда телефон ВПЕРВЫЕ увидел текущую отметку манифеста, в днях эпохи.
   *
   * Обновляется только когда отметка ИЗМЕНИЛАСЬ. Это и есть единственная мера
   * свежести, которая переживает переведённые часы: сколько телефон уже прожил с
   * одним и тем же манифестом. Захваченный узел, показывающий один и тот же
   * подписанный манифест полугодовой давности, упирается именно в неё.
   */
  var manifestFirstSeenDay: Long?
    get() = readDay(MANIFEST_FIRST_SEEN_DAY)
    set(value) = writeDay(MANIFEST_FIRST_SEEN_DAY, value)

  /**
   * День последней УДАВШЕЙСЯ проверки обновлений.
   *
   * Без него молчание узла невидимо: телефон, месяцами не видевший обновлений,
   * выглядит нормально. См. [HearthUpdateTrust.isStale].
   */
  var lastUpdateCheckDay: Long?
    get() = readDay(LAST_UPDATE_CHECK_DAY)
    set(value) = writeDay(LAST_UPDATE_CHECK_DAY, value)

  /**
   * Сколько РАЗНЫХ дней после последнего ответа телефон стучался к узлу впустую.
   *
   * Без этого счётчика молчание узла считалось календарём, и телефон, который сам
   * неделю не выходил в сеть, обвинял узел: человека посылали к владельцу узла зря.
   * Считаются дни, а не попытки: приложение выходит на передний план много раз за день.
   */
  var failedUpdateCheckDays: Long
    get() = runCatching { settings.getLong(FAILED_CHECK_DAYS, 0L) }.getOrDefault(0L)
    set(value) {
      runCatching { settings.putLong(FAILED_CHECK_DAYS, value.coerceAtLeast(0L)) }
    }

  /** День последней НЕУДАЧНОЙ попытки: по нему счётчик растёт не чаще раза в день. */
  var lastFailedCheckDay: Long?
    get() = readDay(LAST_FAILED_CHECK_DAY)
    set(value) = writeDay(LAST_FAILED_CHECK_DAY, value)

  /**
   * День, когда человеку последний раз сказали о том, что обновления не проверяются.
   *
   * Отдельно от [staleNoticeDay]: там про молчание узла (само пройдёт, когда узел
   * оживёт), здесь про отказ, который сам не пройдёт, — нет ключа в сборке, не сошлась
   * подпись, вышел срок. Два разных повода и два разных счётчика, иначе одно
   * предупреждение глушило бы другое.
   */
  var updateProblemNoticeDay: Long?
    get() = readDay(UPDATE_PROBLEM_NOTICE_DAY)
    set(value) = writeDay(UPDATE_PROBLEM_NOTICE_DAY, value)

  /**
   * Какой `versionCode` уже объявляли человеку в шторке как доступный.
   *
   * Хранится именно версия, а не только день: повод здесь не длящийся, а сменяющийся.
   * Вышла версия новее объявленной — это новость, и ждать конца окна нельзя, иначе в
   * эту разницу попадёт security-релиз, выпущенный через день после обычного. Разбор —
   * [HearthUpdateOffer.shouldAnnounce].
   */
  var updateOfferedVersionCode: Long?
    get() = readDay(UPDATE_OFFERED_VERSION)
    set(value) = writeDay(UPDATE_OFFERED_VERSION, value)

  /** День, когда про эту версию сказали: тот же versionCode повторяем не чаще раза в окно. */
  var updateOfferedDay: Long?
    get() = readDay(UPDATE_OFFERED_DAY)
    set(value) = writeDay(UPDATE_OFFERED_DAY, value)

  /**
   * Узел ответил: забыть счёт неудачных дней.
   *
   * Счётчик меряет НЕПРЕРЫВНУЮ полосу молчания, а не сумму неудач за всю жизнь
   * телефона: иначе год редких обрывов однажды сложился бы в обвинение живому узлу.
   */
  fun noteCheckSucceeded(day: Long) {
    lastUpdateCheckDay = day
    failedUpdateCheckDays = 0
    lastFailedCheckDay = null
  }

  /**
   * До узла не дошли. Считаем день, а не попытку.
   *
   * Приложение выходит на передний план десятки раз за день, и три неудачи подряд бывают
   * за двадцать минут из-за одного перезагружающегося роутера. Обвинять узел за это
   * нельзя, поэтому в счёт идёт только первый промах за день.
   */
  fun noteCheckFailed(day: Long) {
    if (lastFailedCheckDay == day) return
    lastFailedCheckDay = day
    failedUpdateCheckDays = failedUpdateCheckDays + 1
  }

  /**
   * День, когда человеку последний раз сказали о молчании узла.
   *
   * Чтобы не превращать предупреждение в шум: одно уведомление на окно молчания, а не
   * одно на каждый запуск приложения. Предупреждение, которое видно каждый день,
   * перестают читать — и тогда оно не работает вовсе.
   */
  var staleNoticeDay: Long?
    get() = readDay(STALE_NOTICE_DAY)
    set(value) = writeDay(STALE_NOTICE_DAY, value)

  /**
   * Хост узла, на который указывал ПРИМЕНЁННЫЙ bundle.
   *
   * # Зачем ещё один хост, когда есть `hearthUpdateHost`
   *
   * `hearthUpdateHost` — это адрес device API узла, и его в bundle может не быть вовсе
   * (`node = null`). Тогда устройство оставалось без единого объявленного «своего хоста»,
   * и код добывал его из базы — из списка SMP-серверов. Так источник истины определялся
   * тем, что лежит в базе, а база приезжает с архивом восстановления, в том числе чужим.
   * Проверка «эта ссылка на нашем узле?» подтверждала сама себя.
   *
   * Здесь хост берётся из bundle, который человек отсканировал или ввёл кодом лично, —
   * и записывается ОДИН раз, в момент применения. Из базы он не выводится никогда.
   *
   * `null` — устройство не заводили на этом установленном приложении. Это значит
   * «своего узла не знаем», а не «возьмём первый попавшийся».
   */
  var bundleHost: String?
    get() = runCatching { settings.getString(BUNDLE_HOST, "") }.getOrDefault("").ifBlank { null }
    set(value) {
      runCatching {
        if (value.isNullOrBlank()) settings.remove(BUNDLE_HOST) else settings.putString(BUNDLE_HOST, value)
      }
    }

  /**
   * Список ICE из ПРИМЕНЁННОГО bundle, строками через перевод строки.
   *
   * # Зачем копия, когда есть `webrtcIceServers`
   *
   * `webrtcIceServers` — рабочая настройка: её перезаписывает каждое обновление кредов
   * TURN с узла, её же правит экран ручной правки ICE и приносит восстановленная база.
   * То есть это то, что МОЖЕТ оказаться чужим, и именно её проверяет пин перед звонком.
   *
   * Здесь лежит то, что пришло вместе с адресами релеев — из QR или кода доступа,
   * который человек получил лично. Это запасной источник на случай, когда в рабочей
   * настройке своих записей не осталось: без него единственным выходом был бы пустой
   * список ICE, а пустой список при relay-only означает «звонков нет вовсе».
   *
   * Секретов здесь не больше, чем в самой настройке ICE: те же строки уже лежат в
   * `webrtcIceServers`. Пароли релеев (`smp://`) сюда не попадают.
   *
   * `null` — bundle на этом установленном приложении не применяли.
   */
  var bundleIce: String?
    get() = runCatching { settings.getString(BUNDLE_ICE, "") }.getOrDefault("").ifBlank { null }
    set(value) {
      runCatching {
        if (value.isNullOrBlank()) settings.remove(BUNDLE_ICE) else settings.putString(BUNDLE_ICE, value)
      }
    }

  /**
   * Что сказать человеку про серверы для звонков.
   *
   * Отдельно от [callNotice]: там про срок годности ключей TURN, здесь про сам список
   * ICE (чужие записи, откат к списку из bundle, неподтверждённый список). Раньше эти
   * случаи не доходили до человека вовсе — они кончались молчаливым отказом звонка.
   *
   * `null` — говорить не о чем; здоровый выбор списка стирает строку сам.
   */
  var iceNotice: String?
    get() = runCatching { settings.getString(ICE_NOTICE, "") }.getOrDefault("").ifBlank { null }
    set(value) {
      runCatching {
        if (value.isNullOrBlank()) settings.remove(ICE_NOTICE) else settings.putString(ICE_NOTICE, value)
      }
    }

  /**
   * День, когда человек закрыл плашку «устройство не заведено на узле».
   *
   * Плашка закрываемая и возвращается сама через [HearthNodeSetup.SNOOZE_DAYS]. Днями,
   * а не «навсегда»: состояние настоящее и чинить его надо, но держать человека в нём
   * каждый день — значит приучить закрывать не читая.
   */
  var nodeNoticeSnoozeDay: Long?
    get() = readDay(NODE_NOTICE_SNOOZE_DAY)
    set(value) = writeDay(NODE_NOTICE_SNOOZE_DAY, value)

  /**
   * Что сказать человеку про звонки после последнего обновления ключей TURN.
   *
   * # Зачем это вообще хранить
   *
   * Обновление кредов идёт в фоне на старте — там некому ничего показать, и раньше его
   * вывод уходил только в лог. Поэтому расхождение часов выглядело как «звонки иногда
   * не проходят» и не связывалось ни с чем. Здесь лежит одна строка, и её показывает
   * экран «Узел» — единственное место, куда человека посылают, когда что-то не так.
   *
   * `null` — говорить не о чем; успешное обновление со здоровым сроком стирает строку
   * само, чтобы старое предупреждение не пережило починку.
   */
  var callNotice: String?
    get() = runCatching { settings.getString(CALL_NOTICE, "") }.getOrDefault("").ifBlank { null }
    set(value) {
      runCatching {
        if (value.isNullOrBlank()) settings.remove(CALL_NOTICE) else settings.putString(CALL_NOTICE, value)
      }
    }

  /**
   * Что сказать человеку про обновления после последней УДАВШЕЙСЯ проверки.
   *
   * Сегодня там бывает одно: «узел давно не публиковал нового». Это не отказ — клиент
   * продолжает ставить обновления, — но и не пустяк: ровно так выглядит узел, который
   * перестал раздавать security-релизы. Раньше этот случай был отказом и звучал как
   * «обновлений вам больше не будет».
   *
   * `null` — говорить не о чем; здоровая проверка стирает строку сама.
   */
  var updateNotice: String?
    get() = runCatching { settings.getString(UPDATE_NOTICE, "") }.getOrDefault("").ifBlank { null }
    set(value) {
      runCatching {
        if (value.isNullOrBlank()) settings.remove(UPDATE_NOTICE) else settings.putString(UPDATE_NOTICE, value)
      }
    }

  /**
   * Забыть всё, что телефон помнит про обновления.
   *
   * Зовётся при переводе устройства на ДРУГОЙ узел (`HearthCoreApplier.rememberBundleHost`):
   * отметки прежнего узла после переезда не просто бесполезны, а вредны — см. причину
   * там же. Отдельная функция, а не четыре присваивания на месте: забыть надо ВСЁ, а
   * забытое наполовину состояние хуже, чем не забытое вовсе.
   */
  fun forgetUpdateState() {
    manifestFirstSeenDay = null
    lastUpdateCheckDay = null
    staleNoticeDay = null
    updateNotice = null
    failedUpdateCheckDays = 0
    lastFailedCheckDay = null
    updateProblemNoticeDay = null
    updateOfferedVersionCode = null
    updateOfferedDay = null
  }

  private const val BUNDLE_HOST = "hearthBundleHost"
  private const val BUNDLE_ICE = "hearthBundleIce"
  private const val ICE_NOTICE = "hearthIceNotice"
  private const val NODE_NOTICE_SNOOZE_DAY = "hearthNodeNoticeSnoozeDay"
  private const val CALL_NOTICE = "hearthCallNotice"
  private const val UPDATE_NOTICE = "hearthUpdateNotice"
  private const val MANIFEST_FIRST_SEEN_DAY = "hearthManifestFirstSeenDay"
  private const val LAST_UPDATE_CHECK_DAY = "hearthLastUpdateCheckDay"
  private const val STALE_NOTICE_DAY = "hearthStaleNoticeDay"
  private const val FAILED_CHECK_DAYS = "hearthFailedUpdateCheckDays"
  private const val LAST_FAILED_CHECK_DAY = "hearthLastFailedUpdateCheckDay"
  private const val UPDATE_PROBLEM_NOTICE_DAY = "hearthUpdateProblemNoticeDay"
  private const val UPDATE_OFFERED_VERSION = "hearthUpdateOfferedVersion"
  private const val UPDATE_OFFERED_DAY = "hearthUpdateOfferedDay"

  /**
   * Значения нет.
   *
   * Отдельная константа, а не `0`: ноль — это 1 января 1970 года, вполне возможная
   * дата на телефоне с севшей батарейкой часов, и путать её с «не записано» нельзя.
   */
  private const val UNSET = Long.MIN_VALUE

  private fun readDay(key: String): Long? =
    // Любая осечка хранилища — это «не записано», а не падение на пути запуска.
    runCatching { settings.getLong(key, UNSET) }.getOrDefault(UNSET).takeIf { it != UNSET }

  private fun writeDay(key: String, value: Long?) {
    runCatching {
      if (value == null) settings.remove(key) else settings.putLong(key, value)
    }
  }
}
