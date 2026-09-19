package chat.hearth

import chat.simplex.common.model.AddressSettings
import chat.simplex.common.model.ChatController
import chat.simplex.common.model.ChatDeleteMode
import chat.simplex.common.model.ChatInfo
import chat.simplex.common.model.ChatType
import chat.simplex.common.model.CreatedConnLink
import chat.simplex.common.model.UserContactLinkRec
import chat.simplex.common.platform.Log
import chat.simplex.common.platform.chatModel

/**
 * Держать телефон на серверах своего узла.
 *
 * # Что было
 *
 * Ядро SimpleX знает своих операторов — SimpleX Chat и Flux — и их серверы. Импорт
 * bundle операторов выключает. Но включить их обратно умеет не только человек в
 * настройках: экран условий в онбординге при нажатии «Принять» включает операторов,
 * отмеченных на нём по умолчанию. Телефон, прошедший этот экран, создавал очереди на
 * серверах SimpleX, хотя на узле был заведён и выглядел настроенным. Узнали по живым
 * ссылкам — в них стоял хост smp8.simplex.im, — и по узлу: на нашем релее за всё время
 * одна очередь, ноль подписок, ноль сообщений.
 *
 * # Что делаем
 *
 * Выключаем всех операторов сразу после применения bundle и при каждом запуске
 * заведённого устройства. Команда ядра `APISetServerOperators` тут же пересобирает
 * списки серверов агента для всех профилей, так что перезапуск не нужен.
 *
 * Уже созданное это не переносит само: адрес и неиспользованные приглашения, выданные
 * до исправления, остаются на тех серверах, где были созданы. Их заменяет
 * [hearthCleanUpForeignLinks].
 *
 * # Откуда берётся «заведено»
 *
 * Раньше — только из префа `hearthDeviceId`. Преф лежит в настройках устройства, а
 * серверы — в базе, и восстановление архива переносит вторые без первого. Теперь
 * решение принимает [hearthBringUpPlan] по трём признакам сразу, и «в базе есть свои
 * серверы» — полноправный из них.
 */

/** Выключить всех операторов. `true`, если какой-то был включён и выключился. */
suspend fun hearthDisableOperators(): Boolean {
  val rh = chatModel.remoteHostId()
  val detail = ChatController.getServerOperators(rh) ?: return false
  val wasEnabled = detail.serverOperators.filter { it.enabled }
  if (wasEnabled.isEmpty()) return false
  val updated = ChatController.setServerOperators(rh, detail.serverOperators.map { it.copy(enabled = false) })
  if (updated == null) {
    Log.e("hearth", "операторы не выключились: ядро отказало")
    return false
  }
  chatModel.conditions.value = updated
  Log.w("hearth", "выключены операторы: ${wasEnabled.joinToString { it.operatorId.toString() }}")
  return true
}

/**
 * Выключить операторов там, где это уместно.
 *
 * Уместность решает [hearthBringUpPlan], а не один преф. Ключевая оговорка прежняя и
 * теперь записана кодом: на ЧИСТОЙ установке выключать операторов нельзя — своих
 * серверов ещё нет, и телефон остался бы вовсе без серверов, с ошибкой вместо экрана
 * настройки. А вот восстановленная из архива база свои серверы уже содержит, и там
 * ждать заведения на узле незачем.
 */
suspend fun hearthEnforceOwnServers(): HearthStepOutcome = runCatching {
  val plan = hearthCurrentBringUpPlan()
  if (HearthBringUpStep.DisableOperators !in plan) {
    return@runCatching HearthStepOutcome.NotApplicable
  }
  hearthDisableOperators()
  HearthStepOutcome.Done
}.getOrElse { e ->
  Log.e("hearth", "не удалось проверить операторов: ${e.message}")
  HearthStepOutcome.Failed
}

/**
 * Перевести свой релей на порт 443 у уже настроенного телефона (см. HearthRelayPort.kt).
 *
 * Работает локально — в сеть не ходит, узел для этого не нужен. Именно поэтому
 * телефону в сети, которая режет 5223, достаточно поставить обновление файлом:
 * до узла он ещё не достаёт, а достать должен как раз после этого шага.
 */
suspend fun hearthMigrateRelayToWebPort(): HearthStepOutcome {
  if (HearthBringUpStep.MigrateRelayPort !in hearthCurrentBringUpPlan()) {
    return HearthStepOutcome.NotApplicable
  }
  val host = hearthRelayHost() ?: return HearthStepOutcome.NotApplicable
  val rh = chatModel.remoteHostId()
  val current = ChatController.getUserServers(rh) ?: return HearthStepOutcome.Failed
  var changed = false
  val updated = current.map { entry ->
    if (entry.operator != null) entry
    else entry.copy(smpServers = entry.smpServers.map { srv ->
      val moved = if (srv.deleted) null else hearthRelayAddressOnWebPort(srv.server, host)
      if (moved == null) srv else {
        changed = true
        // serverId сохраняем: ядро обновит ту же запись, а не заведёт вторую рядом.
        srv.copy(server = moved, tested = null)
      }
    })
  }
  // Переводить нечего — это сделанная работа, а не осечка: повторять её незачем.
  if (!changed) return HearthStepOutcome.Done
  val errors = ChatController.validateServers(rh, updated)?.first.orEmpty()
  if (errors.isNotEmpty()) {
    Log.e("hearth", "перевод на 443 отвергнут ядром: ${errors.joinToString()}")
    return HearthStepOutcome.Failed
  }
  if (!ChatController.setUserServers(rh, updated)) return HearthStepOutcome.Failed
  // Пересобрать серверы агента сразу, не дожидаясь перезапуска.
  hearthDisableOperators()
  Log.w("hearth", "свой релей переведён на порт $HEARTH_RELAY_WEB_PORT")
  return HearthStepOutcome.Done
}

/**
 * Заменить то, что осталось на чужих серверах: адрес и незавершённые приглашения.
 *
 * Идёт в сеть — удаление очереди это команда её серверу, — поэтому запускается в
 * фоне и не мешает старту. Неудача не страшна: следующий запуск попробует снова.
 */
suspend fun hearthCleanUpForeignLinks() {
  if (HearthBringUpStep.CleanUpForeignLinks !in hearthCurrentBringUpPlan()) return
  val host = hearthRelayHost() ?: return
  runCatching { replaceForeignAddress(host) }
    .onFailure { Log.e("hearth", "адрес не заменён: ${it.message}") }
  runCatching { dropForeignInvitations(host) }
    .onFailure { Log.e("hearth", "приглашения не удалены: ${it.message}") }
}

private suspend fun replaceForeignAddress(host: String) {
  val address = chatModel.userAddress.value ?: return
  if (address.connLinkContact.isOn(host)) return
  val rh = chatModel.remoteHostId()
  // Сначала удалить: у профиля один адрес, второй ядро не создаст.
  ChatController.apiDeleteUserAddress(rh) ?: run {
    Log.w("hearth", "старый адрес на чужом сервере не удалился — попробуем при следующем запуске")
    return
  }
  chatModel.userAddress.value = null
  val created = ChatController.apiCreateUserAddress(rh) ?: return
  val shortLink = created.connShortLink != null
  // Так же, как экран адреса после «Создать адрес».
  chatModel.userAddress.value = UserContactLinkRec(
    created,
    shortLinkDataSet = shortLink,
    shortLinkLargeDataSet = shortLink,
    addressSettings = AddressSettings(businessAddress = false, autoAccept = null, autoReply = null),
  )
  Log.w("hearth", "адрес на чужом сервере заменён адресом на своём узле")
}

private suspend fun dropForeignInvitations(host: String) {
  val rh = chatModel.remoteHostId()
  // Только те, что создали мы сами (у них есть ссылка) и не на своём узле. Входящие
  // запросы на соединение ссылки не имеют — их не трогаем.
  val foreign = chatModel.chats.value.mapNotNull { chat ->
    (chat.chatInfo as? ChatInfo.ContactConnection)?.contactConnection
  }.filter { pcc -> pcc.connLinkInv?.let { !it.isOn(host) } == true }
  for (pcc in foreign) {
    runCatching {
      ChatController.apiDeleteChat(rh, ChatType.ContactConnection, pcc.pccConnId, ChatDeleteMode.Full(notify = false))
    }
  }
  if (foreign.isNotEmpty()) Log.w("hearth", "удалено приглашений на чужих серверах: ${foreign.size}")
}

/**
 * Лежит ли ссылка на своём узле.
 *
 * Разбор — общий ([hearthLinksAreOn]), а не «содержит подстроку», как было. Подстрока
 * ошибалась в опасную сторону: `smp://…@myhearth.example.com.evil.net` считался своим.
 */
private fun CreatedConnLink.isOn(host: String): Boolean =
  hearthLinksAreOn(listOfNotNull(connShortLink, connFullLink), host)

/**
 * Нужен ли этому устройству экран узла, прежде чем им можно пользоваться.
 *
 * Отдельная функция, а не проверка префа в ветке запуска: восстановленная из архива
 * база приносит профиль и серверы, но НЕ приносит `hearthDeviceId`. Ветка запуска
 * решала по одному признаку «профиля нет», поэтому такое устройство проходило мимо
 * экрана узла — с чужими серверами и без учёта на узле. Решение принимает
 * [hearthBringUpPlan], то же самое, что и у остальных шагов приведения: иначе они
 * снова разойдутся во мнении, как уже расходились.
 *
 * Стоит денег ровно один локальный запрос списка серверов у ядра — в сеть здесь никто
 * не ходит.
 */
suspend fun hearthNeedsNodeOnboarding(): Boolean =
  HearthBringUpStep.Onboarding in hearthCurrentBringUpPlan()

/**
 * Что делать с этим устройством прямо сейчас.
 *
 * Все три признака берутся в одном месте, чтобы шаги не расходились во мнении: один
 * решал по префу, другой по базе — так и появилась дыра с восстановлением архива.
 */
internal suspend fun hearthCurrentBringUpPlan(): Set<HearthBringUpStep> = hearthBringUpPlan(
  enrolled = hearthEnrolled(),
  dbHasUser = chatModel.currentUser.value != null,
  dbHasOwnServers = hearthOwnServersInDb().isNotEmpty(),
)

private fun hearthEnrolled(): Boolean = !ChatController.appPrefs.hearthDeviceId.get().isNullOrBlank()

/**
 * Хост своего релея.
 *
 * # Почему только из объявленного, и никогда из базы
 *
 * Раньше при пустом `hearthUpdateHost` хост выводился из базы — брался первый НЕ
 * операторский SMP-сервер. Довод был про восстановление архива: серверы приезжают с
 * архивом, а преф нет. Но из этого же и следует дыра: «свой узел» определялся тем, что
 * лежит в базе, а база могла приехать ЧУЖИМ архивом. Тогда чужой релей объявлял себя
 * своим — и [hearthCleanUpForeignLinks], чья работа как раз в том, чтобы отличать своё
 * от чужого, послушно удаляла НАШИ ссылки и оставляла чужие. Проверка подтверждала
 * сама себя.
 *
 * Теперь источник истины ровно один и он объявлен: хост релея из применённого bundle
 * ([HearthPrefs.bundleHost]) — то, что человек лично отсканировал или ввёл кодом.
 * Адрес device API (`hearthUpdateHost`) остаётся лишь запасным, для устройств,
 * заведённых сборкой, где bundleHost ещё не писался. Ни один из них из базы не
 * выводится. Правило общее на весь клиент и живёт в [hearthOwnNodeHost].
 *
 * # Чем это платит семья
 *
 * `null` означает «своего узла не знаем», и шаги, которые на него опираются, молча не
 * выполняются. Связь при этом не ломается: без хоста не делаются только перевод релея
 * на 443 и чистка чужих ссылок, а сообщения и звонки идут по тому, что уже записано в
 * ядре. Устройство в этом состоянии и так не заведено (`hearthDeviceId` пуст — оба
 * префа пишутся одним и тем же применением bundle), поэтому [hearthBringUpPlan] уже
 * ведёт его на экран узла: там оно получит и хост, и учёт.
 */
private fun hearthRelayHost(): String? =
  hearthOwnNodeHost(HearthPrefs.bundleHost, ChatController.appPrefs.hearthUpdateHost.get())

/** Адреса не операторских SMP-серверов из базы. Пусто — своих серверов нет. */
private suspend fun hearthOwnServersInDb(): List<String> {
  val rh = chatModel.remoteHostId()
  val servers = runCatching { ChatController.getUserServers(rh) }.getOrNull() ?: return emptyList()
  return servers
    .filter { it.operator == null }
    .flatMap { entry -> entry.smpServers.filter { !it.deleted }.map { it.server } }
}
