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
 * То же, но только для устройства, заведённого на узле.
 *
 * Незаведённое не трогаем: без bundle у него нет своих серверов, и выключение
 * операторов оставило бы его вовсе без серверов — с ошибкой вместо экрана настройки.
 */
suspend fun hearthEnforceOwnServers(): Boolean {
  if (!hearthEnrolled()) return false
  return runCatching { hearthDisableOperators() }.getOrElse { e ->
    Log.e("hearth", "не удалось проверить операторов: ${e.message}")
    false
  }
}

/**
 * Перевести свой релей на порт 443 у уже настроенного телефона (см. HearthRelayPort.kt).
 *
 * Работает локально — в сеть не ходит, узел для этого не нужен. Именно поэтому
 * телефону в сети, которая режет 5223, достаточно поставить обновление файлом:
 * до узла он ещё не достаёт, а достать должен как раз после этого шага.
 */
suspend fun hearthMigrateRelayToWebPort(): Boolean {
  if (!hearthEnrolled()) return false
  val host = hearthRelayHost() ?: return false
  val rh = chatModel.remoteHostId()
  val current = ChatController.getUserServers(rh) ?: return false
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
  if (!changed) return false
  val errors = ChatController.validateServers(rh, updated)?.first.orEmpty()
  if (errors.isNotEmpty()) {
    Log.e("hearth", "перевод на 443 отвергнут ядром: ${errors.joinToString()}")
    return false
  }
  if (!ChatController.setUserServers(rh, updated)) return false
  // Пересобрать серверы агента сразу, не дожидаясь перезапуска.
  hearthDisableOperators()
  Log.w("hearth", "свой релей переведён на порт $HEARTH_RELAY_WEB_PORT")
  return true
}

/**
 * Заменить то, что осталось на чужих серверах: адрес и незавершённые приглашения.
 *
 * Идёт в сеть — удаление очереди это команда её серверу, — поэтому запускается в
 * фоне и не мешает старту. Неудача не страшна: следующий запуск попробует снова.
 */
suspend fun hearthCleanUpForeignLinks() {
  if (!hearthEnrolled()) return
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

/** Лежит ли ссылка на своём узле. Хост есть и в короткой ссылке, и внутри полной. */
private fun CreatedConnLink.isOn(host: String): Boolean =
  listOfNotNull(connShortLink, connFullLink).any { it.contains(host, ignoreCase = true) }

private fun hearthEnrolled(): Boolean = !ChatController.appPrefs.hearthDeviceId.get().isNullOrBlank()

/** Хост своего релея — тот же, что у device API узла, пришёл с bundle. */
private fun hearthRelayHost(): String? = ChatController.appPrefs.hearthUpdateHost.get()?.ifBlank { null }
