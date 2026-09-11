package chat.hearth

import chat.simplex.common.model.ChatController
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
 * Уже созданное это не переносит: адрес и неиспользованные приглашения, выданные до
 * исправления, остаются на тех серверах, где были созданы. Их надо удалить и создать
 * заново.
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
  if (ChatController.appPrefs.hearthDeviceId.get().isNullOrBlank()) return false
  return runCatching { hearthDisableOperators() }.getOrElse { e ->
    Log.e("hearth", "не удалось проверить операторов: ${e.message}")
    false
  }
}
