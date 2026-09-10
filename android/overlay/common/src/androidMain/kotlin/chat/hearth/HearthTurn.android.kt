package chat.hearth

import chat.simplex.common.model.ChatController
import chat.simplex.common.platform.Log

/**
 * Android-реализация обновления ICE.
 *
 * Транспорт — тот же [HearthAndroidUpdateTransport], что ходит за обновлениями: адрес
 * узла и токен устройства у него уже есть, второй такой класс был бы копией.
 */
private class AndroidTurnTransport(
  private val transport: HearthAndroidUpdateTransport,
) : HearthTurnTransport {
  override suspend fun turnCredentials(): Result<String> = transport.turnCredentials()
}

private object PrefsIceSink : HearthIceSink {
  override suspend fun setIceServers(ice: List<String>) {
    // Тот же формат, что пишет импорт bundle: строки через перевод строки.
    ChatController.appPrefs.webrtcIceServers.set(ice.joinToString(separator = "\n"))
  }
}

actual suspend fun hearthRefreshIceServers() {
  val context = chat.simplex.common.platform.androidAppContext
  val transport = HearthAndroidUpdateTransport.fromPrefs(context)
  val refresher = HearthTurnRefresher(transport?.let(::AndroidTurnTransport), PrefsIceSink)
  when (val result = refresher.refresh()) {
    is HearthTurnRefresh.Updated ->
      Log.d("hearth", "ICE обновлены с узла: ${result.count} записей")
    is HearthTurnRefresh.NotConfigured -> Unit
    is HearthTurnRefresh.Failed ->
      // Не показываем человеку: старые креды могут быть ещё живы, а узел мог быть
      // недоступен ровно в момент запуска. Следующий запуск попробует снова.
      Log.w("hearth", "ICE не обновлены: ${result.reason}")
  }
}
