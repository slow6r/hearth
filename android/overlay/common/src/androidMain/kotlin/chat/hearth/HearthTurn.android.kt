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
  // Хост берём из настроек устройства — из уже применённого bundle, — а не из
  // ответа, который собираемся проверять: иначе проверка подтверждала бы сама себя.
  // Источник ровно один и тот же, что у пина ICE перед звонком: хост релея. Раньше
  // здесь стоял адрес device API, и при разных именах device API и релея принятые
  // bundle'ом записи оказывались «чужими» на пути звонка. См. hearthOwnNodeHost.
  val trustedHost = hearthOwnNodeHost(
    HearthPrefs.bundleHost,
    ChatController.appPrefs.hearthUpdateHost.get(),
  )
  val refresher = HearthTurnRefresher(
    transport?.let(::AndroidTurnTransport),
    PrefsIceSink,
    trustedHost,
  )
  when (val result = refresher.refresh()) {
    is HearthTurnRefresh.Updated -> {
      // Строку про срок годности кладём туда, где её увидит человек (экран «Узел»).
      // Раньше она была бы только в логе, а лог семья не читает — поэтому сбитая дата
      // выглядела как «звонки иногда не проходят» и не связывалась ни с чем.
      // Здоровый ответ пишет null и тем самым стирает старое предупреждение.
      HearthPrefs.callNotice = result.notice
      Log.d("hearth", "ICE обновлены с узла: ${result.count} записей")
      result.notice?.let { Log.w("hearth", "срок ключей TURN: $it") }
    }
    is HearthTurnRefresh.NotConfigured -> Unit
    is HearthTurnRefresh.Failed ->
      // Не показываем человеку: старые креды могут быть ещё живы, а узел мог быть
      // недоступен ровно в момент запуска. Следующий запуск попробует снова.
      Log.w("hearth", "ICE не обновлены: ${result.reason}")
  }
}
