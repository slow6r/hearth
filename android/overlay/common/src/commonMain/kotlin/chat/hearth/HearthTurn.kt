package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Свежие ICE-серверы с узла (ADR 0010).
 *
 * # Зачем это обязательно, а не «на всякий случай»
 *
 * Креды TURN — не пароль, а подпись с датой: coturn проверяет HMAC от строки со
 * временем истечения. Значит они **протухают по календарю**, и через
 * `turn.credential_ttl_secs` (на узле — 30 дней) перестают приниматься.
 *
 * Отказ при этом самый неприятный из возможных: сообщения продолжают ходить, потому
 * что им TURN не нужен, а звонки — как повезёт. Там, где оба собеседника пробиваются
 * напрямую, звонок идёт; там, где нужен ретранслятор, — тишина в трубке. Со стороны
 * это выглядит как «иногда работает», и искать причину будут в чём угодно, кроме
 * даты.
 *
 * Поэтому обновление кредов — не действие человека и не кнопка в настройках, а часть
 * запуска приложения.
 *
 * # Почему не увеличить срок
 *
 * Увеличенный срок отодвигает поломку, а не убирает её, и одновременно удлиняет окно,
 * в котором утёкшие креды остаются годными. С автообновлением всё наоборот: срок
 * можно **сократить**, и это одновременно надёжнее и строже.
 */
@Serializable
data class HearthTurnCredentials(
  val username: String,
  val credential: String,
  /** Строки ICE в том же виде, что в bundle: `stun:host:port`, `turn:user:cred@host:port`. */
  val ice: List<String>,
  val expires: String = "",
) {
  companion object {
    private val json = Json {
      ignoreUnknownKeys = true
      isLenient = false
    }

    fun parse(payload: String): Result<HearthTurnCredentials> = runCatching {
      val creds = json.decodeFromString(serializer(), payload)
      require(creds.ice.isNotEmpty()) { "узел вернул пустой список ICE" }
      // Пустой список записать в настройки хуже, чем не трогать их вовсе: старые
      // креды хотя бы могут быть ещё живы, а пустой ICE — гарантированная тишина.
      require(creds.ice.none { it.contains("\n") }) { "в строке ICE перевод строки" }
      creds
    }
  }
}

/** Транспорт до узла за свежими кредами. Предъявляет токен УЖЕ заведённого устройства. */
interface HearthTurnTransport {
  suspend fun turnCredentials(): Result<String>
}

/** Куда положить обновлённый список. Платформенная запись в настройки клиента. */
interface HearthIceSink {
  suspend fun setIceServers(ice: List<String>)
}

/** Чем закончилось обновление — для лога, не для экрана. */
sealed interface HearthTurnRefresh {
  data class Updated(val count: Int) : HearthTurnRefresh
  /** Узел не настроен: устройство ещё не заведено, обновлять нечего. */
  data object NotConfigured : HearthTurnRefresh
  data class Failed(val reason: String) : HearthTurnRefresh
}

/**
 * Обновить ICE-серверы.
 *
 * Тихая операция: человеку она не показывается ни успехом, ни неудачей. Неудача не
 * повод для тревоги — узел мог быть недоступен ровно в момент запуска, а старые креды
 * ещё живы. Настройки при неудаче не трогаем.
 */
class HearthTurnRefresher(
  private val transport: HearthTurnTransport?,
  private val sink: HearthIceSink,
) {
  suspend fun refresh(): HearthTurnRefresh {
    val transport = transport ?: return HearthTurnRefresh.NotConfigured
    val payload = transport.turnCredentials().getOrElse { e ->
      return HearthTurnRefresh.Failed(e.message ?: "узел недоступен")
    }
    val creds = HearthTurnCredentials.parse(payload).getOrElse { e ->
      return HearthTurnRefresh.Failed(e.message ?: "ответ узла не разобран")
    }
    return runCatching {
      sink.setIceServers(creds.ice)
      HearthTurnRefresh.Updated(creds.ice.size) as HearthTurnRefresh
    }.getOrElse { e -> HearthTurnRefresh.Failed(e.message ?: "не удалось записать настройки") }
  }
}

/**
 * Обновить ICE при запуске приложения.
 *
 * Вызывается из точки старта чата, а не из экрана: экран настроек человек может не
 * открыть ни разу за год, а звонки должны работать всё это время.
 */
expect suspend fun hearthRefreshIceServers()
