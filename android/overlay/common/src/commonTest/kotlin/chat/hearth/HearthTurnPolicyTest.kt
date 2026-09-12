package chat.hearth

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Обновление TURN-кредов проверяется так же строго, как bundle.
 *
 * Разница в источнике принципиальна: bundle человек сканирует лично, а креды
 * приходят от узла по сети — то есть от стороны, которую мы и не считаем доверенной
 * после захвата. Раньше здесь проверялись только непустота и отсутствие перевода
 * строки, и захваченный узел мог увести звонки на чужой TURN.
 */
class HearthTurnPolicyTest {

  private val host = "relay.myhearth.ru"

  private fun payload(vararg ice: String): String =
    """{"username":"u","credential":"c","ice":[${ice.joinToString(",") { "\"$it\"" }}]}"""

  @Test
  fun our_own_turn_is_accepted() {
    val creds = HearthTurnCredentials
      .parse(payload("stun:$host:3478", "turn:u:c@$host:3478"), host)
      .getOrThrow()
    assertTrue(creds.ice.size == 2)
  }

  @Test
  fun a_foreign_turn_is_refused() {
    // Главный случай: узел захвачен и уводит звонки через чужой сервер, которому
    // достаются адреса обоих собеседников.
    val result = HearthTurnCredentials.parse(payload("turn:u:c@evil.example:3478"), host)
    assertTrue(result.isFailure)
  }

  @Test
  fun a_public_stun_is_refused() {
    val result = HearthTurnCredentials.parse(payload("stun:stun.l.google.com:19302"), host)
    assertTrue(result.isFailure)
  }

  @Test
  fun one_foreign_entry_poisons_the_whole_list() {
    // Частично чужой список — тот же провал: клиент выберет наилучший маршрут сам.
    val result = HearthTurnCredentials.parse(
      payload("stun:$host:3478", "turn:u:c@evil.example:3478"),
      host,
    )
    assertTrue(result.isFailure)
  }

  @Test
  fun an_empty_list_is_refused() {
    assertTrue(HearthTurnCredentials.parse("""{"username":"u","credential":"c","ice":[]}""", host).isFailure)
  }

  @Test
  fun without_a_known_host_the_old_behaviour_stays() {
    // Устройство, не знающее своего узла, не должно терять креды вовсе.
    assertTrue(HearthTurnCredentials.parse(payload("stun:$host:3478"), null).isSuccess)
  }
}
