package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * Дубли чатов не доходят до списка.
 *
 * Тест написан по крэшу из семьи: `Key "(null, @2)" was already used` — два чата с
 * одним ключом в `LazyColumn`. Ключ здесь тот же, что у списка: пара
 * (remoteHostId, id), и остаётся первое вхождение.
 */
class HearthChatListTest {

  private data class Chat(val rh: Long?, val id: String, val unread: Int = 0)

  @Test
  fun the_family_crash_two_at_2_become_one() {
    val list = listOf(Chat(null, "@2", unread = 3), Chat(null, "@5"), Chat(null, "@2"))
    val out = HearthChatList.dedupe(list) { it.rh to it.id }
    assertEquals(listOf(Chat(null, "@2", unread = 3), Chat(null, "@5")), out)
  }

  @Test
  fun first_occurrence_wins_and_keeps_its_counters() {
    val list = listOf(Chat(null, "@1", unread = 7), Chat(null, "@1", unread = 0))
    assertEquals(7, HearthChatList.dedupe(list) { it.rh to it.id }.single().unread)
  }

  @Test
  fun same_id_on_different_hosts_is_two_chats() {
    val list = listOf(Chat(null, "@2"), Chat(1L, "@2"))
    assertEquals(2, HearthChatList.dedupe(list) { it.rh to it.id }.size)
  }

  @Test
  fun a_clean_list_is_returned_as_is() {
    val list = listOf(Chat(null, "@1"), Chat(null, "@2"), Chat(null, "#3"))
    assertSame(list, HearthChatList.dedupe(list) { it.rh to it.id })
  }

  @Test
  fun order_is_preserved() {
    val list = listOf(Chat(null, "#9"), Chat(null, "@2"), Chat(null, "#9"), Chat(null, "@1"))
    assertEquals(listOf("#9", "@2", "@1"), HearthChatList.dedupe(list) { it.rh to it.id }.map { it.id })
  }
}
