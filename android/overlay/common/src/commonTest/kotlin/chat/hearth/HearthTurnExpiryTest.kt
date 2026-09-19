package chat.hearth

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Срок годности TURN-кредов.
 *
 * Поле `expires` узел присылал всегда, а клиент не читал его ни разу. Потом прочитал —
 * и стал ОТВЕРГАТЬ ответ при `at <= now`. Это оказалось хуже исходного молчания: узел
 * выдаёт креды на 30 суток, поэтому «просрочено» на свежем ответе означает не мёртвые
 * креды, а убежавшие часы телефона, и семья теряла звонки без единого объяснения.
 *
 * Здесь закреплено то, к чему пришли: ответ узла записывается всегда, а три случая —
 * «срок в порядке», «креды просрочены», «часы телефона расходятся с узлом» — различаются
 * и доходят до человека словами. Жёсткими остались проверки, которые действительно
 * что-то охраняют: чужой хост в ICE и непонятный формат срока.
 */
class HearthTurnExpiryTest {

  private val host = "relay.example.org"
  private val now = hearthEpochSecondsOf("2026-09-12T12:00:00Z")!!

  private fun payload(expires: String) = """
    {"username":"1757160000","credential":"aGVhcnRo",
     "ice":["stun:$host:3478","turn:1757160000:aGVhcnRo@$host:3478"],
     "expires":"$expires"}
  """.trimIndent()

  @Test
  fun credentials_that_are_still_alive_are_accepted() {
    val creds = HearthTurnCredentials.parse(payload("2026-10-12T12:00:00Z"), host).getOrThrow()
    assertEquals(2, creds.ice.size)
  }

  @Test
  fun expired_credentials_are_explained_not_refused() {
    // Раньше это был отказ, и он тихо убивал звонки. Отказ тут ничего не охраняет:
    // маршрут медиа держит пин по хосту, мёртвый пропуск coturn отвергнет сам, а
    // лежащие в настройках старые креды выданы РАНЬШЕ этих — то есть протухли вернее.
    val creds = HearthTurnCredentials.parse(payload("2026-09-12T11:59:59Z"), host).getOrThrow()
    val state = creds.freshness(now)
    assertTrue(state is HearthTurnFreshness.Expired, "получено: $state")
    // Текст обязан быть действием, а не диагнозом.
    assertTrue((state as HearthTurnFreshness.Expired).message.contains("владельцу узла"), state.message)
  }

  @Test
  fun a_clock_that_ran_ahead_is_named_as_the_clock() {
    // Узел выдаёт креды на 30 суток. Если свежий ответ выглядит просроченным БОЛЬШЕ чем
    // на этот срок, узел такого выдать не мог — значит вперёд убежали часы телефона.
    val creds = HearthTurnCredentials.parse(payload("2026-06-01T00:00:00Z"), host).getOrThrow()
    val state = creds.freshness(now)
    assertTrue(state is HearthTurnFreshness.ClockDisagrees, "получено: $state")
    assertTrue((state as HearthTurnFreshness.ClockDisagrees).message.contains("дату"), state.message)
  }

  @Test
  fun a_clock_that_fell_behind_is_named_too() {
    // Зеркальный случай: срок дальше в будущее, чем узел вообще выдаёт. Телефон с
    // севшей батарейкой часов увидит именно это.
    val creds = HearthTurnCredentials.parse(payload("2026-11-12T12:00:00Z"), host).getOrThrow()
    val state = creds.freshness(now)
    assertTrue(state is HearthTurnFreshness.ClockDisagrees, "получено: $state")
    assertTrue((state as HearthTurnFreshness.ClockDisagrees).message.contains("дату"), state.message)
  }

  @Test
  fun a_live_deadline_says_nothing_at_all() {
    val creds = HearthTurnCredentials.parse(payload("2026-10-12T12:00:00Z"), host).getOrThrow()
    assertEquals(HearthTurnFreshness.Fresh, creds.freshness(now))
    // Срока нет — тоже не событие: узлы прежних версий его не присылают.
    assertEquals(HearthTurnFreshness.Fresh, HearthTurnCredentials.parse(payload(""), host).getOrThrow().freshness(now))
  }

  @Test
  fun an_unreadable_expiry_is_refused() {
    // «Поля нет» и «поле есть, и оно не то» — разные вещи. Второе спускать нельзя.
    val result = HearthTurnCredentials.parse(payload("скоро"), host)
    assertTrue(result.isFailure)
    assertTrue(result.exceptionOrNull()?.message.orEmpty().contains("непонятный"), "${result.exceptionOrNull()}")
  }

  @Test
  fun a_missing_expiry_is_still_accepted() {
    // Узлы прежних версий срок не присылают, и отказ оставил бы их без звонков вовсе.
    assertTrue(HearthTurnCredentials.parse(payload(""), host).isSuccess)
  }

  @Test
  fun an_offset_timestamp_is_compared_by_the_moment_not_by_the_string() {
    // 2026-09-12T14:30:00+03:00 — это 11:30 UTC, то есть УЖЕ просрочено, хотя строка
    // лексикографически больше «2026-09-12T12:00:00Z».
    val creds = HearthTurnCredentials.parse(payload("2026-09-12T14:30:00+03:00"), host).getOrThrow()
    assertTrue(creds.freshness(now) is HearthTurnFreshness.Expired, "${creds.freshness(now)}")
  }

  @Test
  fun the_parser_no_longer_needs_a_clock_at_all() {
    // Разбор больше не судит возраст — судит [freshness], и часы нужны только ей.
    // Разбор смотрит на то, что от часов не зависит: формат, хост, непустоту списка.
    assertTrue(HearthTurnCredentials.parse(payload("2020-01-01T00:00:00Z"), host).isSuccess)
    // Но неразобранный срок он по-прежнему отвергает, и тоже без часов.
    assertTrue(HearthTurnCredentials.parse(payload("скоро"), host).isFailure)
  }

  @Test
  fun renewal_starts_a_day_before_the_deadline() {
    val soon = HearthTurnCredentials.parse(payload("2026-09-13T11:00:00Z"), host).getOrThrow()
    assertTrue(soon.expiresSoon(now))
    val later = HearthTurnCredentials.parse(payload("2026-09-20T12:00:00Z"), host).getOrThrow()
    assertFalse(later.expiresSoon(now))
    // Срока нет — значит неизвестно, когда протухнет: это тоже повод обновить.
    assertTrue(HearthTurnCredentials.parse(payload(""), host).getOrThrow().expiresSoon(now))
  }

  @Test
  fun a_bad_deadline_does_not_cost_the_family_its_calls() = runBlocking {
    // Раньше тут был отказ, и настройки не трогались вовсе. На телефоне с убежавшей
    // датой это означало: узел отдаёт живые креды, телефон их отвергает, звонки не
    // проходят, объяснения нет. Теперь свежий ответ узла записывается, а человеку
    // остаётся строка с тем, что проверить.
    var written: List<String>? = null
    val refresher = HearthTurnRefresher(
      transport = object : HearthTurnTransport {
        override suspend fun turnCredentials() = Result.success(payload("2026-09-01T00:00:00Z"))
      },
      sink = object : HearthIceSink {
        override suspend fun setIceServers(ice: List<String>) {
          written = ice
        }
      },
      expectedHost = host,
      nowEpochSeconds = { now },
    )

    val result = refresher.refresh()

    assertTrue(result is HearthTurnRefresh.Updated, "получено: $result")
    assertNotNull((result as HearthTurnRefresh.Updated).notice, "человеку не сказали ничего")
    assertEquals(2, written?.size)
  }

  @Test
  fun a_foreign_turn_still_never_reaches_the_settings() = runBlocking {
    // Смягчили именно срок годности, а не пин по хосту: маршрут медиа по-прежнему
    // держится жёстко, иначе звонок ушёл бы через чужой сервер.
    var written: List<String>? = null
    val refresher = HearthTurnRefresher(
      transport = object : HearthTurnTransport {
        override suspend fun turnCredentials() = Result.success(
          """{"username":"u","credential":"c","ice":["turn:u:c@evil.example:3478"],"expires":"2026-10-12T12:00:00Z"}"""
        )
      },
      sink = object : HearthIceSink {
        override suspend fun setIceServers(ice: List<String>) {
          written = ice
        }
      },
      expectedHost = host,
      nowEpochSeconds = { now },
    )

    assertTrue(refresher.refresh() is HearthTurnRefresh.Failed)
    assertNull(written, "чужой TURN записан в настройки")
  }

  @Test
  fun live_credentials_do_reach_the_settings() = runBlocking {
    var written: List<String>? = null
    val refresher = HearthTurnRefresher(
      transport = object : HearthTurnTransport {
        override suspend fun turnCredentials() = Result.success(payload("2026-10-12T12:00:00Z"))
      },
      sink = object : HearthIceSink {
        override suspend fun setIceServers(ice: List<String>) {
          written = ice
        }
      },
      expectedHost = host,
      nowEpochSeconds = { now },
    )

    assertEquals(HearthTurnRefresh.Updated(2), refresher.refresh())
    assertEquals(2, written?.size)
  }

  @Test
  fun a_refresher_without_a_trusted_host_writes_but_says_so() = runBlocking {
    // Хост у HearthTurnRefresher был необязательным параметром с умолчанием `null`.
    // Продуктовый путь его передавал, но получить обновление ICE вообще без пина можно
    // было, просто не дописав аргумент. Теперь параметр обязателен — отсутствие хоста
    // пишется буквой, вот этой строчкой ниже, — а сам случай перестал быть беззвучным:
    // чужие записи узла проходят в настройки, и человеку про это сказано.
    var written: List<String>? = null
    val refresher = HearthTurnRefresher(
      transport = object : HearthTurnTransport {
        override suspend fun turnCredentials() = Result.success(
          """{"username":"u","credential":"c","ice":["turn:u:c@other.example:3478"],"expires":"2026-10-12T12:00:00Z"}"""
        )
      },
      sink = object : HearthIceSink {
        override suspend fun setIceServers(ice: List<String>) {
          written = ice
        }
      },
      expectedHost = null,
      nowEpochSeconds = { now },
    )

    val result = refresher.refresh()

    assertTrue(result is HearthTurnRefresh.Updated, "получено: $result")
    assertEquals(1, written?.size, "устройство без хоста узла не должно остаться без ICE")
    assertEquals(
      HearthTurnRefresher.UNPINNED_NOTICE,
      (result as HearthTurnRefresh.Updated).notice,
      "непроверенный список записан молча",
    )
  }

  @Test
  fun a_trusted_host_keeps_the_ordinary_answer_quiet() {
    // Обратная половина: на обычном устройстве новая строка не появляется. Иначе
    // предупреждение видели бы все и перестали читать.
    runBlocking {
      val refresher = HearthTurnRefresher(
        transport = object : HearthTurnTransport {
          override suspend fun turnCredentials() = Result.success(payload("2026-10-12T12:00:00Z"))
        },
        sink = object : HearthIceSink {
          override suspend fun setIceServers(ice: List<String>) = Unit
        },
        expectedHost = host,
        nowEpochSeconds = { now },
      )
      assertNull((refresher.refresh() as HearthTurnRefresh.Updated).notice)
    }
  }
}
