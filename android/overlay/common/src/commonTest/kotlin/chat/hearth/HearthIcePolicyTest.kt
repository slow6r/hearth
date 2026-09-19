package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Список ICE проверяется в момент звонка, а не только при записи.
 *
 * Пин на входе (bundle, ответ узла) уже был, и его проверяет HearthTurnPolicyTest.
 * Здесь проверяется второе, отдельное свойство: что бы ни лежало в настройках —
 * дописанное руками на открытом экране, восстановленное из старой базы, положенное
 * через adb — до WebRTC доходит только то, что указывает на узел этой семьи.
 *
 * И третье, не менее важное: НИ ОДИН путь не должен заканчиваться отсутствием звонков
 * молча. Раньше одна чужая запись обнуляла список целиком, а при relay-only пустой
 * список означает «звонка не будет вовсе».
 *
 * И четвёртое, обратное третьему: смягчение не имеет права отменить защиту. Список,
 * который не удалось подтвердить, отдаётся звонку — но relay-only на нём НЕ включается,
 * иначе медиа принудительно уходило бы через неизвестный ретранслятор. Проверка идёт в
 * обе стороны, потому что оба перекоса уже случались.
 */
class HearthIcePolicyTest {

  private val host = "relay.myhearth.ru"
  private val ours = listOf("stun:$host:3478", "turn:u:c@$host:3478")
  private val foreign = "turn:u:c@evil.example:3478"

  @Test
  fun our_own_turn_passes_through_unchanged() {
    assertEquals(ours, hearthPinnedIce(ours, host))
  }

  @Test
  fun a_foreign_turn_is_dropped() {
    // Главный случай: список подменили, звонок ушёл бы через чужой сервер, которому
    // достались бы адреса обоих собеседников.
    assertEquals(emptyList<String>(), hearthPinnedIce(listOf(foreign), host))
  }

  @Test
  fun a_public_stun_is_dropped() {
    assertEquals(emptyList<String>(), hearthPinnedIce(listOf("stun:stun.l.google.com:19302"), host))
  }

  @Test
  fun one_foreign_entry_no_longer_poisons_the_whole_list() {
    // Было наоборот: чужая запись обнуляла список целиком. При relay-only и пустом
    // defaultIceServers это означало не «строже», а «звонков нет» — и молча. Свои
    // записи остаются, чужая уходит, маршрут мимо узла остаётся невозможным.
    assertEquals(ours, hearthPinnedIce(ours + foreign, host))
  }

  @Test
  fun upstream_public_turn_is_dropped_too() {
    // Ровно те записи, которые патч 0004 вычищал из call.js.
    assertEquals(emptyList<String>(), hearthPinnedIce(listOf("turns:private2:x@turn.simplex.im:443"), host))
  }

  @Test
  fun an_unknown_own_host_pins_nothing() {
    // Раньше отсюда возвращался весь список без единой проверки, и дальше он шёл как
    // проверенный — то есть включал relay-only. Приписать записи к своему узлу, не зная
    // этого узла, нельзя; связь при этом не отнимается, см. тест ниже про hearthIceChoice.
    assertEquals(emptyList<String>(), hearthPinnedIce(ours, null))
  }

  @Test
  fun an_empty_list_stays_empty() {
    assertEquals(emptyList<String>(), hearthPinnedIce(emptyList(), host))
    assertEquals(emptyList<String>(), hearthPinnedIce(listOf(""), host))
    assertEquals(emptyList<String>(), hearthPinnedIce(listOf("", "   "), null))
  }

  @Test
  fun blank_lines_around_entries_do_not_break_the_check() {
    // Настройка хранится одной строкой через перевод строки, и лишний перевод строки
    // в конце — обычное дело. Пустая строка не должна значить «чужой сервер».
    assertEquals(ours, hearthPinnedIce(ours + "", host))
  }

  @Test
  fun an_entry_without_a_port_is_accepted_and_gets_the_default_one() {
    // Раньше такая запись отравляла весь список, хотя upstream её принимает. Порт при
    // этом дописывается: без него parseRTCIceServer собирает `stun:host:-1`.
    assertEquals(listOf("stun:$host:3478"), hearthPinnedIce(listOf("stun:$host"), host))
    assertEquals(listOf("turns:u:c@$host:5349"), hearthPinnedIce(listOf("turns:u:c@$host"), host))
  }

  // --- выбор списка и запасные источники --------------------------------------------

  @Test
  fun the_ordinary_case_says_nothing_to_the_person() {
    val choice = hearthIceChoice(ours, bundleIce = emptyList(), expectedHost = host)
    assertEquals(ours, choice.servers)
    assertNull(choice.notice, "в здоровом случае человека дёргать не за что")
  }

  @Test
  fun dropping_a_foreign_entry_is_told_about() {
    val choice = hearthIceChoice(ours + foreign, bundleIce = emptyList(), expectedHost = host)
    assertEquals(ours, choice.servers)
    assertNotNull(choice.notice, "чужая запись в списке — это то, о чём надо сказать")
  }

  @Test
  fun a_wholly_foreign_list_falls_back_to_the_bundle() {
    // Телефон, заведённый старой сборкой, переезд узла, чужой архив: в настройке
    // ничего своего не осталось. Раньше это был пустой список ICE, то есть отсутствие
    // звонков. Теперь берётся то, что пришло с узла вместе с адресами релеев.
    val choice = hearthIceChoice(listOf(foreign), bundleIce = ours, expectedHost = host)
    assertEquals(ours, choice.servers)
    assertNotNull(choice.notice)
  }

  @Test
  fun without_a_bundle_the_old_list_is_used_and_the_person_is_warned() {
    // Последний рубеж: подтвердить список нечем, но отнимать звонки нельзя. Отдаём как
    // есть — ровно поведение upstream — и говорим человеку.
    val choice = hearthIceChoice(listOf(foreign), bundleIce = emptyList(), expectedHost = host)
    assertEquals(listOf(foreign), choice.servers)
    assertNotNull(choice.notice, "молчаливый fail-open — худшее из возможного")
    assertEquals(false, choice.verified, "непроверенный список не смеет называться проверенным")
  }

  @Test
  fun a_device_without_a_known_host_keeps_its_calls_but_unverified() {
    // Продолжение an_unknown_own_host_pins_nothing: пин пуст, но связь на месте.
    // Список отдаётся как есть, помечен непроверенным и объяснён отдельным текстом —
    // «мы не знаем, какой узел наш» лечится не тем же, чем «список не наш».
    val choice = hearthIceChoice(ours, bundleIce = emptyList(), expectedHost = null)
    assertEquals(ours, choice.servers, "звонки отнимать нельзя")
    assertEquals(false, choice.verified)
    assertEquals(HearthIceText.UNKNOWN_HOST, choice.notice)
  }

  @Test
  fun an_unknown_host_still_falls_back_to_the_bundle_list() {
    // В настройке пусто, хост неизвестен: раньше сюда дотягивался пин и отдавал bundle.
    // Теперь пин молчит, и список обязан прийти вторым путём — иначе устройство
    // осталось бы без ICE вовсе, то есть без звонков.
    val choice = hearthIceChoice(emptyList(), bundleIce = ours, expectedHost = null)
    assertEquals(ours, choice.servers)
    assertEquals(false, choice.verified)
    assertNotNull(choice.notice)
  }

  @Test
  fun the_two_unverified_cases_do_not_share_one_text() {
    // Тексты разные намеренно: один посылает к владельцу узла, другой — на экран
    // «Узел» переподключать телефон. Один текст на оба случая посылал бы половину
    // семьи не туда.
    val foreignList = hearthIceChoice(listOf(foreign), emptyList(), host)
    val noHost = hearthIceChoice(listOf(foreign), emptyList(), null)
    assertEquals(HearthIceText.UNVERIFIED, foreignList.notice)
    assertEquals(HearthIceText.UNKNOWN_HOST, noHost.notice)
  }

  @Test
  fun no_ice_anywhere_is_told_about_too() {
    val choice = hearthIceChoice(emptyList(), bundleIce = emptyList(), expectedHost = host)
    assertEquals(emptyList<String>(), choice.servers)
    assertNotNull(choice.notice)
    assertEquals(false, choice.verified)
  }

  @Test
  fun no_path_ends_with_an_empty_list_while_the_device_has_any_ice() {
    // Главное свойство целиком: какой бы ни была настройка, если у устройства есть
    // хоть одна запись ICE — своя, чужая или из bundle, — список не будет пустым.
    val cases = listOf(
      Triple(ours, emptyList<String>(), host as String?),
      Triple(ours + foreign, emptyList<String>(), host as String?),
      Triple(listOf(foreign), ours, host as String?),
      Triple(listOf(foreign), emptyList<String>(), host as String?),
      Triple(emptyList<String>(), ours, host as String?),
      Triple(ours, emptyList<String>(), null as String?),
      Triple(listOf(foreign), emptyList<String>(), null as String?),
      Triple(emptyList<String>(), ours, null as String?),
    )
    for ((configured, bundle, expected) in cases) {
      val choice = hearthIceChoice(configured, bundle, expected)
      assertTrue(
        choice.servers.isNotEmpty(),
        "пустой список ICE при relay-only — это отсутствие звонков: $configured / $bundle",
      )
    }
  }

  // --- relay-only -------------------------------------------------------------------

  @Test
  fun relay_only_holds_while_there_is_something_to_relay_through() {
    assertTrue(hearthUseRelay(ours, preferRelay = false, verified = true))
    assertTrue(hearthUseRelay(ours, preferRelay = true, verified = true))
  }

  @Test
  fun relay_only_is_released_when_there_is_no_ice_at_all() {
    // Без списка ICE relay-only не строже, а просто запрещает звонок: ретранслятора
    // нет. Остаётся выбор человека, то есть поведение upstream.
    assertEquals(false, hearthUseRelay(null, preferRelay = false, verified = true))
    assertEquals(false, hearthUseRelay(emptyList<String>(), preferRelay = false, verified = true))
    assertEquals(true, hearthUseRelay(emptyList<String>(), preferRelay = true, verified = true))
  }

  @Test
  fun an_unverified_list_never_forces_media_through_a_stranger() {
    // Главный случай этого круга. Список непустой, значит по прежнему правилу
    // relay-only оставался включённым — и медиа ПРИНУДИТЕЛЬНО шло через сервер, про
    // который мы сами написали человеку, что не знаем, чей он. Это хуже, чем было до
    // правки: раньше чужой сервер был лишь одним из маршрутов, а стал единственным.
    assertEquals(false, hearthUseRelay(listOf(foreign), preferRelay = false, verified = false))
    // Осознанный выбор человека при этом остаётся в силе: relay — его настройка.
    assertEquals(true, hearthUseRelay(listOf(foreign), preferRelay = true, verified = false))
  }

  @Test
  fun no_choice_that_is_not_verified_ever_turns_relay_only_on() {
    // Свойство целиком, по всем исходам hearthIceChoice сразу: relay-only включается
    // ТОЛЬКО на списке, про который доказано, что он наш. Перебор здесь нужен ровно
    // затем, чтобы новая ветка выбора не проехала мимо этого правила молча.
    val cases = listOf(
      Triple(ours, emptyList<String>(), host as String?),
      Triple(ours + foreign, emptyList<String>(), host as String?),
      Triple(listOf(foreign), ours, host as String?),
      Triple(listOf(foreign), emptyList<String>(), host as String?),
      Triple(emptyList<String>(), ours, host as String?),
      Triple(ours, emptyList<String>(), null as String?),
      Triple(listOf(foreign), emptyList<String>(), null as String?),
      Triple(emptyList<String>(), ours, null as String?),
      Triple(emptyList<String>(), emptyList<String>(), host as String?),
    )
    for ((configured, bundle, expected) in cases) {
      val choice = hearthIceChoice(configured, bundle, expected)
      val relayOnly = hearthUseRelay(choice.servers, preferRelay = false, verified = choice.verified)
      if (relayOnly) {
        assertTrue(
          choice.verified && hearthPinnedIce(choice.servers, expected) == choice.servers,
          "relay-only на неподтверждённом списке: $configured / $bundle / $expected",
        )
      }
      // И наоборот: непроверенный список обязан оставлять человеку прямой путь.
      if (!choice.verified) {
        assertEquals(
          false,
          relayOnly,
          "медиа принуждают идти через неизвестный сервер: $configured / $bundle / $expected",
        )
      }
    }
  }

  // --- доверенный хост --------------------------------------------------------------

  @Test
  fun the_trusted_host_is_the_relay_host_from_the_bundle() {
    // Один явный источник. Раньше пин звонка брал адрес device API, а bundle проверял
    // ICE по хосту первого SMP-адреса: разведи их по разным именам — и только что
    // принятые записи стали бы «чужими».
    assertEquals("bundle.example", hearthOwnNodeHost("bundle.example", "node.example"))
  }

  @Test
  fun the_device_api_host_is_only_a_fallback_for_older_installs() {
    // У устройств, заведённых сборкой без HearthPrefs.bundleHost, другого объявленного
    // хоста нет вовсе — отнимать у них пин незачем.
    assertEquals("node.example", hearthOwnNodeHost(null, "node.example"))
    assertEquals("node.example", hearthOwnNodeHost("   ", "node.example"))
  }

  @Test
  fun no_source_at_all_means_no_pin() {
    assertNull(hearthOwnNodeHost(null, null))
    assertNull(hearthOwnNodeHost("", ""))
  }

  @Test
  fun a_split_between_the_relay_and_the_device_api_is_visible() {
    // Сегодня hearthd кладёт один и тот же хост в оба места. Это соглашение, а не
    // гарантия, поэтому расхождение должно быть проверяемым, а не подразумеваемым.
    assertTrue(hearthNodeHostsAgree("relay.example", "relay.example"))
    assertTrue(hearthNodeHostsAgree("relay.example", "RELAY.EXAMPLE"))
    assertTrue(hearthNodeHostsAgree("relay.example", null), "сравнивать не с чем — не расхождение")
    assertTrue(hearthNodeHostsAgree(null, "api.example"))
    assertEquals(false, hearthNodeHostsAgree("relay.example", "api.example"))
  }
}
