package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Дешёвые сторожа на константы политики.
 *
 * Проверяют они не логику, а то, что решение не отменили молча: при ребейзе на новый
 * upstream-тег флаг легко потерять вместе с куском кода, в который он вписан, и
 * экран, который решили не показывать, вернётся сам собой.
 */
class HearthPresetsTest {

  @Test
  fun the_manual_ice_screen_stays_closed() {
    assertFalse(HearthPresets.ICE_EDITABLE, "экран ручной правки ICE открывать нельзя")
  }

  @Test
  fun media_always_goes_through_the_relay() {
    assertTrue(HearthPresets.ALWAYS_RELAY, "режим all раскрывает реальный адрес устройства")
  }

  @Test
  fun public_operator_presets_stay_off() {
    assertFalse(HearthPresets.PRESETS_ENABLED)
    assertFalse(HearthPresets.SHOW_UPSTREAM_LINKS)
    assertTrue(HearthPresets.presetServers.isEmpty())
  }

  @Test
  fun without_a_bundle_there_are_no_ice_servers() {
    // Отсутствие запасного списка — половина патча 0004: пустой список означает
    // «звонок не состоится», а не «возьми публичный STUN».
    assertTrue(HearthPresets.defaultIceServers(null).isEmpty())
  }
}
