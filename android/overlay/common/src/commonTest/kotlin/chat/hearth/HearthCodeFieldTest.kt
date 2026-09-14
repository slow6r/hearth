package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Пересчёт позиции курсора в поле ввода кода.
 *
 * Поле хранит двенадцать знаков без дефисов, а показывает их группами по четыре.
 * Если не пересчитывать позицию, курсор уезжает после каждой правки и знаки
 * встают не в том порядке — человеку приходится тыкать в строку руками. Проверять
 * это пальцами на телефоне бессмысленно: здесь чистая арифметика, и её место в тесте.
 */
class HearthCodeFieldTest {

  @Test
  fun offsets_skip_over_the_dashes() {
    // H7K4-P9QX-M3TV: дефисы стоят после 4-го и 8-го знака.
    assertEquals(0, HearthAccessCode.displayOffset(0))
    assertEquals(4, HearthAccessCode.displayOffset(4))
    assertEquals(6, HearthAccessCode.displayOffset(5))
    assertEquals(9, HearthAccessCode.displayOffset(8))
    assertEquals(11, HearthAccessCode.displayOffset(9))
    assertEquals(14, HearthAccessCode.displayOffset(12))
  }

  @Test
  fun a_cursor_in_the_shown_string_maps_back_to_the_code() {
    assertEquals(0, HearthAccessCode.codeOffset(0))
    assertEquals(4, HearthAccessCode.codeOffset(4))
    assertEquals(4, HearthAccessCode.codeOffset(5))
    assertEquals(8, HearthAccessCode.codeOffset(9))
    assertEquals(8, HearthAccessCode.codeOffset(10))
    assertEquals(12, HearthAccessCode.codeOffset(14))
  }

  @Test
  fun the_mapping_round_trips_for_every_position() {
    for (offset in 0..HearthAccessCode.LENGTH) {
      assertEquals(
        offset,
        HearthAccessCode.codeOffset(HearthAccessCode.displayOffset(offset)),
        "позиция $offset не вернулась к себе"
      )
    }
  }

  @Test
  fun offsets_never_leave_the_string() {
    assertEquals(0, HearthAccessCode.displayOffset(-5))
    assertEquals(14, HearthAccessCode.displayOffset(99))
    assertEquals(0, HearthAccessCode.codeOffset(-5))
    assertEquals(HearthAccessCode.LENGTH, HearthAccessCode.codeOffset(99))
  }
}
