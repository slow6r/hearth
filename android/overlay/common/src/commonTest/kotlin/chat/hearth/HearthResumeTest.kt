package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Переподключение при выходе на передний план — не чаще раза в минуту. */
class HearthResumeTest {

  @Test
  fun first_time_always_reconnects() {
    assertTrue(HearthResume.shouldReconnect(lastMs = 0, nowMs = 5))
  }

  @Test
  fun within_a_minute_is_skipped() {
    assertFalse(HearthResume.shouldReconnect(lastMs = 100_000, nowMs = 100_000 + 59_999))
  }

  @Test
  fun a_minute_later_reconnects_again() {
    assertTrue(HearthResume.shouldReconnect(lastMs = 100_000, nowMs = 100_000 + 60_000))
  }

  @Test
  fun a_clock_that_went_backwards_does_not_block_forever() {
    // Если часы перевели назад, ждать «минуту от будущего» нельзя.
    assertTrue(HearthResume.shouldReconnect(lastMs = 500_000, nowMs = 100_000))
  }

  @Test
  fun claim_marks_the_attempt() {
    HearthResume.reset()
    assertTrue(HearthResume.claim(nowMs = 1_000))
    assertFalse(HearthResume.claim(nowMs = 2_000))
    assertTrue(HearthResume.claim(nowMs = 1_000 + 60_000))
    HearthResume.reset()
  }
}
