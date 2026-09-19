package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Когда про доступную версию говорят в шторку.
 *
 * Правило вынесено в commonMain ради этих тестов: показ уведомления без устройства не
 * проверить, а решение «говорить или молчать» — единственное место, где можно ошибиться
 * тихо. Ошибка в одну сторону приучает не читать уведомления, в другую — прячет
 * security-релиз.
 */
class HearthUpdateOfferTest {

  private val window = HearthUpdateTrust.STALE_AFTER_DAYS

  @Test
  fun про_версию_о_которой_ещё_не_говорили_говорим_сразу() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = null,
        announcedDay = null,
        todayEpochDays = 100,
      )
    )
  }

  @Test
  fun ту_же_версию_в_тот_же_день_не_повторяем() {
    assertFalse(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = 394L,
        announcedDay = 100,
        todayEpochDays = 100,
      )
    )
  }

  @Test
  fun ту_же_версию_внутри_окна_не_повторяем() {
    assertFalse(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = 394L,
        announcedDay = 100,
        todayEpochDays = 100 + window - 1,
      )
    )
  }

  @Test
  fun ту_же_версию_после_окна_напоминаем() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = 394L,
        announcedDay = 100,
        todayEpochDays = 100 + window,
      )
    )
  }

  /**
   * Ради этого случая и хранится версия, а не только день: security-релиз, вышедший на
   * следующий день после обычного, обязан дойти немедленно, а не через неделю.
   */
  @Test
  fun новая_версия_на_следующий_день_говорится_не_дожидаясь_окна() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 395,
        announcedVersionCode = 394L,
        announcedDay = 100,
        todayEpochDays = 101,
      )
    )
  }

  /**
   * Понижение версии на узле — тоже смена, и о ней лучше сказать: молча промолчать
   * означало бы, что откат раздачи невидим.
   */
  @Test
  fun версия_ниже_объявленной_тоже_считается_сменой() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 393,
        announcedVersionCode = 394L,
        announcedDay = 100,
        todayEpochDays = 101,
      )
    )
  }

  /**
   * Часы, переведённые назад, давали бы отрицательную разность — и обычная проверка
   * «прошло ли окно» замолчала бы до тех пор, пока часы не догонят.
   */
  @Test
  fun часы_назад_не_затыкают_уведомление_навсегда() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = 394L,
        announcedDay = 500,
        todayEpochDays = 100,
      )
    )
  }

  @Test
  fun день_без_версии_не_считается_объявленным() {
    assertTrue(
      HearthUpdateOffer.shouldAnnounce(
        versionCode = 394,
        announcedVersionCode = null,
        announcedDay = 100,
        todayEpochDays = 100,
      )
    )
  }

  @Test
  fun в_тексте_есть_версия_и_сказано_что_само_не_скачается() {
    val text = HearthUpdateOffer.text("7.0.1-h24")
    assertTrue(text.contains("7.0.1-h24"))
    assertTrue(text.contains("не") && text.contains("качает"))
    assertTrue(text.contains("Домашний узел"))
  }
}
