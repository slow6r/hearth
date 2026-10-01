package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Что забирается с узла само при выключенном «принимать изображения».
 *
 * Ошибиться здесь можно тихо в обе стороны: слишком низкий потолок оставит стикеры мылом,
 * слишком высокий начнёт молча тянуть фотографии у того, кто это выключил осознанно.
 */
class HearthAutoAcceptTest {

  /** Самый тяжёлый стикер в наборе на узле — 45 216 байт. */
  private val heaviestSticker = 45_216L

  @Test
  fun стикер_забирается() {
    assertTrue(HearthAutoAccept.acceptsSmallImageAnyway(isImage = true, fileSize = heaviestSticker))
  }

  @Test
  fun потолок_включительно() {
    assertTrue(
      HearthAutoAccept.acceptsSmallImageAnyway(
        isImage = true,
        fileSize = HearthAutoAccept.SMALL_IMAGE_MAX_BYTES,
      )
    )
  }

  @Test
  fun на_байт_выше_потолка_уже_нет() {
    assertFalse(
      HearthAutoAccept.acceptsSmallImageAnyway(
        isImage = true,
        fileSize = HearthAutoAccept.SMALL_IMAGE_MAX_BYTES + 1,
      )
    )
  }

  /**
   * Фотография сжимается upstream до MAX_IMAGE_SIZE = 255 КБ. Она обязана остаться за
   * выключателем: человек, запретивший автоприём, не должен молча получать её.
   */
  @Test
  fun фотография_под_правило_не_попадает() {
    assertFalse(HearthAutoAccept.acceptsSmallImageAnyway(isImage = true, fileSize = 261_120L))
  }

  @Test
  fun не_картинка_не_забирается_даже_крошечная() {
    assertFalse(HearthAutoAccept.acceptsSmallImageAnyway(isImage = false, fileSize = 1_000L))
  }

  /** Файла нет — это «нет», а не «ноль байт». */
  @Test
  fun без_файла_правило_молчит() {
    assertFalse(HearthAutoAccept.acceptsSmallImageAnyway(isImage = true, fileSize = null))
  }

  @Test
  fun нулевой_и_отрицательный_размер_не_проходят() {
    assertFalse(HearthAutoAccept.acceptsSmallImageAnyway(isImage = true, fileSize = 0L))
    assertFalse(HearthAutoAccept.acceptsSmallImageAnyway(isImage = true, fileSize = -1L))
  }

  /** Потолок обязан остаться ниже того, до которого upstream сжимает фотографии. */
  @Test
  fun потолок_ниже_предела_фотографий_upstream() {
    assertTrue(HearthAutoAccept.SMALL_IMAGE_MAX_BYTES < 261_120L)
    assertTrue(HearthAutoAccept.SMALL_IMAGE_MAX_BYTES > heaviestSticker)
  }
}
